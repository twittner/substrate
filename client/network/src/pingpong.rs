use async_std::net::UdpSocket;
use futures::{channel::mpsc, prelude::*};
use libp2p::{
	core::{identity::{Keypair, PublicKey}, PeerId},
	multiaddr::{Multiaddr, Protocol}
};
use lru_time_cache::LruCache;
use minicbor::{Encode, Decode};
use std::{
	convert::TryInto,
	io,
	net::{IpAddr, SocketAddr},
	task::{Context, Poll},
	time::Duration
};
use thiserror::Error;

/// The max. size of our UDP payload.
const MAX_MESSAGE_LEN: usize = 256;

/// The max. size of our UDP payload.
const MAX_PENDING_CHECKS: usize = 128;

/// The max. number of the recently seen peers cache entries.
const MAX_CACHE_SIZE: usize = 1024;

/// The max. duration of recently seen peers cache entries.
const CACHE_TTL: Duration = Duration::from_secs(300);

const MAX_OUTSTANDING_REQUESTS: usize = 1024;

const REQUEST_TTL: Duration = Duration::from_secs(10);

pub(crate) struct Sender(mpsc::Sender<Entry>);

impl Sender {
	pub(crate) fn check(&mut self, pk: PublicKey, id: PeerId, ma: Multiaddr) -> Result<(), Error> {
		let a = to_sockaddr(&ma)?;
		let e = Entry { pubkey: pk, peerid: id, multiaddr: ma, sockaddr: a };
		self.0.try_send(e).map_err(|e| todo!())
	}
}

pub(crate) struct AddressTester {
	keypair: Keypair,
	socket: UdpSocket,
	buffer: Vec<u8>,
	recent: LruCache<Vec<u8>, PeerId>,
	awaiting: LruCache<Nonce, Entry>,
	requests: mpsc::Receiver<Entry>
}

struct Entry {
	pubkey: PublicKey,
	peerid: PeerId,
	multiaddr: Multiaddr,
	sockaddr: SocketAddr
}

#[non_exhaustive]
#[derive(Debug, Error)]
pub(crate) enum Error {
	#[error("i/o error: {0}")]
	Io(#[from] io::Error),

	#[error("encoding failed: {0}")]
	Encoding(#[from] Box<dyn std::error::Error + Send>),

	#[error("decoding failed: {0}")]
	Decoding(#[source] Box<dyn std::error::Error + Send>),

	#[error("message signing failed: {0}")]
	Signing(#[source] Box<dyn std::error::Error + Send>),

	#[error("missing or invalid nonce")]
	Nonce,

	#[error("unexpected message received from {0}")]
	UnexpectedMessage(SocketAddr),

	#[error("unexpected Multiaddr provided")]
	UnexpectedMultiaddr,

	#[error("a queue has reached its max. capacity")]
	Full(usize)
}

impl AddressTester {
	pub(crate) fn new(keypair: Keypair, socket: UdpSocket) -> (Self, Sender) {
		let (tx, rx) = mpsc::channel(MAX_PENDING_CHECKS);
		let this = AddressTester {
			keypair,
			socket,
			buffer: Vec::with_capacity(MAX_MESSAGE_LEN),
			awaiting: LruCache::with_expiry_duration_and_capacity(REQUEST_TTL, MAX_OUTSTANDING_REQUESTS),
			recent: LruCache::with_expiry_duration_and_capacity(CACHE_TTL, MAX_CACHE_SIZE),
			requests: rx
		};
		(this, Sender(tx))
	}

	pub(crate) async fn open(keypair: Keypair, addr: &Multiaddr) -> Result<(Self, Sender), Error> {
		let socket = UdpSocket::bind(to_sockaddr(addr)?).await?;
		Ok(AddressTester::new(keypair, socket))
	}

	pub(crate) fn quickcheck(&mut self, id: &PeerId, ma: &Multiaddr) -> bool {
		if let Some(peer) = self.recent.peek(ma.as_ref()) {
			if peer == id {
				self.recent.get(ma.as_ref()); // update cache entry time
				return true
			}
		}
		false
	}

	pub(crate) async fn next_checked(&mut self) -> Result<(PeerId, Multiaddr), Error> {
		loop {
			let (next_check, next_inbound) = {
				let mut check = self.requests.next();

				self.buffer.resize(MAX_MESSAGE_LEN, 0);
				let dgram = self.socket.recv_from(&mut self.buffer);
				futures::pin_mut!(dgram);

				future::poll_fn(move |cx: &mut Context| {
					let a = check.poll_unpin(cx);
					let b = dgram.poll_unpin(cx);
					if a.is_pending() && b.is_pending() {
						return Poll::Pending
					}
					Poll::Ready((a, b))
				})
				.await
			};

			if let Poll::Ready(Some(e)) = next_check {
				let nonce = Nonce::random();
				let msg = Message::ping(&nonce);
				self.send_msg(e.sockaddr, &msg).await?;
				self.awaiting.insert(nonce, e);
			}

			match next_inbound {
				Poll::Ready(Ok((n, from))) => {
					self.buffer.truncate(n);
					match self.on_inbound(from).await {
						Ok(e) => return Ok((e.peerid, e.multiaddr)),
						Err(e) => {
							log::debug!("failed to process inbound message from {}: {}", from, e)
						}
					}
				}
				Poll::Ready(Err(e)) => return Err(e.into()),
				Poll::Pending => {}
			}
		}
	}

	async fn on_inbound(&mut self, from: SocketAddr) -> Result<Entry, Error> {
		let mut decoder = minicbor::Decoder::new(&self.buffer);
        let msg = decoder.decode::<Message>().map_err(|e| Error::Decoding(Box::new(e)))?;

		match msg.kind {
			Some(Kind::Ping) => todo!(),
			Some(Kind::Pong) => {
				let nonce = msg.nonce.and_then(Nonce::from_slice).ok_or(Error::Nonce)?;
				if let Some(e) = self.awaiting.get(&nonce) {
					let signature = &self.buffer[decoder.position() ..];
					if e.pubkey.verify(&self.buffer[.. decoder.position()], signature) {
						return Ok(self.awaiting.remove(&nonce).expect("just looked it up"))
					}
				}
			}
			_ => {}
		}

		Err(Error::UnexpectedMessage(from))
	}

	async fn send_msg(&mut self, to: SocketAddr, msg: &Message<'_>) -> Result<(), Error> {
		self.buffer.clear();

        minicbor::encode(msg, &mut self.buffer).map_err(|e| Error::Encoding(Box::new(e)))?;
		let signature = self.keypair.sign(&self.buffer).map_err(|e| Error::Signing(Box::new(e)))?;

		self.buffer.extend_from_slice(&signature);
        let _n = self.socket.send_to(&self.buffer, to).await?;
		debug_assert_eq!(_n, self.buffer.len());

        Ok(())
	}
}

fn to_sockaddr(addr: &Multiaddr) -> Result<SocketAddr, Error> {
	let mut iter = addr.iter();
	let proto1 = iter.next().ok_or(Error::UnexpectedMultiaddr)?;
	let proto2 = iter.next().ok_or(Error::UnexpectedMultiaddr)?;

	if iter.next().is_some() {
		return Err(Error::UnexpectedMultiaddr)
	}

	match (proto1, proto2) {
		(Protocol::Ip4(ip), Protocol::Tcp(port)) | (Protocol::Ip4(ip), Protocol::Udp(port)) =>
			Ok(SocketAddr::from((IpAddr::from(ip), port))),

		(Protocol::Ip6(ip), Protocol::Tcp(port)) | (Protocol::Ip6(ip), Protocol::Udp(port)) =>
			Ok(SocketAddr::from((IpAddr::from(ip), port))),

		_ => Err(Error::UnexpectedMultiaddr)
	}
}

// Nonce type /////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct Nonce([u8; 32]);

impl AsRef<[u8]> for Nonce {
	fn as_ref(&self) -> &[u8] {
		&self.0[..]
	}
}

impl Nonce {
	fn random() -> Self {
		Nonce(rand::random())
	}

	fn from_slice(s: &[u8]) -> Option<Self> {
		s.try_into().ok().map(Nonce)
	}
}

// Wire protocol //////////////////////////////////////////////////////////////

// A PING contains a random nonce.
// A PONG echoes back the nonce from the PING.
// All messages are signed with the sender's private key.

#[derive(Debug, Encode, Decode)]
struct Message<'a> {
	#[n(0)] kind: Option<Kind>,
	#[n(1)] nonce: Option<&'a [u8]>
}

#[derive(Debug, Encode, Decode)]
enum Kind {
	#[n(0)] Ping,
	#[n(1)] Pong
}

impl<'a> Message<'a> {
	fn ping(nonce: &'a Nonce) -> Self {
		Message {
			kind: Some(Kind::Ping),
			nonce: Some(nonce.as_ref())
		}
	}

	fn pong(nonce: &'a Nonce) -> Self {
		Message {
			kind: Some(Kind::Pong),
			nonce: Some(nonce.as_ref())
		}
	}
}

