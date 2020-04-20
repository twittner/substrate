// Copyright 2020 Parity Technologies (UK) Ltd.
// This file is part of Substrate.
//
// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Substrate.  If not, see <http://www.gnu.org/licenses/>.

//! Reachability checks via UDP messages.
//!
//! The module contains `Pinger` a type which can be asked to check reachability
//! of multiaddresses by sending a UDP packet and awaiting a signed response.
//! Addresses are asynchronously enqueued for checking and resported back by
//! repeated invocation of `Pinger::next_checked`. Implicitly, incoming ping
//! messages are answer by sending back corresponding PONGs.
//!
//! Confirmed addresses are cached for some time and repeated checks of the same
//! (`PeerId`, `Multiaddr`) pair will confirm the address without sending another
//! PING.

use async_std::net::UdpSocket;
use futures::{channel::mpsc, future::{self, Either}, prelude::*, stream::FusedStream};
use libp2p::{
	core::{identity::{Keypair, PublicKey}, PeerId},
	multiaddr::{Multiaddr, Protocol}
};
use lru_time_cache::LruCache;
use minicbor::{Encode, Decode};
use std::{
	convert::TryInto,
	fmt,
	io,
	net::{IpAddr, SocketAddr},
	task::{Context, Poll},
	time::Duration
};
use thiserror::Error;

/// The max. size of a single UDP message payload.
const MAX_MESSAGE_LEN: usize = 512;

/// The max. number ouf pending checks that can be requested.
const MAX_PENDING_CHECKS: usize = 128;

/// The max. number of the recently seen peers cache entries.
const MAX_CACHE_SIZE: usize = 1024;

/// The max. duration of recently seen peers cache entries.
const CACHE_TTL: Duration = Duration::from_secs(300);

/// The max. number of concurrent PING requests in flight.
const MAX_OUTSTANDING_REQUESTS: usize = 1024;

// If MAX_PENDING_CHECKS were allowed to be greater that MAX_OUTSTANDING_REQUESTS
// we would continue to process check requests and start evicting older PINGs for
// which we still expect a response within PING_TTL.
static_assertions::const_assert!(MAX_OUTSTANDING_REQUESTS >= MAX_PENDING_CHECKS);

/// The max. lifetime of a PING, i.e. within PING_TTL we expect a PONG.
const PING_TTL: Duration = Duration::from_secs(10);

/// A `Pinger` accepts requests to check addresses and pings them via UDP.
pub(crate) struct Pinger {
	keypair: Keypair,
	socket: UdpSocket,
	buffer: Vec<u8>,
	recent: LruCache<Vec<u8>, PeerId>,
	awaiting: LruCache<Nonce, Entry>,
	requests: mpsc::Receiver<Entry>,
	pending: Option<Entry>
}

#[derive(Debug)]
struct Entry {
	pubkey: PublicKey,
	peerid: PeerId,
	multiaddr: Multiaddr,
	sockaddr: SocketAddr
}

impl fmt::Debug for Pinger {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("Pinger")
			.field("key", &self.keypair.public())
			.field("socket", &self.socket)
			.field("buffer", &self.buffer.len())
			.field("recent", &self.recent.len())
			.field("awaiting", &self.awaiting.len())
			.field("pending", &self.pending)
			.finish()
	}
}

impl Pinger {
	/// Create a new `Pinger` with an already bound UDP socket and the given keypair.
	pub(crate) fn new(keypair: Keypair, socket: UdpSocket) -> (Self, Sender) {
		let (tx, rx) = mpsc::channel(MAX_PENDING_CHECKS);
		let this = Pinger {
			keypair,
			socket,
			buffer: Vec::with_capacity(MAX_MESSAGE_LEN),
			awaiting: LruCache::with_expiry_duration_and_capacity(PING_TTL, MAX_OUTSTANDING_REQUESTS),
			recent: LruCache::with_expiry_duration_and_capacity(CACHE_TTL, MAX_CACHE_SIZE),
			requests: rx,
			pending: None
		};
		(this, Sender(tx))
	}

	/// Bind a new UDP socket to the given address and return a `Pinger`.
	pub(crate) async fn open(keypair: Keypair, addr: &Multiaddr) -> Result<(Self, Sender), Error> {
		let socket = UdpSocket::bind(to_sockaddr(addr)?).await?;
		Ok(Pinger::new(keypair, socket))
	}

	/// The main driver of PINGER.
	///
	/// This method needs to be invoked repeatedly in order to make progress and get back
	/// verified addresses. Only after an error has been returned should the processing be
	/// considered failed and the `Pinger` should be dropped.
	pub(crate) async fn next_checked(&mut self) -> Result<(PeerId, Multiaddr), Error> {
		// Execution proceeds by polling the mpsc receiver for new check requests
		// concurrently with the UDP socket for inbound packets. If any one of those
		// two is ready we process the value and continue from there.
		loop {
			if let Some(e) = self.pending.take() {
				return Ok((e.peerid, e.multiaddr))
			}

			let (next_check, next_inbound) = {
				// Get the next check request or do nothing if all mpsc senders
				// are gone in which case we only continue to answer incoming PINGs.
				let mut check = if self.requests.is_terminated() {
					Either::Left(future::pending())
				} else {
					Either::Right(self.requests.next())
				};

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
				if self.recently_seen(&e.peerid, &e.multiaddr) {
					// We can not return from here since we still need to process
					// the inbound socket packet if there was one.
					debug_assert!(self.pending.is_none());
					self.pending = Some(e)
				} else {
					let nonce = Nonce::random();
					let msg = Message::ping(&nonce);
					self.send_msg(e.sockaddr, &msg).await?;
					self.awaiting.insert(nonce, e);
				}
			}

			match next_inbound {
				Poll::Ready(Ok((n, from))) => {
					self.buffer.truncate(n);
					match self.on_inbound(from).await {
						Ok(None) => {}
						Ok(Some(e)) =>
							if let Some(p) = self.pending.take() {
								self.pending = Some(e);
								return Ok((p.peerid, p.multiaddr))
							} else {
								return Ok((e.peerid, e.multiaddr))
							}
						Err(e) => {
							log::debug!("failed to process inbound message from {}: {}", from, e)
						}
					}
				}
				Poll::Ready(Err(e)) => {
					log::debug!("failed to read from UDP socket: {}", e);
					return Err(e.into())
				}
				Poll::Pending => {
					// We do not return `Poll::Pending` here because `next_check` was ready.
				}
			}
		}
	}

	/// Handle inbound UDP packets.
	///
	/// This is either a response to one of our own PING requests, or else a request
	/// for us to answer with a PONG. If it is a PONG and we confirm its validitiy,
	/// the corresponding entry is returned. For PINGs we answer and return back `None`
	/// to the caller.
	async fn on_inbound(&mut self, from: SocketAddr) -> Result<Option<Entry>, Error> {
		let mut decoder = minicbor::Decoder::new(&self.buffer);
        let message = decoder.decode::<Message>().map_err(|e| Error::Decoding(Box::new(e)))?;

		match message.kind {
			Some(Kind::Ping) => {
				let nonce = message.nonce.and_then(Nonce::from_slice).ok_or(Error::Nonce)?;
				log::trace!("PING from {}", from);
				let answer = Message::pong(&nonce);
				self.send_msg(from, &answer).await?;
				Ok(None)
			}
			Some(Kind::Pong) => {
				let nonce = message.nonce.and_then(Nonce::from_slice).ok_or(Error::Nonce)?;
				if let Some(e) = self.awaiting.peek(&nonce) {
					let signature = &self.buffer[decoder.position() ..];
					if e.pubkey.verify(&self.buffer[.. decoder.position()], signature) {
						log::trace!("PONG from {}", from);
						return Ok(self.awaiting.remove(&nonce))
					}
				}
				Err(Error::UnexpectedMessage(from))
			}
			_ => {
				log::trace!("unknown message type");
				Ok(None)
			}
		}
	}

	/// Send the given message (PING or POMG) to a socket address.
	async fn send_msg(&mut self, to: SocketAddr, msg: &Message<'_>) -> Result<(), Error> {
		self.buffer.clear();

        minicbor::encode(msg, &mut self.buffer).map_err(|e| Error::Encoding(Box::new(e)))?;
		let signature = self.keypair.sign(&self.buffer).map_err(|e| Error::Signing(Box::new(e)))?;
		self.buffer.extend_from_slice(&signature);

		log::trace!("sending {:?} ({} bytes) to {}", msg.kind, self.buffer.len(), to);

        let _n = self.socket.send_to(&self.buffer, to).await?;
		debug_assert_eq!(_n, self.buffer.len());

        Ok(())
	}

	/// Check if we have a cached entry for this `PeerId`, `Multiaddr` combination.
	fn recently_seen(&mut self, id: &PeerId, ma: &Multiaddr) -> bool {
		// We use `peek` to not update the timestamp of this entry. This way it
		// will eventually be evicted and force a reconfirmation by sending
		// another PING message. Otherwise we may keep finding the entry in our
		// local cache long after the peer is gone.
		if let Some(peer) = self.recent.peek(ma.as_ref()) {
			if peer == id {
				log::trace!("({}, {}) found in cache", id, ma);
				return true
			}
		}
		false
	}
}

/// Convert a `Multiaddr` to a `SocketAddr`.
///
/// Supports only TCP/IP and UDP addresses.
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

// Request check sender ///////////////////////////////////////////////////////

/// A handle to issue check requests to `Pinger`.
#[derive(Clone, Debug)]
pub(crate) struct Sender(mpsc::Sender<Entry>);

impl Sender {
	pub(crate) fn try_check(&mut self, pk: PublicKey, id: PeerId, ma: Multiaddr) -> Result<(), Error> {
		let a = to_sockaddr(&ma)?;
		let e = Entry { pubkey: pk, peerid: id, multiaddr: ma, sockaddr: a };
		self.0.try_send(e).map_err(|e| {
			if e.is_full() {
				return Error::Full(MAX_PENDING_CHECKS)
			}
			Error::RequestFailed(Box::new(e))
		})
	}

	pub(crate) async fn check(&mut self, pk: PublicKey, id: PeerId, ma: Multiaddr) -> Result<(), Error> {
		let a = to_sockaddr(&ma)?;
		let e = Entry { pubkey: pk, peerid: id, multiaddr: ma, sockaddr: a };
		self.0.send(e).await.map_err(|e| Error::RequestFailed(Box::new(e)))
	}
}

// Nonce type /////////////////////////////////////////////////////////////////

/// A one-time value to be included in PINGs and echoed back in PONGs.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct Nonce([u8; 32]);

impl AsRef<[u8]> for Nonce {
	fn as_ref(&self) -> &[u8] {
		&self.0[..]
	}
}

impl Nonce {
	/// Get a fresh random nonce.
	fn random() -> Self {
		Nonce(rand::random())
	}

	/// Try to create a nonce from the given byte slice.
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

// Error type definition //////////////////////////////////////////////////////

/// Possible error cases a which may occur when checking addresses.
#[non_exhaustive]
#[derive(Debug, Error)]
pub(crate) enum Error {
	/// Some underlying I/O error.
	#[error("i/o error: {0}")]
	Io(#[from] io::Error),

	/// Encoding of an outbound message failed.
	#[error("encoding failed: {0}")]
	Encoding(#[from] Box<dyn std::error::Error + Send>),

	/// Decoding of an inbound message failed.
	#[error("decoding failed: {0}")]
	Decoding(#[source] Box<dyn std::error::Error + Send>),

	/// Signing an outbound message failed.
	#[error("message signing failed: {0}")]
	Signing(#[source] Box<dyn std::error::Error + Send>),

	/// A nonce was missing or had the wrong format in an inbound message.
	#[error("missing or invalid nonce")]
	Nonce,

	/// We received an unexpected message from a remote node.
	#[error("unexpected message received from {0}")]
	UnexpectedMessage(SocketAddr),

	/// A `Multiaddr` was of an unexpected format.
	#[error("unexpected Multiaddr provided")]
	UnexpectedMultiaddr,

	/// The check request queue is full.
	#[error("the request queue has reached its max. capacity: {0}")]
	Full(usize),

	/// Attempt to request an address check but the `Pinger` has been dropped already.
	#[error("failed to request an address check: {0}")]
	RequestFailed(#[source] Box<dyn std::error::Error + Send>)
}

