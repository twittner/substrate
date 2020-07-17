// Copyright 2019-2020 Parity Technologies (UK) Ltd.
// This file is part of Substrate.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Substrate.  If not, see <http://www.gnu.org/licenses/>.

//! Collection of request-response protocols.
//!
//! The [`RequestResponses`] struct defined in this module provides support for zero or more
//! so-called "request-response" protocols.
//!
//! A request-response protocol works in the following way:
//!
//! - For every emitted request, a new substream is open and the protocol is negotiated. If the
//! remote supports the protocol, the size of the request is sent as a LEB128 number, followed
//! with the request itself. The remote then sends the size of the response as a LEB128 number,
//! followed with the response.
//!
//! - Requests have a certain time limit before they time out. This time includes the time it
//! takes to send/receive the request and response.
//!
//! - If provided, a ["requests processing"](RequestResponseConfig::inbound_queue) channel
//! is used to handle incoming requests.
//!

use event_listener::{Event as TryAgainEvent, EventListener};
use futures::{channel::{mpsc, oneshot}, prelude::*};
use libp2p::{
	core::{
		connection::{ConnectionId, ListenerId},
		ConnectedPoint, Multiaddr, PeerId,
	},
	request_response::{
		RequestResponse, RequestResponseCodec, RequestResponseConfig, RequestResponseEvent,
		RequestResponseMessage, ResponseChannel, ProtocolSupport
	},
	swarm::{
		protocols_handler::multi::MultiHandler, NetworkBehaviour, NetworkBehaviourAction,
		PollParameters, ProtocolsHandler,
	},
};
use lru::LruCache;
use minicbor::{Encode, Decode};
use std::{
	borrow::Cow, collections::{hash_map::Entry, HashMap}, convert::TryFrom as _, io, iter,
	pin::Pin, task::{Context, Poll}, time::Duration,
	num::NonZeroU16
};

pub use libp2p::request_response::{InboundFailure, OutboundFailure, RequestId};

/// Configuration for a single request-response protocol.
#[derive(Debug, Clone)]
pub struct ProtocolConfig {
    /// Name of the protocol on the wire. Should be something like `/foo/bar`.
    pub name: Cow<'static, str>,

    /// Maximum allowed size, in bytes, of a request.
    ///
    /// Any request larger than this value will be declined as a way to avoid allocating too
    /// much memory for it.
    pub max_request_size: u64,

    /// Maximum allowed size, in bytes, of a response.
    ///
    /// Any response larger than this value will be declined as a way to avoid allocating too
    /// much memory for it.
    pub max_response_size: u64,

    /// Duration after which emitted requests are considered timed out.
    ///
    /// If you expect the response to come back quickly, you should set this to a smaller duration.
    pub request_timeout: Duration,

    /// Channel on which the networking service will send incoming requests.
    ///
    /// Every time a peer sends a request to the local node using this protocol, the networking
    /// service will push an element on this channel. The receiving side of this channel then has
    /// to pull this element, process the request, and send back the response to send back to the
    /// peer.
    ///
    /// The size of the channel has to be carefully chosen. If the channel is full, the networking
    /// service will discard the incoming request send back an error to the peer. Consequently,
    /// the channel being full is an indicator that the node is overloaded.
    ///
    /// You can typically set the size of the channel to `T / d`, where `T` is the
    /// `request_timeout` and `d` is the expected average duration of CPU and I/O it takes to
    /// build a response.
    ///
    /// Can be `None` if the local node does not support answering incoming requests.
    /// If this is `None`, then the local node will not advertise support for this protocol towards
    /// other peers. If this is `Some` but the channel is closed, then the local node will
    /// advertise support for this protocol, but any incoming request will lead to an error being
    /// sent back.
    pub inbound_queue: Option<mpsc::Sender<IncomingRequest>>,

    /// The max. buffer length for incoming requests per peer.
    /// Must be less or equal to the size of `inbound_queue`.
    pub max_inbound_queue_len: NonZeroU16
}

/// A single request received by a peer on a request-response protocol.
#[derive(Debug)]
pub struct IncomingRequest {
	/// Who sent the request.
	pub peer: PeerId,

	/// Request sent by the remote. Will always be smaller than
	/// [`RequestResponseConfig::max_request_size`].
	pub payload: Vec<u8>,

	/// Channel to send back the response to.
	pub pending_response: oneshot::Sender<Vec<u8>>,
}

/// Event generated by the [`RequestResponsesBehaviour`].
#[derive(Debug)]
pub enum Event {
	/// A remote sent a request and either we have successfully answered it or an error happened.
	///
	/// This event is generated for statistics purposes.
	InboundRequest {
		/// Peer which has emitted the request.
		peer: PeerId,
		/// Name of the protocol in question.
		protocol: Cow<'static, str>,
		/// If `Ok`, contains the time elapsed between when we received the request and when we
		/// sent back the response. If `Err`, the error that happened.
		result: Result<Duration, ResponseFailure>,
	},

	/// A request initiated using [`RequestResponsesBehaviour::send_request`] has succeeded or
	/// failed.
	RequestFinished {
		/// Request that has succeeded.
		request_id: RequestId,
		/// Response sent by the remote or reason for failure.
		result: Result<Vec<u8>, RequestFailure>,
	},
}

/// The response header is sent in front of the response body.
#[derive(Clone, Debug, Encode, Decode)]
pub struct ResponseHeader {
	/// The response body length.
	#[n(0)] length: u64,
	/// If `Some`, the number of requests the remote is allowed to send.
	/// After an endpoint used up its budget it must wait for a response which
	/// grants it more budget.
	#[n(1)] budget: Option<u16>
}

/// Implementation of `NetworkBehaviour` that provides support for request-response protocols.
pub struct RequestResponsesBehaviour {
	/// The multiple sub-protocols, by name.
	/// Contains the underlying libp2p `RequestResponse` behaviour, plus an optional
	/// "response builder" used to build responses for incoming requests.
	protocols: HashMap<
		Cow<'static, str>,
		(RequestResponse<GenericCodec>, Option<(NonZeroU16, mpsc::Sender<IncomingRequest>)>)
	>,

	/// Whenever an incoming request arrives, a `Future` is added to this list and will yield the
	/// response to send back to the remote.
	pending_responses: stream::FuturesUnordered<
		Pin<Box<dyn Future<Output = RequestProcessingOutcome> + Send>>
	>,

	/// The budget limits per protocol and peer.
	limits: HashMap<Cow<'static, str>, LruCache<PeerId, Limit>>
}

/// The send and receive budget limits.
struct Limit {
	/// The remaining number of outbound requests.
	/// Decremented when requests are sent.
	send_budget: u16,
	/// The expected number of inbound requests.
	/// When used up the responder must grant more sending credit to the remote.
	recv_budget: u16,
	/// An event to listen on when no more sending credit is available.
	event: TryAgainEvent
}

/// Generated by the response builder and waiting to be processed.
enum RequestProcessingOutcome {
	Response {
		protocol: Cow<'static, str>,
		inner_channel: ResponseChannel<Result<(ResponseHeader, Vec<u8>), ()>>,
		header: ResponseHeader,
		response: Vec<u8>,
	},
	Error {
		peer: PeerId,
		protocol: Cow<'static, str>,
	},
}

impl RequestResponsesBehaviour {
	/// Creates a new behaviour. Must be passed a list of supported protocols. Returns an error if
	/// the same protocol is passed twice.
	pub fn new(list: impl Iterator<Item = ProtocolConfig>) -> Result<Self, RegisterError> {
		let mut limits = HashMap::new();
		let mut protocols = HashMap::new();
		for protocol in list {
			let mut cfg = RequestResponseConfig::default();
			cfg.set_connection_keep_alive(Duration::from_secs(10));
			cfg.set_request_timeout(protocol.request_timeout);

			let protocol_support = if protocol.inbound_queue.is_some() {
				ProtocolSupport::Full
			} else {
				ProtocolSupport::Outbound
			};

			let rq_rp = RequestResponse::new(GenericCodec {
				max_request_size: protocol.max_request_size,
				max_response_size: protocol.max_response_size,
				buffer: Vec::new()
			}, iter::once((protocol.name.as_bytes().to_vec(), protocol_support)), cfg);

			match protocols.entry(protocol.name.clone()) {
				Entry::Vacant(e) => {
					let val = if let Some(q) = protocol.inbound_queue {
						Some((protocol.max_inbound_queue_len, q))
					} else {
						None
					};
					e.insert((rq_rp, val));
				}
				Entry::Occupied(e) => return Err(RegisterError::DuplicateProtocol(e.key().clone()))
			}

			limits.insert(protocol.name, LruCache::new(4096));
		}

		Ok(Self {
			protocols,
			pending_responses: stream::FuturesUnordered::new(),
			limits
		})
	}

	/// Initiates sending a request.
	///
	/// An error is returned if we are not connected to the target peer or if the protocol doesn't
	/// match one that has been registered.
	pub fn send_request(&mut self, target: &PeerId, protocol: &str, request: Vec<u8>) -> Result<RequestId, SendRequestError> {
		if let Some((proto, _)) = self.protocols.get_mut(protocol) {
			if proto.is_connected(target) {
				if let Some(peers) = self.limits.get_mut(protocol) {
					if let Some(limit) = peers.get_mut(target) {
						if limit.send_budget == 0 {
							return Err(SendRequestError::BackOff(limit.event.listen(), request))
						}
						limit.send_budget -= 1
					}
				}
				Ok(proto.send_request(target, request))
			} else {
				Err(SendRequestError::NotConnected)
			}
		} else {
			Err(SendRequestError::UnknownProtocol)
		}
	}
}

impl NetworkBehaviour for RequestResponsesBehaviour {
	type ProtocolsHandler = MultiHandler<
		String,
		<RequestResponse<GenericCodec> as NetworkBehaviour>::ProtocolsHandler,
	>;
	type OutEvent = Event;

	fn new_handler(&mut self) -> Self::ProtocolsHandler {
		let iter = self.protocols.iter_mut()
			.map(|(p, (r, _))| (p.to_string(), NetworkBehaviour::new_handler(r)));

		MultiHandler::try_from_iter(iter)
			.expect("Protocols are in a HashMap and there can be at most one handler per \
						  protocol name, which is the only possible error; qed")
	}

	fn addresses_of_peer(&mut self, _: &PeerId) -> Vec<Multiaddr> {
		Vec::new()
	}

	fn inject_connection_established(
		&mut self,
		peer_id: &PeerId,
		conn: &ConnectionId,
		endpoint: &ConnectedPoint,
	) {
		for (p, _) in self.protocols.values_mut() {
			NetworkBehaviour::inject_connection_established(p, peer_id, conn, endpoint)
		}
	}

	fn inject_connected(&mut self, peer_id: &PeerId) {
		for (p, _) in self.protocols.values_mut() {
			NetworkBehaviour::inject_connected(p, peer_id)
		}
		for (proto, data) in &self.protocols {
			if let (_, Some(_)) = data {
				if let Some(peers) = self.limits.get_mut(proto) {
					let limit = Limit {
						send_budget: 1,
						recv_budget: 1, // Initially 1 so we grant more upon receiving the first request.
						event: TryAgainEvent::new()
					};
					peers.put(peer_id.clone(), limit);
				}
			}
		}
	}

	fn inject_connection_closed(&mut self, peer_id: &PeerId, conn: &ConnectionId, endpoint: &ConnectedPoint) {
		for (p, _) in self.protocols.values_mut() {
			NetworkBehaviour::inject_connection_closed(p, peer_id, conn, endpoint)
		}
	}

	fn inject_disconnected(&mut self, peer_id: &PeerId) {
		for (p, _) in self.protocols.values_mut() {
			NetworkBehaviour::inject_disconnected(p, peer_id)
		}
	}

	fn inject_addr_reach_failure(
		&mut self,
		peer_id: Option<&PeerId>,
		addr: &Multiaddr,
		error: &dyn std::error::Error
	) {
		for (p, _) in self.protocols.values_mut() {
			NetworkBehaviour::inject_addr_reach_failure(p, peer_id, addr, error)
		}
	}

	fn inject_event(
		&mut self,
		peer_id: PeerId,
		connection: ConnectionId,
		(p_name, event): <Self::ProtocolsHandler as ProtocolsHandler>::OutEvent,
	) {
		if let Some((proto, _)) = self.protocols.get_mut(&*p_name) {
			return proto.inject_event(peer_id, connection, event)
		}

		log::warn!(target: "sub-libp2p",
			"inject_node_event: no request-response instance registered for protocol {:?}",
			p_name)
	}

	fn inject_new_external_addr(&mut self, addr: &Multiaddr) {
		for (p, _) in self.protocols.values_mut() {
			NetworkBehaviour::inject_new_external_addr(p, addr)
		}
	}

	fn inject_expired_listen_addr(&mut self, addr: &Multiaddr) {
		for (p, _) in self.protocols.values_mut() {
			NetworkBehaviour::inject_expired_listen_addr(p, addr)
		}
	}

	fn inject_dial_failure(&mut self, peer_id: &PeerId) {
		for (p, _) in self.protocols.values_mut() {
			NetworkBehaviour::inject_dial_failure(p, peer_id)
		}
	}

	fn inject_new_listen_addr(&mut self, addr: &Multiaddr) {
		for (p, _) in self.protocols.values_mut() {
			NetworkBehaviour::inject_new_listen_addr(p, addr)
		}
	}

	fn inject_listener_error(&mut self, id: ListenerId, err: &(dyn std::error::Error + 'static)) {
		for (p, _) in self.protocols.values_mut() {
			NetworkBehaviour::inject_listener_error(p, id, err)
		}
	}

	fn inject_listener_closed(&mut self, id: ListenerId, reason: Result<(), &io::Error>) {
		for (p, _) in self.protocols.values_mut() {
			NetworkBehaviour::inject_listener_closed(p, id, reason)
		}
	}

	fn poll(
		&mut self,
		cx: &mut Context,
		params: &mut impl PollParameters,
	) -> Poll<
		NetworkBehaviourAction<
			<Self::ProtocolsHandler as ProtocolsHandler>::InEvent,
			Self::OutEvent,
		>,
	> {
		'poll_all: loop {
			// Poll to see if any response is ready to be sent back.
			while let Poll::Ready(Some(result)) = self.pending_responses.poll_next_unpin(cx) {
				match result {
					RequestProcessingOutcome::Response { protocol, inner_channel, header, response } => {
						if let Some((protocol, _)) = self.protocols.get_mut(&*protocol) {
							protocol.send_response(inner_channel, Ok((header, response)));
						}
					}
					RequestProcessingOutcome::Error { peer, protocol } => {
						let out = Event::InboundRequest {
							peer,
							protocol,
							result: Err(ResponseFailure::Busy),
						};
						return Poll::Ready(NetworkBehaviourAction::GenerateEvent(out));
					}
				}
			}

			// Poll request-responses protocols.
			for (protocol, (behaviour, resp_builder)) in &mut self.protocols {
				while let Poll::Ready(ev) = behaviour.poll(cx, params) {
					let ev = match ev {
						// Main events we are interested in.
						NetworkBehaviourAction::GenerateEvent(ev) => ev,

						// Other events generated by the underlying behaviour are transparently
						// passed through.
						NetworkBehaviourAction::DialAddress { address } => {
							log::error!("The request-response isn't supposed to start dialing peers");
							return Poll::Ready(NetworkBehaviourAction::DialAddress { address })
						}
						NetworkBehaviourAction::DialPeer { peer_id, condition } => {
							log::error!("The request-response isn't supposed to start dialing peers");
							return Poll::Ready(NetworkBehaviourAction::DialPeer {
								peer_id,
								condition,
							})
						}
						NetworkBehaviourAction::NotifyHandler {
							peer_id,
							handler,
							event,
						} => {
							return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
								peer_id,
								handler,
								event: ((*protocol).to_string(), event),
							})
						}
						NetworkBehaviourAction::ReportObservedAddr { address } => {
							return Poll::Ready(NetworkBehaviourAction::ReportObservedAddr {
								address,
							})
						}
					};

					match ev {
						// Received a request from a remote.
						RequestResponseEvent::Message {
							peer,
							message: RequestResponseMessage::Request { request, channel },
						} => {
							let (tx, rx) = oneshot::channel();
							let mut new_budget = None;

							// Submit the request to the "response builder" passed by the user at
							// initialization.
							if let Some((qlen, resp_builder)) = resp_builder {
								if let Some(peers) = self.limits.get_mut(protocol) {
									if let Some(limit) = peers.get_mut(&peer) {
										match limit.recv_budget {
											0 => {
												log::warn!("received request while out of budget");
												// TODO: Inform peerset manager of misbehaviour.
												continue 'poll_all
											}
											1 => {
												limit.recv_budget -= 1;
												new_budget = Some(qlen.get())
											}
											_ => {
												limit.recv_budget -= 1
											}
										}
									}
								}
								// If the response builder is too busy, silently drop `tx`.
								// This will be reported as a `Busy` error.
								let _ = resp_builder.try_send(IncomingRequest {
									peer: peer.clone(),
									payload: request,
									pending_response: tx,
								});
							}

							let protocol = protocol.clone();
							self.pending_responses.push(Box::pin(async move {
								// The `tx` created above can be dropped if we are not capable of
								// processing this request, which is reflected as a "Busy" error.
								if let Ok(response) = rx.await {
									let header = ResponseHeader {
										length: response.len() as u64,
										budget: new_budget
									};
									RequestProcessingOutcome::Response {
										protocol,
										inner_channel: channel,
										header,
										response
									}
								} else {
									RequestProcessingOutcome::Error { peer, protocol }
								}
							}));

							// This `continue` makes sure that `pending_responses` gets polled
							// after we have added the new element.
							continue 'poll_all;
						}

						// Received a response from a remote to one of our requests.
						RequestResponseEvent::Message {
							peer,
							message:
								RequestResponseMessage::Response {
									request_id,
									response,
								},
							..
						} => {
							let out = match response {
								Ok((header, body)) => {
									if let Some(new_budget) = header.budget {
										if let Some(peers) = self.limits.get_mut(protocol) {
											if let Some(limit) = peers.get_mut(&peer) {
												limit.send_budget = new_budget;
												limit.event.notify(usize::from(new_budget))
											}
										}
									}
									Event::RequestFinished { request_id, result: Ok(body) }
								}
								Err(()) => Event::RequestFinished { request_id, result: Err(RequestFailure::Refused) }
							};
							return Poll::Ready(NetworkBehaviourAction::GenerateEvent(out));
						}

						// One of our requests has failed.
						RequestResponseEvent::OutboundFailure {
							request_id,
							error,
							..
						} => {
							// TODO: Reset sending budget.
							let out = Event::RequestFinished {
								request_id,
								result: Err(RequestFailure::Network(error)),
							};
							return Poll::Ready(NetworkBehaviourAction::GenerateEvent(out));
						}

						// Remote has tried to send a request but failed.
						RequestResponseEvent::InboundFailure { peer, error } => {
							// TODO: Reset receive budget if timeout.
							let out = Event::InboundRequest {
								peer,
								protocol: protocol.clone(),
								result: Err(ResponseFailure::Network(error)),
							};
							return Poll::Ready(NetworkBehaviourAction::GenerateEvent(out));
						}
					};
				}
			}

			break Poll::Pending;
		}
	}
}

/// Error when registering a protocol.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum RegisterError {
	/// A protocol has been specified multiple times.
	DuplicateProtocol(#[error(ignore)] Cow<'static, str>),
}

/// Error when sending a request.
#[derive(Debug, thiserror::Error)]
pub enum SendRequestError {
	/// We are not currently connected to the requested peer.
	#[error("Not connected to the requested peer")]
	NotConnected,
	/// Given protocol hasn't been registered.
	#[error("Protocol has not been registered")]
	UnknownProtocol,
	/// Currently too busy.
	/// Wait until we tell you to try again.
	#[error("Can not send request right now.")]
	BackOff(EventListener, Vec<u8>)
}

/// Error in a request.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum RequestFailure {
	/// Remote has closed the substream before answering, thereby signaling that it considers the
	/// request as valid, but refused to answer it.
	Refused,
	/// Problem on the network.
	#[display(fmt = "Problem on the network")]
	Network(#[error(ignore)] OutboundFailure),
}

/// Error when processing a request sent by a remote.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum ResponseFailure {
	/// Internal response builder is too busy to process this request.
	Busy,
	/// Problem on the network.
	#[display(fmt = "Problem on the network")]
	Network(#[error(ignore)] InboundFailure),
}

/// Implements the libp2p [`RequestResponseCodec`] trait. Defines how streams of bytes are turned
/// into requests and responses and vice-versa.
#[derive(Debug, Clone)]
#[doc(hidden)]  // Needs to be public in order to satisfy the Rust compiler.
pub struct GenericCodec {
	max_request_size: u64,
	max_response_size: u64,
	buffer: Vec<u8>
}

#[async_trait::async_trait]
impl RequestResponseCodec for GenericCodec {
	type Protocol = Vec<u8>;
	type Request = Vec<u8>;
	type Response = Result<(ResponseHeader, Vec<u8>), ()>;

	async fn read_request<T>(
		&mut self,
		_: &Self::Protocol,
		mut io: &mut T,
	) -> io::Result<Self::Request>
	where
		T: AsyncRead + Unpin + Send,
	{
		// Read the length.
		let length = unsigned_varint::aio::read_usize(&mut io).await
			.map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
		if length > usize::try_from(self.max_request_size).unwrap_or(usize::max_value()) {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				format!("Request size exceeds limit: {} > {}", length, self.max_request_size)
			));
		}

		// Read the payload.
		let mut buffer = vec![0; length];
		io.read_exact(&mut buffer).await?;
		Ok(buffer)
	}

	async fn read_response<T>(
		&mut self,
		_: &Self::Protocol,
		mut io: &mut T,
	) -> io::Result<Self::Response>
	where
		T: AsyncRead + Unpin + Send,
	{
		// Note that this function returns a `Result<Result<...>>`. Returning an `Err` is
		// considered as a protocol error and will result in the entire connection being closed.
		// Returning `Ok(Err(_))` signifies that a response has successfully been fetched, and
		// that this response is an error.

		// Read the length.
		let length = match unsigned_varint::aio::read_usize(&mut io).await {
			Ok(l) => l,
			Err(unsigned_varint::io::ReadError::Io(err))
				if matches!(err.kind(), io::ErrorKind::UnexpectedEof) =>
			{
				return Ok(Err(()));
			}
			Err(err) => return Err(io::Error::new(io::ErrorKind::InvalidInput, err)),
		};

		if length > usize::from(u16::MAX) {
			return Err(io::Error::new(io::ErrorKind::InvalidInput, "response header too big"))
		}

		self.buffer.resize(length, 0u8);
		io.read_exact(&mut self.buffer).await?;
		let header: ResponseHeader = minicbor::decode(&self.buffer).unwrap(); // TODO

		if header.length > self.max_response_size {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				format!("Response size exceeds limit: {} > {}", header.length, self.max_response_size)
			));
		}

		// Read the payload.
		let mut buffer = vec![0; header.length as usize];
		io.read_exact(&mut buffer).await?;
		Ok(Ok((header, buffer)))
	}

	async fn write_request<T>(
		&mut self,
		_: &Self::Protocol,
		io: &mut T,
		req: Self::Request,
	) -> io::Result<()>
	where
		T: AsyncWrite + Unpin + Send,
	{
		// TODO: check the length?
		// Write the length.
		{
			let mut buffer = unsigned_varint::encode::usize_buffer();
			io.write_all(unsigned_varint::encode::usize(req.len(), &mut buffer)).await?;
		}

		// Write the payload.
		io.write_all(&req).await?;

		io.close().await?;
		Ok(())
	}

	async fn write_response<T>(
		&mut self,
		_: &Self::Protocol,
		io: &mut T,
		res: Self::Response,
	) -> io::Result<()>
	where
		T: AsyncWrite + Unpin + Send,
	{
		// If `res` is an `Err`, we jump to closing the substream without writing anything on it.
		if let Ok(res) = res {
			self.buffer.clear();
			minicbor::encode(&res.0, &mut self.buffer).unwrap(); // TODO
			let mut buffer = unsigned_varint::encode::usize_buffer();
			io.write_all(unsigned_varint::encode::usize(self.buffer.len(), &mut buffer)).await?;
			io.write_all(&self.buffer).await?;
			io.write_all(&res.1).await?;
		}

		io.close().await?;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use futures::{channel::mpsc, prelude::*};
	use libp2p::identity::Keypair;
	use libp2p::Multiaddr;
	use libp2p::core::upgrade;
	use libp2p::core::transport::{Transport, MemoryTransport};
	use libp2p::core::upgrade::{InboundUpgradeExt, OutboundUpgradeExt};
	use libp2p::swarm::{Swarm, SwarmEvent};
	use std::{iter, num::NonZeroU16, time::Duration};

	#[test]
	fn basic_request_response_works() {
		let protocol_name = "/test/req-rep/1";

		// Build swarms whose behaviour is `RequestResponsesBehaviour`.
		let mut swarms = (0..2)
			.map(|_| {
				let keypair = Keypair::generate_ed25519();
				let keypair2 = keypair.clone();

				let transport = MemoryTransport
					.and_then(move |out, endpoint| {
						let secio = libp2p::secio::SecioConfig::new(keypair2);
						libp2p::core::upgrade::apply(
							out,
							secio,
							endpoint,
							upgrade::Version::V1
						)
					})
					.and_then(move |(peer_id, stream), endpoint| {
						let peer_id2 = peer_id.clone();
						let upgrade = libp2p::yamux::Config::default()
							.map_inbound(move |muxer| (peer_id, muxer))
							.map_outbound(move |muxer| (peer_id2, muxer));
						upgrade::apply(stream, upgrade, endpoint, upgrade::Version::V1)
					});

				let behaviour = {
					let (tx, mut rx) = mpsc::channel(64);

					let b = super::RequestResponsesBehaviour::new(iter::once(super::ProtocolConfig {
						name: From::from(protocol_name),
						max_request_size: 1024,
						max_response_size: 1024 * 1024,
						request_timeout: Duration::from_secs(30),
						inbound_queue: Some(tx),
						max_inbound_queue_len: NonZeroU16::new(64).expect("64 > 0")
					})).unwrap();

					async_std::task::spawn(async move {
						while let Some(rq) = rx.next().await {
							assert_eq!(rq.payload, b"this is a request");
							let _ = rq.pending_response.send(b"this is a response".to_vec());
						}
					});

					b
				};

				let mut swarm = Swarm::new(transport, behaviour, keypair.public().into_peer_id());
				let listen_addr: Multiaddr = format!("/memory/{}", rand::random::<u64>()).parse().unwrap();

				Swarm::listen_on(&mut swarm, listen_addr.clone()).unwrap();
				(swarm, listen_addr)
			})
			.collect::<Vec<_>>();

		// Ask `swarm[0]` to dial `swarm[1]`. There isn't any discovery mechanism in place in
		// this test, so they wouldn't connect to each other.
		{
			let dial_addr = swarms[1].1.clone();
			Swarm::dial_addr(&mut swarms[0].0, dial_addr).unwrap();
		}

		// Running `swarm[0]` in the background until a `InboundRequest` event happens,
		// which is a hint about the test having ended.
		async_std::task::spawn({
			let (mut swarm, _) = swarms.remove(0);
			async move {
				loop {
					match swarm.next_event().await {
						SwarmEvent::Behaviour(super::Event::InboundRequest { result, .. }) => {
							assert!(result.is_ok());
							break
						},
						_ => {}
					}
				}
			}
		});

		// Remove and run the remaining swarm.
		let (mut swarm, _) = swarms.remove(0);
		async_std::task::block_on(async move {
			let mut sent_request_id = None;

			loop {
				match swarm.next_event().await {
					SwarmEvent::ConnectionEstablished { peer_id, .. } => {
						let id = swarm.send_request(
							&peer_id,
							protocol_name,
							b"this is a request".to_vec()
						).unwrap();
						assert!(sent_request_id.is_none());
						sent_request_id = Some(id);
					}
					SwarmEvent::Behaviour(super::Event::RequestFinished {
						request_id,
						result,
					}) => {
						assert_eq!(Some(request_id), sent_request_id);
						let result = result.unwrap();
						assert_eq!(result, b"this is a response");
						break;
					}
					_ => {}
				}
			}
		});
	}

	#[test]
	fn max_response_size_exceeded() {
		let protocol_name = "/test/req-rep/1";

		// Build swarms whose behaviour is `RequestResponsesBehaviour`.
		let mut swarms = (0..2)
			.map(|_| {
				let keypair = Keypair::generate_ed25519();
				let keypair2 = keypair.clone();

				let transport = MemoryTransport
					.and_then(move |out, endpoint| {
						let secio = libp2p::secio::SecioConfig::new(keypair2);
						libp2p::core::upgrade::apply(
							out,
							secio,
							endpoint,
							upgrade::Version::V1
						)
					})
					.and_then(move |(peer_id, stream), endpoint| {
						let peer_id2 = peer_id.clone();
						let upgrade = libp2p::yamux::Config::default()
							.map_inbound(move |muxer| (peer_id, muxer))
							.map_outbound(move |muxer| (peer_id2, muxer));
						upgrade::apply(stream, upgrade, endpoint, upgrade::Version::V1)
					});

				let behaviour = {
					let (tx, mut rx) = mpsc::channel(64);

					let b = super::RequestResponsesBehaviour::new(iter::once(super::ProtocolConfig {
						name: From::from(protocol_name),
						max_request_size: 1024,
						max_response_size: 8,  // <-- important for the test
						request_timeout: Duration::from_secs(30),
						inbound_queue: Some(tx),
						max_inbound_queue_len: NonZeroU16::new(64).expect("64 > 0")
					})).unwrap();

					async_std::task::spawn(async move {
						while let Some(rq) = rx.next().await {
							assert_eq!(rq.payload, b"this is a request");
							let _ = rq.pending_response.send(b"this response exceeds the limit".to_vec());
						}
					});

					b
				};

				let mut swarm = Swarm::new(transport, behaviour, keypair.public().into_peer_id());
				let listen_addr: Multiaddr = format!("/memory/{}", rand::random::<u64>()).parse().unwrap();

				Swarm::listen_on(&mut swarm, listen_addr.clone()).unwrap();
				(swarm, listen_addr)
			})
			.collect::<Vec<_>>();

		// Ask `swarm[0]` to dial `swarm[1]`. There isn't any discovery mechanism in place in
		// this test, so they wouldn't connect to each other.
		{
			let dial_addr = swarms[1].1.clone();
			Swarm::dial_addr(&mut swarms[0].0, dial_addr).unwrap();
		}

		// Running `swarm[0]` in the background until a `InboundRequest` event happens,
		// which is a hint about the test having ended.
		async_std::task::spawn({
			let (mut swarm, _) = swarms.remove(0);
			async move {
				loop {
					match swarm.next_event().await {
						SwarmEvent::Behaviour(super::Event::InboundRequest { result, .. }) => {
							assert!(result.is_ok());
							break
						},
						_ => {}
					}
				}
			}
		});

		// Remove and run the remaining swarm.
		let (mut swarm, _) = swarms.remove(0);
		async_std::task::block_on(async move {
			let mut sent_request_id = None;

			loop {
				match swarm.next_event().await {
					SwarmEvent::ConnectionEstablished { peer_id, .. } => {
						let id = swarm.send_request(
							&peer_id,
							protocol_name,
							b"this is a request".to_vec()
						).unwrap();
						assert!(sent_request_id.is_none());
						sent_request_id = Some(id);
					}
					SwarmEvent::Behaviour(super::Event::RequestFinished {
						request_id,
						result,
					}) => {
						assert_eq!(Some(request_id), sent_request_id);
						match result {
							Err(super::RequestFailure::Network(super::OutboundFailure::ConnectionClosed)) => {},
							_ => panic!()
						}
						break;
					}
					_ => {}
				}
			}
		});
	}
}
