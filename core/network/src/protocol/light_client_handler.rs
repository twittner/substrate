//! `NetworkBehaviour` implementation which handles incoming light client
//! requests.
//!
//! Every request is coming in on a separate connection substream which gets
//! closed after we have sent the response back. Incoming requests are encoded
//! as protocol buffers (cf. `light.v1.proto`).

// Overview: We first define the various configuration options the
// `LightClientHandler` struct supports. Then we define the struct itself with
// its callback methods (e.g. `on_remote_call_request`) before defining the
// implementation of the `NetworkBehaviour` trait for `LightClientHandler`.
// Finally we specify `Protocol`, an `InboundUpgrade` for connection streams
// which parses incoming protobuf messages and wraps them in a `Request` object
// together with the actual connection substream. This `Protocol` is used by
// the `NetworkBehaviour`'s protocol handler (`OneShotHandler`).

use codec::{Encode, Decode};
use client::light::fetcher;
use crate::{
	chain::{Client, FinalityProofProvider},
	protocol::api
};
use futures::prelude::*;
use libp2p::{
	core::{
		ConnectedPoint,
		Multiaddr,
		PeerId,
		upgrade::{InboundUpgrade, ReadOneError, ReadRespond, UpgradeInfo, WriteOne, Negotiated, read_respond},
		upgrade::{OutboundUpgrade, write_one, RequestResponse, request_response}
	},
	swarm::{NetworkBehaviour, NetworkBehaviourAction, OneShotHandler, PollParameters, SubstreamProtocol}
};
use log::{debug, trace};
use primitives::storage::StorageKey;
use prost::Message;
use rustc_hex::ToHex;
use sr_primitives::traits::{Block, Zero};
use std::{
	collections::{BTreeMap, VecDeque},
	io,
	iter,
	sync::Arc,
	time::Duration
};
use tokio_io::{AsyncRead, AsyncWrite};

// Type alias for convenience.
pub type Error = Box<dyn std::error::Error + 'static>;

/// Configuration options for `LightClientHandler`.
#[derive(Debug, Clone)]
pub struct Config {
	max_data_size: usize,
	max_pending_requests: usize,
	inactivity_timeout: Duration,
	max_retries: u8
}

impl Default for Config {
	fn default() -> Self {
		Config::new()
	}
}

impl Config {
	pub fn new() -> Self {
		Config {
			max_data_size: 1024 * 1024,
			max_pending_requests: 32,
			inactivity_timeout: Duration::from_secs(5),
			max_retries: 1
		}
	}

	/// Limit the max. length of incoming request bytes.
	pub fn set_max_data_size(&mut self, v: usize) -> &mut Self {
		self.max_data_size = v;
		self
	}

	/// Limit the max. number of pending requests.
	pub fn set_max_pending_requests(&mut self, v: usize) -> &mut Self {
		self.max_pending_requests = v;
		self
	}

	/// Limit the max. duration the substream may remain inactive before closing it.
	pub fn set_inactivity_timeout(&mut self, v: Duration) -> &mut Self {
		self.inactivity_timeout = v;
		self
	}

	/// Limit the max. number of request retries.
	pub fn set_max_retries(&mut self, v: u8) -> &mut Self {
		self.max_retries = v;
		self
	}
}

/// The light client handler behaviour.
// TODO (after https://github.com/libp2p/rust-libp2p/pull/1226): #[derive(Debug)]
pub struct LightClientHandler<T, B: Block> {
	/// This behaviour's configuration.
	config: Config,
	/// Blockchain client.
	chain: Arc<dyn Client<B>>,
	/// When asked for a proof of finality, we use this struct to build one.
	finality_proof_provider: Option<Arc<dyn FinalityProofProvider<B>>>,
	/// Pending response futures.
	responses: VecDeque<WriteOne<Negotiated<T>, Vec<u8>>>,
	/// Pending requests.
	requests: VecDeque<api::v1::light::Request>,
	/// Request ID counter
	next_request_id: u64
}

impl<T, B> LightClientHandler<T, B>
where
	T: AsyncRead + AsyncWrite,
	B: Block
{
	pub fn new(cfg: Config, chain: Arc<dyn Client<B>>) -> Self {
		LightClientHandler {
			config: cfg,
			chain,
			finality_proof_provider: None,
			responses: VecDeque::new(),
			requests: VecDeque::new(),
			next_request_id: 1
		}
	}

	pub fn set_finality_proof_provider(&mut self, p: Option<Arc<dyn FinalityProofProvider<B>>>) {
		self.finality_proof_provider = p
	}

	pub fn request(&mut self, request_data: protocol::RequestData<B>) {
		let id = self.next_request_id;
		self.next_request_id += 1;

		match request_data {
			protocol::RequestData::RemoteCall(req, sender) => {
				let request = {
					let r = api::v1::light::RemoteCallRequest {
						block: req.block.encode(),
						method: req.method,
						data: req.call_data
					};
					api::v1::light::request::Request::RemoteCallRequest(r)
				};
				self.requests.push_back(api::v1::light::Request { id, request: Some(request) })
			}
			_ => unimplemented!()
		}
	}

	fn on_remote_call_request
		( &mut self
		, peer: &PeerId
		, request_id: u64
		, request: &api::v1::light::RemoteCallRequest
		) -> Result<api::v1::light::Response, Error>
	{
		trace!(target: "sync", "Remote call request {} from {} ({} at {:?})",
			request_id,
			peer,
			request.method,
			request.block
		);

		let block = Decode::decode(&mut request.block.as_ref())?;

		let proof = match self.chain.execution_proof(&block, &request.method, &request.data) {
			Ok((_, proof)) => proof,
			Err(e) => {
				trace!(target: "sync", "Remote call request {} from {} ({} at {:?}) failed with: {}",
					request_id,
					peer,
					request.method,
					request.block,
					e);
				Vec::new()
			}
		};

		let response = {
			let r = api::v1::light::RemoteCallResponse { proof };
			api::v1::light::response::Response::RemoteCallResponse(r)
		};

		Ok(api::v1::light::Response { id: request_id, response: Some(response) })
	}

	fn on_remote_read_request
		( &mut self
		, peer: &PeerId
		, request_id: u64
		, request: &api::v1::light::RemoteReadRequest
		) -> Result<api::v1::light::Response, Error>
	{
		trace!(target: "sync", "Remote read request {} from {} ({} at {:?})",
			request_id,
			peer,
			request.key.to_hex::<String>(),
			request.block);

		let block = Decode::decode(&mut request.block.as_ref())?;

		let proof = match self.chain.read_proof(&block, &request.key) {
			Ok(proof) => proof,
			Err(error) => {
				trace!(target: "sync", "Remote read request {} from {} ({} at {:?}) failed with: {}",
					request_id,
					peer,
					request.key.to_hex::<String>(),
					request.block,
					error);
				Vec::new()
			}
		};

		let response = {
			let r = api::v1::light::RemoteReadResponse { proof };
			api::v1::light::response::Response::RemoteReadResponse(r)
		};

		Ok(api::v1::light::Response { id: request_id, response: Some(response) })
	}

	fn on_remote_header_request
		( &mut self
		, peer: &PeerId
		, request_id: u64
		, request: &api::v1::light::RemoteHeaderRequest
		) -> Result<api::v1::light::Response, Error>
	{
		trace!(target: "sync", "Remote header proof request {} from {} ({:?})",
			request_id,
			peer,
			request.block);

		let block = Decode::decode(&mut request.block.as_ref())?;

		let (header, proof) = match self.chain.header_proof(block) {
			Ok((header, proof)) => (header.encode(), proof),
			Err(error) => {
				trace!(target: "sync", "Remote header proof request {} from {} ({:?}) failed with: {}",
					request_id,
					peer,
					request.block,
					error);
				(Default::default(), Vec::new())
			}
		};

		let response = {
			let r = api::v1::light::RemoteHeaderResponse { header, proof };
			api::v1::light::response::Response::RemoteHeaderResponse(r)
		};

		Ok(api::v1::light::Response { id: request_id, response: Some(response) })
	}

	fn on_remote_changes_request
		( &mut self
		, peer: &PeerId
		, request_id: u64
		, request: &api::v1::light::RemoteChangesRequest
		) -> Result<api::v1::light::Response, Error>
	{
		trace!(target: "sync", "Remote changes proof request {} from {} for key {} ({:?}..{:?})",
			request_id,
			peer,
			request.key.to_hex::<String>(),
			request.first,
			request.last
		);

		let first = Decode::decode(&mut request.first.as_ref())?;
		let last = Decode::decode(&mut request.last.as_ref())?;
		let min = Decode::decode(&mut request.min.as_ref())?;
		let max = Decode::decode(&mut request.max.as_ref())?;
		let key = StorageKey(request.key.clone());

		let proof = match self.chain.key_changes_proof(first, last, min, max, &key) {
			Ok(proof) => proof,
			Err(error) => {
				trace!(target: "sync",
					"Remote changes proof request {} from {} for key {} ({:?}..{:?}) failed with: {}",
					request_id,
					peer,
					key.0.to_hex::<String>(),
					request.first,
					request.last,
					error
				);
				fetcher::ChangesProof::<B::Header> {
					max_block: Zero::zero(),
					proof: Vec::new(),
					roots: BTreeMap::new(),
					roots_proof: Vec::new()
				}
			}
		};

		let response = {
			let r = api::v1::light::RemoteChangesResponse {
				max: proof.max_block.encode(),
				proof: proof.proof,
				roots: proof.roots.into_iter()
					.map(|(k, v)| api::v1::light::Pair { fst: k.encode(), snd: v.encode() })
					.collect(),
				roots_proof: proof.roots_proof
			};
			api::v1::light::response::Response::RemoteChangesResponse(r)
		};

		Ok(api::v1::light::Response { id: request_id, response: Some(response) })
	}

	fn on_finality_proof_request
		( &mut self
		, peer: &PeerId
		, request_id: u64
		, request: &api::v1::light::FinalityProofRequest
		) -> Result<api::v1::light::Response, Error>
	{
		trace!(target: "sync", "Finality proof request {} from {} for {:?}", request_id, peer, request.block);

		let block = Decode::decode(&mut request.block.as_ref())?;

		let proof =
			if let Some(provider) = &self.finality_proof_provider {
				match provider.prove_finality(block, &request.request) {
					Ok(p) => p.unwrap_or(Vec::new()),
					Err(e) => {
						trace!(target: "sync", "Finality proof request {} from {} for {:?} failed with: {}",
							request_id,
							peer,
							request.block,
							e);
						Vec::new()
					}
				}
			} else {
				return Err(io::Error::new(io::ErrorKind::Other, "Finality provider is not configured").into())
			};

		let response = {
			let r = api::v1::light::FinalityProofResponse { block: request.block.clone(), proof };
			api::v1::light::response::Response::FinalityProofResponse(r)
		};

		Ok(api::v1::light::Response { id: request_id, response: Some(response) })
	}
}

impl<T, B> NetworkBehaviour for LightClientHandler<T, B>
where
	T: AsyncRead + AsyncWrite,
	B: Block
{
	type ProtocolsHandler = OneShotHandler<T, InboundProtocol, OutboundProtocol, Event<T>>;
	type OutEvent = api::v1::light::Response;

	fn new_handler(&mut self) -> Self::ProtocolsHandler {
		let p = InboundProtocol {
			max_data_size: self.config.max_data_size
		};
		OneShotHandler::new(SubstreamProtocol::new(p), self.config.inactivity_timeout)
	}

	fn addresses_of_peer(&mut self, _: &PeerId) -> Vec<Multiaddr> {
		Vec::new()
	}

	fn inject_connected(&mut self, _peer: PeerId, _info: ConnectedPoint) {
	}

	fn inject_disconnected(&mut self, _peer: &PeerId, _info: ConnectedPoint) {
	}

	fn inject_node_event(&mut self, peer: PeerId, event: Event<T>) {
		match event {
			Event::Request(request, stream) => {
				let result = match &request.request {
					Some(api::v1::light::request::Request::RemoteCallRequest(r)) =>
						self.on_remote_call_request(&peer, request.id, r),
					Some(api::v1::light::request::Request::RemoteReadRequest(r)) =>
						self.on_remote_read_request(&peer, request.id, r),
					Some(api::v1::light::request::Request::RemoteHeaderRequest(r)) =>
						self.on_remote_header_request(&peer, request.id, r),
					Some(api::v1::light::request::Request::RemoteReadChildRequest(_)) => {
						trace!("ignoring remote read child request {} from {}", request.id, peer);
						return
					}
					Some(api::v1::light::request::Request::RemoteChangesRequest(r)) =>
						self.on_remote_changes_request(&peer, request.id, r),
					Some(api::v1::light::request::Request::FinalityProofRequest(r)) =>
						self.on_finality_proof_request(&peer, request.id, r),
					None => {
						debug!("ignoring request {} without request data from peer {}", request.id, peer);
						return
					}
				};
				match result {
					Ok(response) => {
						trace!("enqueueing response {} for peer {}", response.id, peer);
						let mut data = Vec::new();
						if let Err(e) = response.encode(&mut data) {
							debug!("error encoding response {} for peer {}: {}", response.id, peer, e)
						} else {
							self.responses.push_back(write_one(stream, data))
						}
					}
					Err(e) => debug!("error handling request {} from peer {}: {}", request.id, peer, e)
				}
			}
			Event::Response(response) => {
				self.events.push_back(response)
			}
		}
	}

	fn poll(&mut self, _: &mut impl PollParameters) -> Async<NetworkBehaviourAction<OutboundProtocol, Void>> {
		if let Some((peer, request)) = self.requests.pop_front() {
			let mut buf = Vec::with_capacity(request.encoded_len());
			if let Err(e) = request.encode(&mut buf) {
				debug!("failed to serialise request {} for peer {}: {}", request.id, peer, e)
			} else {
				let protocol = OutboundProtocol {
					request: buf,
					max_data_size: self.config.max_data_size
				};
				return Async::Ready(NetworkBehaviourAction::SendEvent { peer_id: peer, event: protocol })
			}
		}

		let mut remaining = self.responses.len();
		while let Some(mut io) = self.responses.pop_front() {
			remaining -= 1;
			match io.poll() {
				Ok(Async::NotReady) => self.responses.push_back(io),
				Ok(Async::Ready(())) => {}
				Err(e) => debug!("error writing response: {}", e)
			}
			if remaining == 0 {
				break
			}
		}

		Async::NotReady
	}
}

// TODO (after https://github.com/libp2p/rust-libp2p/pull/1226): #[derive(Debug)]
pub enum Event<T> {
	Request(api::v1::light::Request, Negotiated<T>),
	Response(api::v1::light::Response)
}

impl<T> From<api::v1::light::Response> for Event<T> {
	fn from(r: api::v1::light::Response) -> Self {
		Event::Response(r)
	}
}

/// Substream upgrade protocol.
#[derive(Debug, Clone)]
pub struct InboundProtocol {
	/// The max. request length in bytes.
	max_data_size: usize
}

impl UpgradeInfo for InboundProtocol {
    type Info = &'static [u8];
    type InfoIter = iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        iter::once(b"/polkadot/light/1")
    }
}

impl<T: AsyncRead> InboundUpgrade<T> for InboundProtocol {
    type Output = Event<T>;
    type Error = ReadOneError;
    type Future = ReadRespond<Negotiated<T>, (), fn(Negotiated<T>, Vec<u8>, ()) -> Result<Self::Output, Self::Error>>;

    fn upgrade_inbound(self, s: Negotiated<T>, _: Self::Info) -> Self::Future {
		read_respond(s, self.max_data_size, (), |s, buf, ()| {
			api::v1::light::Request::decode(buf)
				.map(move |r| Event::Request(r, s))
				.map_err(|decode_error| {
					ReadOneError::Io(std::io::Error::new(std::io::ErrorKind::Other, decode_error))
				})
		})
	}
}

#[derive(Debug, Clone)]
pub struct OutboundProtocol {
	/// The serialised protobuf request.
	request: Vec<u8>,
	/// The max. request length in bytes.
	max_data_size: usize
}

impl UpgradeInfo for OutboundProtocol {
    type Info = &'static [u8];
    type InfoIter = iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        iter::once(b"/polkadot/light/1")
    }
}

type OnResponse = fn(Vec<u8>, ()) -> Result<api::v1::light::Response, ReadOneError>;

impl<T: AsyncRead + AsyncWrite> OutboundUpgrade<T> for OutboundProtocol {
    type Output = api::v1::light::Response;
    type Error = ReadOneError;
    type Future = RequestResponse<Negotiated<T>, (), OnResponse, Vec<u8>>;

    fn upgrade_outbound(self, s: Negotiated<T>, _: Self::Info) -> Self::Future {
		request_response(s, self.request, self.max_data_size, (), |data, ()| {
			api::v1::light::Response::decode(data)
				.map_err(|decode_error| {
					ReadOneError::Io(std::io::Error::new(std::io::ErrorKind::Other, decode_error))
				})
		})
	}
}
