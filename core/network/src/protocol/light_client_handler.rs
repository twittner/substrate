use codec::{Encode, Decode};
use client::light::fetcher;
use crate::{
	chain::{Client, FinalityProofProvider},
	protocol::{self, api}
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
use sr_primitives::traits::{Block, Header, NumberFor, Zero};
use std::{
	collections::{BTreeMap, VecDeque, HashMap},
	io,
	iter,
	sync::Arc,
	time::Duration
};
use tokio_io::{AsyncRead, AsyncWrite};
use void::Void;

// Type alias for convenience.
pub type Error = Box<dyn std::error::Error + 'static>;

/// Configuration options for `LightClientHandler`.
#[derive(Debug, Clone)]
pub struct Config {
	max_data_size: usize,
	max_pending_requests: usize,
	inactivity_timeout: Duration
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
			max_pending_requests: 128,
			inactivity_timeout: Duration::from_secs(5)
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
}

#[derive(Debug)]
struct PeerInfo<B: Block> {
	address: Multiaddr,
	best_block: Option<NumberFor<B>>,
	status: PeerStatus
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PeerStatus {
	/// The peer is available.
	Idle,
	/// We wait for the peer to return us a response for the given request ID.
	BusyWith(u64)
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
	/// Verifies that received responses are correct.
	checker: Arc<dyn fetcher::FetchChecker<B>>,
	/// Peer information (addresses, their best block, etc.)
	peers: HashMap<PeerId, PeerInfo<B>>,
	/// Pending response futures.
	responses: VecDeque<WriteOne<Negotiated<T>, Vec<u8>>>,
	/// Pending requests.
	pending_requests: VecDeque<protocol::RequestData<B>>,
	/// In flight requests.
	outstanding: HashMap<u64, (PeerId, protocol::RequestData<B>)>,
	/// Request ID counter
	next_request_id: u64
}

impl<T, B> LightClientHandler<T, B>
where
	T: AsyncRead + AsyncWrite,
	B: Block
{
	pub fn new(cfg: Config, chain: Arc<dyn Client<B>>, checker: Arc<dyn fetcher::FetchChecker<B>>) -> Self {
		LightClientHandler {
			config: cfg,
			chain,
			finality_proof_provider: None,
			checker,
			peers: HashMap::new(),
			responses: VecDeque::new(),
			pending_requests: VecDeque::new(),
			outstanding: HashMap::new(),
			next_request_id: 1
		}
	}

	pub fn set_finality_proof_provider(&mut self, p: Option<Arc<dyn FinalityProofProvider<B>>>) {
		self.finality_proof_provider = p
	}

	pub fn update_best_block(&mut self, peer: &PeerId, num: NumberFor<B>) {
		self.peers.get_mut(peer).map(|info| {
			info.best_block = Some(num)
		});
	}

	pub(crate) fn request(&mut self, request_data: protocol::RequestData<B>) -> Result<(), Error> {
		if self.pending_requests.len() >= self.config.max_pending_requests {
			return Err(std::io::Error::new(std::io::ErrorKind::Other, "too many pending requests").into())
		}
		self.pending_requests.push_back(request_data);
		Ok(())
	}

	fn next_request_id(&mut self) -> u64 {
		let id = self.next_request_id;
		self.next_request_id += 1;
		id
	}

	fn idle_peers_with_block(&mut self, num: NumberFor<B>) -> impl Iterator<Item = PeerId> + '_ {
		self.peers.iter()
			.filter(move |(_, info)| {
				info.status == PeerStatus::Idle && info.best_block >= Some(num)
			})
			.map(|(peer, _)| peer.clone())
	}

	fn idle_peers_with_unknown_block(&mut self) -> impl Iterator<Item = PeerId> + '_ {
		self.peers.iter()
			.filter(|(_, info)| {
				info.status == PeerStatus::Idle && info.best_block.is_none()
			})
			.map(|(peer, _)| peer.clone())
	}

	fn remove_peer(&mut self, peer: &PeerId) {
		// If we have a request in flight, we move it back to (the front of) the pending requests queue.
		if let Some(id) = self.outstanding.iter().find(|(_, (p, _))| p == peer).map(|(k, _)| *k) {
			let (_, request_data) = self.outstanding.remove(&id).expect("key belongs to entry in this map");
			self.pending_requests.push_front(request_data);
		}
		let _info = self.peers.remove(peer);
		debug_assert!(_info.is_some())
	}

	fn on_response
		( &mut self
		, peer: &PeerId
		, response: api::v1::light::Response
		, request: protocol::RequestData<B>
		) -> Result<(), Error>
	{
		trace!(target: "sync", "response {} from {}", response.id, peer);
		use api::v1::light::response::Response;
		match response.response {
			Some(Response::RemoteCallResponse(res)) =>
				if let protocol::RequestData::RemoteCall(req, sender) = request {
					let reply = self.checker.check_execution_proof(&req, res.proof)?;
					let _ = sender.send(Ok(reply));
					Ok(())
				} else {
					Err(io::Error::new(io::ErrorKind::Other, "invalid response type").into())
				}
			Some(Response::RemoteReadResponse(res)) =>
				match request {
					protocol::RequestData::RemoteRead(req, sender) => {
						let reply = self.checker.check_read_proof(&req, res.proof)?;
						let _ = sender.send(Ok(reply));
						Ok(())
					}
					protocol::RequestData::RemoteReadChild(req, sender) => {
						let reply = self.checker.check_read_child_proof(&req, res.proof)?;
						let _ = sender.send(Ok(reply));
						Ok(())
					}
					_ => Err(io::Error::new(io::ErrorKind::Other, "invalid response type").into())
				}
			Some(Response::RemoteChangesResponse(res)) =>
				if let protocol::RequestData::RemoteChanges(req, sender) = request {
					let max_block = Decode::decode(&mut res.max.as_ref())?;
					let roots = {
						let mut r = BTreeMap::new();
						for pair in res.roots {
							let k = Decode::decode(&mut pair.fst.as_ref())?;
							let v = Decode::decode(&mut pair.snd.as_ref())?;
							r.insert(k, v);
						}
						r
					};
					let reply = self.checker.check_changes_proof(&req, fetcher::ChangesProof {
						max_block,
						proof: res.proof,
						roots,
						roots_proof: res.roots_proof
					})?;
					let _ = sender.send(Ok(reply));
					Ok(())
				} else {
					Err(io::Error::new(io::ErrorKind::Other, "invalid response type").into())
				}
			Some(Response::RemoteHeaderResponse(res)) =>
				if let protocol::RequestData::RemoteHeader(req, sender) = request {
					let header =
						if res.header.is_empty() {
							None
						} else {
							Some(Decode::decode(&mut res.header.as_ref())?)
						};
					let reply = self.checker.check_header_proof(&req, header, res.proof)?;
					let _ = sender.send(Ok(reply));
					Ok(())
				} else {
					Err(io::Error::new(io::ErrorKind::Other, "invalid response type").into())
				}
			None => Err(io::Error::new(io::ErrorKind::Other, "missing response data").into()),
			_ => Err(io::Error::new(io::ErrorKind::Other, "unhandled response type").into())
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
	type OutEvent = Void;

	fn new_handler(&mut self) -> Self::ProtocolsHandler {
		let p = InboundProtocol {
			max_data_size: self.config.max_data_size
		};
		OneShotHandler::new(SubstreamProtocol::new(p), self.config.inactivity_timeout)
	}

	fn addresses_of_peer(&mut self, peer: &PeerId) -> Vec<Multiaddr> {
		self.peers.get(peer)
			.map(|info| vec![info.address.clone()])
			.unwrap_or_default()
	}

	fn inject_connected(&mut self, peer: PeerId, info: ConnectedPoint) {
		let peer_address = match info {
			ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
			ConnectedPoint::Dialer { address } => address
		};

		trace!("peer {} connected with address {}", peer, peer_address);

		let info = PeerInfo {
			address: peer_address,
			best_block: None,
			status: PeerStatus::Idle
		};

		let _previous = self.peers.insert(peer, info);
		debug_assert!(_previous.is_none())
	}

	fn inject_disconnected(&mut self, peer: &PeerId, _: ConnectedPoint) {
		trace!("peer {} disconnected", peer);
		self.remove_peer(peer)
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
				let id = response.id;

				// We first just check if the response is expected and originates from the expected peer.
				if let Some((original_peer, _)) = self.outstanding.get(&id) {
					if original_peer != &peer {
						debug!("was expecting response {} from {} instead of {}", id, original_peer, peer);
						return
					}
				} else {
					debug!("unexpected response {} from peer {}", id, peer);
					return
				}

				// Now that we know the response is legit, let's extract the original request data.
				let request_data =
					self.outstanding.remove(&id)
						.expect("the response id refers to the same entry we looked up above")
						.1;

				if let Some(info) = self.peers.get_mut(&peer) {
					if info.status != PeerStatus::BusyWith(response.id) {
						// If we get here, something is wrong with our internal handling of peer
						// status information. At any time, a single peer processes at most one
						// request from us and its status should contain the request ID we are
						// expecting a response for. If a peer would send us a response with a
						// random ID, we should not have an entry for it in our `outstanding`
						// map, so a malicious peer should not be able to get us here. It is our
						// own fault and must be fixed!
						panic!("unexpected peer status {:?} for {}", info.status, peer);
					}
					info.status = PeerStatus::Idle;
					if let Err(e) = self.on_response(&peer, response, request_data) {
						debug!("error handling response {} from peer {}: {}", id, peer, e)
					}
				} else {
					// If we get here, something is wrong with our internal handling of peers.
					// We apparently have an entry in our `outstanding` map and the peer is the one we
					// expected. So, if we can not find an entry for it in our peer information table,
					// then these two collections are out of sync which must not happen and is a clear
					// programmer error that must be fixed!
					panic!("missing peer information for {}; response {}", peer, id);
				}
			}
		}
	}

	fn poll(&mut self, _: &mut impl PollParameters) -> Async<NetworkBehaviourAction<OutboundProtocol, Void>> {
		// If we have a pending request to send, try to find an available peer and send it.
		if let Some(request_data) = self.pending_requests.pop_front() {
			let number = required_block(&request_data);
			let available_peer = {
				let p = self.idle_peers_with_block(number).next();
				if p.is_none() {
					self.idle_peers_with_unknown_block().next()
				} else {
					p
				}
			};
			if let Some(peer) = available_peer {
				let id = self.next_request_id();
				let rq = serialise_request(id, &request_data);
				let mut buf = Vec::with_capacity(rq.encoded_len());
				if let Err(e) = rq.encode(&mut buf) {
					debug!("failed to serialise request {}: {}", id, e)
				} else {
					let protocol = OutboundProtocol {
						request: buf,
						max_data_size: self.config.max_data_size
					};
					self.peers.get_mut(&peer).map(|info| info.status = PeerStatus::BusyWith(id));
					self.outstanding.insert(id, (peer.clone(), request_data));
					return Async::Ready(NetworkBehaviourAction::SendEvent { peer_id: peer, event: protocol })
				}
			} else {
				self.pending_requests.push_front(request_data);
				debug!("no peer available to send request to")
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

fn required_block<B: Block>(request: &protocol::RequestData<B>) -> NumberFor<B> {
	match request {
		protocol::RequestData::RemoteHeader(data, _) => data.block,
		protocol::RequestData::RemoteRead(data, _) => *data.header.number(),
		protocol::RequestData::RemoteReadChild(data, _) => *data.header.number(),
		protocol::RequestData::RemoteCall(data, _) => *data.header.number(),
		protocol::RequestData::RemoteChanges(data, _) => data.max_block.0,
		protocol::RequestData::RemoteBody(data, _) => *data.header.number()
	}
}

fn serialise_request<B: Block>(id: u64, request: &protocol::RequestData<B>) -> api::v1::light::Request {
	match request {
		protocol::RequestData::RemoteCall(data, _) => {
			let req = {
				let r = api::v1::light::RemoteCallRequest {
					block: data.block.encode(),
					method: data.method.clone(),
					data: data.call_data.clone()
				};
				api::v1::light::request::Request::RemoteCallRequest(r)
			};
			api::v1::light::Request { id, request: Some(req) }
		}
		_ => unimplemented!()
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
