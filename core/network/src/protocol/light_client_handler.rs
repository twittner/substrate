use codec::{self, Encode, Decode};
use client::{error::Error as ClientError, light::fetcher};
use crate::{chain::Client, protocol::api};
use futures::{prelude::*, sync::oneshot};
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
use log::{debug, error, trace};
use primitives::storage::StorageKey;
use prost::Message;
use rustc_hex::ToHex;
use sr_primitives::traits::{Block, Header, NumberFor, Zero};
use std::{
	collections::{BTreeMap, VecDeque, HashMap},
	fmt,
	iter,
	sync::Arc,
	time::Duration
};
use tokio_io::{AsyncRead, AsyncWrite};
use void::Void;

/// Possible errors while handling light clients.
#[derive(Debug)]
pub enum Error {
	/// There are currently too many pending request.
	TooManyRequests,
	/// The response type does not correspond to the issued request.
	UnexpectedResponse,
	/// The chain client errored.
	Client(ClientError),
	/// Encoding or decoding of some data failed.
	Codec(codec::Error)
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Error::TooManyRequests => f.write_str("too many pending requests"),
			Error::UnexpectedResponse => f.write_str("unexpected response"),
			Error::Client(e) => write!(f, "client error: {}", e),
			Error::Codec(e) => write!(f, "codec error: {}", e)
		}
	}
}

impl std::error::Error for Error {
	fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Error::Client(e) => Some(e),
			Error::Codec(e) => Some(e),
			Error::UnexpectedResponse | Error::TooManyRequests => None
		}
	}
}

impl From<ClientError> for Error {
	fn from(e: ClientError) -> Self {
		Error::Client(e)
	}
}

impl From<codec::Error> for Error {
	fn from(e: codec::Error) -> Self {
		Error::Codec(e)
	}
}

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

/// The possible light client requests we support.
///
/// The associated `oneshot::Sender` will be used to convey the result of
/// their request back to them (cf. `Reply`).
#[derive(Debug)]
pub enum LightClientRequest<B: Block> {
	Header(fetcher::RemoteHeaderRequest<B::Header>, oneshot::Sender<Result<B::Header, ClientError>>),
	Read(fetcher::RemoteReadRequest<B::Header>, oneshot::Sender<Result<Option<Vec<u8>>, ClientError>>),
	ReadChild(fetcher::RemoteReadChildRequest<B::Header>, oneshot::Sender<Result<Option<Vec<u8>>, ClientError>>),
	Call(fetcher::RemoteCallRequest<B::Header>, oneshot::Sender<Result<Vec<u8>, ClientError>>),
	Changes(fetcher::RemoteChangesRequest<B::Header>, oneshot::Sender<Result<Vec<(NumberFor<B>, u32)>, ClientError>>)
}

/// The data to send back to the light client over the oneshot channel.
///
/// It is unified here in order to be able to return it as a function
/// result instead of delivering it to the client as a side effect of
/// response processing.
#[derive(Debug)]
enum Reply<B: Block> {
	VecU8(Vec<u8>),
	VecNumberU32(Vec<(<B::Header as Header>::Number, u32)>),
	OptVecU8(Option<Vec<u8>>),
	Header(B::Header)
}

/// Augments a light client request with metadata.
#[derive(Debug)]
struct RequestWrapper<B: Block, P> {
	/// Remaining retries.
	retries: usize,
	/// The actual request.
	request: LightClientRequest<B>,
	/// Peer information, e.g. `PeerId`.
	peer: P
}

/// Information we have about some peer.
#[derive(Debug)]
struct PeerInfo<B: Block> {
	address: Multiaddr,
	best_block: Option<NumberFor<B>>,
	status: PeerStatus
}

/// A peer is either idle or busy processing a request from us.
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
	/// Verifies that received responses are correct.
	checker: Arc<dyn fetcher::FetchChecker<B>>,
	/// Peer information (addresses, their best block, etc.)
	peers: HashMap<PeerId, PeerInfo<B>>,
	/// Pending response futures.
	responses: VecDeque<WriteOne<Negotiated<T>, Vec<u8>>>,
	/// Pending requests.
	pending_requests: VecDeque<RequestWrapper<B, ()>>,
	/// In flight requests.
	outstanding: HashMap<u64, RequestWrapper<B, PeerId>>,
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
			checker,
			peers: HashMap::new(),
			responses: VecDeque::new(),
			pending_requests: VecDeque::new(),
			outstanding: HashMap::new(),
			next_request_id: 1
		}
	}

	/// We rely on external information about peers best block as we lack the
	/// means to determine it ourselves.
	pub fn update_best_block(&mut self, peer: &PeerId, num: NumberFor<B>) {
		if let Some(info) = self.peers.get_mut(peer) {
			info.best_block = Some(num)
		}
	}

	/// Issue a new light client request.
	pub fn request(&mut self, req: LightClientRequest<B>) -> Result<(), Error> {
		if self.pending_requests.len() >= self.config.max_pending_requests {
			return Err(Error::TooManyRequests)
		}
		let rw = RequestWrapper {
			retries: retries(&req),
			request: req,
			peer: () // we do not know the peer yet
		};
		self.pending_requests.push_back(rw);
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

	/// Remove the given peer.
	///
	/// If we have a request to this peer in flight, we move it back to
	/// (the front of) the pending requests queue.
	fn remove_peer(&mut self, peer: &PeerId) {
		if let Some(id) = self.outstanding.iter().find(|(_, rw)| &rw.peer == peer).map(|(k, _)| *k) {
			let rw = self.outstanding.remove(&id).expect("key belongs to entry in this map");
			let rw = RequestWrapper {
				retries: rw.retries,
				request: rw.request,
				peer: () // need to find another peer
			};
			self.pending_requests.push_front(rw);
		}
		let _info = self.peers.remove(peer);
		debug_assert!(_info.is_some())
	}

	/// Process a request's response.
	///
	/// If successful, this will give us the actual, checked data we should be
	/// sending back to the client, otherwise an error.
	fn on_response
		( &mut self
		, peer: &PeerId
		, request: &LightClientRequest<B>
		, response: api::v1::light::Response
		) -> Result<Reply<B>, Error>
	{
		trace!("response {} from {}", response.id, peer);
		use api::v1::light::response::Response;
		match response.response {
			Some(Response::RemoteCallResponse(res)) =>
				if let LightClientRequest::Call(req, _) = request {
					let reply = self.checker.check_execution_proof(req, res.proof)?;
					Ok(Reply::VecU8(reply))
				} else {
					Err(Error::UnexpectedResponse)
				}
			Some(Response::RemoteReadResponse(res)) =>
				match request {
					LightClientRequest::Read(req, _) => {
						let reply = self.checker.check_read_proof(&req, res.proof)?;
						Ok(Reply::OptVecU8(reply))
					}
					LightClientRequest::ReadChild(req, _) => {
						let reply = self.checker.check_read_child_proof(&req, res.proof)?;
						Ok(Reply::OptVecU8(reply))
					}
					_ => Err(Error::UnexpectedResponse)
				}
			Some(Response::RemoteChangesResponse(res)) =>
				if let LightClientRequest::Changes(req, _) = request {
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
					Ok(Reply::VecNumberU32(reply))
				} else {
					Err(Error::UnexpectedResponse)
				}
			Some(Response::RemoteHeaderResponse(res)) =>
				if let LightClientRequest::Header(req, _) = request {
					let header =
						if res.header.is_empty() {
							None
						} else {
							Some(Decode::decode(&mut res.header.as_ref())?)
						};
					let reply = self.checker.check_header_proof(&req, header, res.proof)?;
					Ok(Reply::Header(reply))
				} else {
					Err(Error::UnexpectedResponse)
				}
			None => Err(Error::UnexpectedResponse)
		}
	}

	fn on_remote_call_request
		( &mut self
		, peer: &PeerId
		, request_id: u64
		, request: &api::v1::light::RemoteCallRequest
		) -> Result<api::v1::light::Response, Error>
	{
		trace!("remote call request {} from {} ({} at {:?})", request_id, peer, request.method, request.block);

		let block = Decode::decode(&mut request.block.as_ref())?;

		let proof = match self.chain.execution_proof(&block, &request.method, &request.data) {
			Ok((_, proof)) => proof,
			Err(e) => {
				trace!("remote call request {} from {} ({} at {:?}) failed with: {}",
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
		trace!("remote read request {} from {} ({} at {:?})",
			request_id,
			peer,
			request.key.to_hex::<String>(),
			request.block);

		let block = Decode::decode(&mut request.block.as_ref())?;

		let proof = match self.chain.read_proof(&block, &request.key) {
			Ok(proof) => proof,
			Err(error) => {
				trace!("remote read request {} from {} ({} at {:?}) failed with: {}",
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
		trace!("remote header proof request {} from {} ({:?})", request_id, peer, request.block);

		let block = Decode::decode(&mut request.block.as_ref())?;

		let (header, proof) = match self.chain.header_proof(block) {
			Ok((header, proof)) => (header.encode(), proof),
			Err(error) => {
				trace!("remote header proof request {} from {} ({:?}) failed with: {}",
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
		trace!("remote changes proof request {} from {} for key {} ({:?}..{:?})",
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
				trace!("remote changes proof request {} from {} for key {} ({:?}..{:?}) failed with: {}",
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
			// An incoming request from remote has been received.
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
			// A response to one of our requests has been received.
			Event::Response(response) => {
				let id = response.id;
				if let Some(request) = self.outstanding.remove(&id) {
					// We first just check if the response originates from the expected peer.
					if request.peer != peer {
						debug!("was expecting response {} from {} instead of {}", id, request.peer, peer);
						self.outstanding.insert(id, request);
						return
					}

					if let Some(info) = self.peers.get_mut(&peer) {
						if info.status != PeerStatus::BusyWith(id) {
							// If we get here, something is wrong with our internal handling of peer
							// status information. At any time, a single peer processes at most one
							// request from us and its status should contain the request ID we are
							// expecting a response for. If a peer would send us a response with a
							// random ID, we should not have an entry for it with this peer ID in
							// our `outstanding` map, so a malicious peer should not be able to get
							// us here. It is our own fault and must be fixed!
							panic!("unexpected peer status {:?} for {}", info.status, peer);
						}

						info.status = PeerStatus::Idle;

						match self.on_response(&peer, &request.request, response) {
							Ok(reply) => send_reply(reply, request.request),
							Err(Error::UnexpectedResponse) => {
								debug!("unexpected response {} from peer {}", id, peer);
								self.remove_peer(&peer);
								let rw = RequestWrapper {
									retries: request.retries,
									request: request.request,
									peer: ()
								};
								self.pending_requests.push_back(rw);
							}
							Err(other) => {
								debug!("error handling response {} from peer {}: {}", id, peer, other);
								if request.retries > 0 {
									let rw = RequestWrapper {
										retries: request.retries - 1,
										request: request.request,
										peer: ()
									};
									self.pending_requests.push_back(rw)
								}
							}
						}
					} else {
						// If we get here, something is wrong with our internal handling of peers.
						// We apparently have an entry in our `outstanding` map and the peer is the one we
						// expected. So, if we can not find an entry for it in our peer information table,
						// then these two collections are out of sync which must not happen and is a clear
						// programmer error that must be fixed!
						panic!("missing peer information for {}; response {}", peer, id);
					}
				} else {
					debug!("unexpected response {} from peer {}", id, peer)
				}
			}
		}
	}

	fn poll(&mut self, _: &mut impl PollParameters) -> Async<NetworkBehaviourAction<OutboundProtocol, Void>> {
		// If we have a pending request to send, try to find an available peer and send it.
		if let Some(request) = self.pending_requests.pop_front() {
			let number = required_block(&request.request);
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
				let rq = serialise_request(id, &request.request);
				let mut buf = Vec::with_capacity(rq.encoded_len());
				if let Err(e) = rq.encode(&mut buf) {
					debug!("failed to serialise request {}: {}", id, e)
				} else {
					let protocol = OutboundProtocol {
						request: buf,
						max_data_size: self.config.max_data_size
					};
					self.peers.get_mut(&peer).map(|info| info.status = PeerStatus::BusyWith(id));
					let rw = RequestWrapper {
						retries: request.retries,
						request: request.request,
						peer: peer.clone()
					};
					self.outstanding.insert(id, rw);
					return Async::Ready(NetworkBehaviourAction::SendEvent { peer_id: peer, event: protocol })
				}
			} else {
				self.pending_requests.push_front(request);
				debug!("no peer available to send request to")
			}
		}

		// Process response sending futures.
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

fn required_block<B: Block>(request: &LightClientRequest<B>) -> NumberFor<B> {
	match request {
		LightClientRequest::Header(data, _) => data.block,
		LightClientRequest::Read(data, _) => *data.header.number(),
		LightClientRequest::ReadChild(data, _) => *data.header.number(),
		LightClientRequest::Call(data, _) => *data.header.number(),
		LightClientRequest::Changes(data, _) => data.max_block.0
	}
}

fn retries<B: Block>(request: &LightClientRequest<B>) -> usize {
	let rc = match request {
		LightClientRequest::Header(data, _) => data.retry_count,
		LightClientRequest::Read(data, _) => data.retry_count,
		LightClientRequest::ReadChild(data, _) => data.retry_count,
		LightClientRequest::Call(data, _) => data.retry_count,
		LightClientRequest::Changes(data, _) => data.retry_count
	};
	rc.unwrap_or(0)
}

fn serialise_request<B: Block>(id: u64, request: &LightClientRequest<B>) -> api::v1::light::Request {
	let request = match request {
		LightClientRequest::Header(data, _) => {
			let r = api::v1::light::RemoteHeaderRequest { block: data.block.encode() };
			api::v1::light::request::Request::RemoteHeaderRequest(r)
		}
		LightClientRequest::Read(data, _) => {
			let r = api::v1::light::RemoteReadRequest {
				block: data.block.encode(),
				key: data.key.clone()
			};
			api::v1::light::request::Request::RemoteReadRequest(r)
		}
		LightClientRequest::ReadChild(data, _) => {
			let r = api::v1::light::RemoteReadChildRequest {
				block: data.block.encode(),
				storage_key: data.storage_key.clone(),
				key: data.key.clone()
			};
			api::v1::light::request::Request::RemoteReadChildRequest(r)
		}
		LightClientRequest::Call(data, _) => {
			let r = api::v1::light::RemoteCallRequest {
				block: data.block.encode(),
				method: data.method.clone(),
				data: data.call_data.clone()
			};
			api::v1::light::request::Request::RemoteCallRequest(r)
		}
		LightClientRequest::Changes(data, _) => {
			let r = api::v1::light::RemoteChangesRequest {
				first: data.first_block.1.encode(),
				last: data.last_block.1.encode(),
				min: data.tries_roots.1.encode(),
				max: data.max_block.1.encode(),
				key: data.key.clone()
			};
			api::v1::light::request::Request::RemoteChangesRequest(r)
		}
	};

	api::v1::light::Request { id, request: Some(request) }
}

fn send_reply<B: Block>(data: Reply<B>, request: LightClientRequest<B>) {
	match (data, request) {
		(Reply::Header(x), LightClientRequest::Header(_, sender)) => {
			let _ = sender.send(Ok(x));
		}
		(Reply::OptVecU8(x), LightClientRequest::Read(_, sender)) => {
			let _ = sender.send(Ok(x));
		}
		(Reply::OptVecU8(x), LightClientRequest::ReadChild(_, sender)) => {
			let _ = sender.send(Ok(x));
		}
		(Reply::VecU8(x), LightClientRequest::Call(_, sender)) => {
			let _ = sender.send(Ok(x));
		}
		(Reply::VecNumberU32(x), LightClientRequest::Changes(_, sender)) => {
			let _ = sender.send(Ok(x));
		}
		(reply, request) => error!("invalid reply for request: {:?}, {:?}", reply, request)
	}
}

/// Output type of inbound and outbound substream upgrades.
// TODO (after https://github.com/libp2p/rust-libp2p/pull/1226): #[derive(Debug)]
pub enum Event<T> {
	/// Incoming request from remote and substream to use for the response.
	Request(api::v1::light::Request, Negotiated<T>),
	/// Incoming response from remote.
	Response(api::v1::light::Response)
}

/// Substream upgrade protocol.
///
/// Reads incoming requests from remote.
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

/// Substream upgrade protocol.
///
/// Sends a request to remote and awaits the response.
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

impl<T: AsyncRead + AsyncWrite> OutboundUpgrade<T> for OutboundProtocol {
    type Output = Event<T>;
    type Error = ReadOneError;
    type Future = RequestResponse<Negotiated<T>, (), fn(Vec<u8>, ()) -> Result<Event<T>, ReadOneError>, Vec<u8>>;

    fn upgrade_outbound(self, s: Negotiated<T>, _: Self::Info) -> Self::Future {
		request_response(s, self.request, self.max_data_size, (), |data, ()| {
			api::v1::light::Response::decode(data)
				.map(Event::Response)
				.map_err(|decode_error| {
					ReadOneError::Io(std::io::Error::new(std::io::ErrorKind::Other, decode_error))
				})
		})
	}
}

