use codec::{Encode, Decode};
use crate::{
	chain::Client,
	protocol::{api, message::BlockAttributes}
};
use futures::prelude::*;
use libp2p::{
	core::{
		ConnectedPoint,
		Multiaddr,
		PeerId,
		upgrade::{InboundUpgrade, ReadOneError, ReadRespond, UpgradeInfo, WriteOne, Negotiated, read_respond},
		upgrade::{DeniedUpgrade, write_one}
	},
	swarm::{NetworkBehaviour, NetworkBehaviourAction, OneShotHandler, PollParameters, SubstreamProtocol}
};
use log::{debug, trace};
use prost::Message;
use sr_primitives::{generic::BlockId, traits::{Block, Header, One, Zero}};
use std::{
	cmp::min,
	collections::VecDeque,
	error::Error,
	io,
	iter,
	marker::PhantomData,
	sync::Arc,
	time::Duration
};
use tokio_io::{AsyncRead, AsyncWrite};
use void::{Void, unreachable};

/// `BlockRequests` configuration options.
#[derive(Debug, Clone)]
pub struct Config {
	max_block_data_response: u32,
	max_request_len: usize,
}

impl Default for Config {
	fn default() -> Self {
		Config::new()
	}
}

impl Config {
	pub fn new() -> Self {
		Config {
			max_block_data_response: 128,
			max_request_len: 1024 * 1024
		}
	}

	pub fn set_max_block_data_response(&mut self, v: u32) -> &mut Self {
		self.max_block_data_response = v;
		self
	}

	pub fn set_max_request_len(&mut self, v: usize) -> &mut Self {
		self.max_request_len = v;
		self
	}
}

// TODO: #[derive(Debug)]
pub struct BlockRequests<T, B: Block> {
	config: Config,
	chain: Arc<dyn Client<B>>,
	outgoing: VecDeque<WriteOne<Negotiated<T>, Vec<u8>>>,
	_mark: PhantomData<T>
}

impl<T, B> BlockRequests<T, B>
where
	T: AsyncRead + AsyncWrite,
	B: Block
{
	pub fn new(cfg: Config, chain: Arc<dyn Client<B>>) -> Self {
		BlockRequests {
			config: cfg,
			chain,
			outgoing: VecDeque::new(),
			_mark: PhantomData
		}
	}

	/// Callback, invoked when a new block request has been received from remote.
	fn on_block_request
		( &mut self
		, peer: &PeerId
		, request: &api::v1::BlockRequest
		) -> Result<api::v1::BlockResponse, Box<dyn Error + 'static>>
	{
		trace!("block request {} from peer {}: from block {:?} to block {:?}, max blocks {:?}",
			request.id,
			peer,
			request.from_block,
			request.to_block,
			request.max_blocks);

		let from_block_id =
			match request.from_block {
				Some(api::v1::block_request::FromBlock::Hash(ref h)) => {
					let h = Decode::decode(&mut h.as_ref())?;
					BlockId::<B>::Hash(h)
				}
				Some(api::v1::block_request::FromBlock::Number(ref n)) => {
					let n = Decode::decode(&mut n.as_ref())?;
					BlockId::<B>::Number(n)
				}
				None => {
					let msg = "missing `BlockRequest::from_block` field";
					return Err(io::Error::new(io::ErrorKind::Other, msg).into())
				}
			};

		let max_blocks =
			if request.max_blocks == 0 {
				self.config.max_block_data_response
			} else {
				min(request.max_blocks, self.config.max_block_data_response)
			};

		let direction =
			if request.direction == api::v1::Direction::Ascending as i32 {
				api::v1::Direction::Ascending
			} else if request.direction == api::v1::Direction::Descending as i32 {
				api::v1::Direction::Descending
			} else {
				let msg = format!("invalid `BlockRequest::direction` value: {}", request.direction);
				return Err(io::Error::new(io::ErrorKind::Other, msg).into())
			};

		let attributes = BlockAttributes::decode(&mut request.fields.to_be_bytes().as_ref())?;
		let get_header = attributes.contains(BlockAttributes::HEADER);
		let get_body = attributes.contains(BlockAttributes::BODY);
		let get_justification = attributes.contains(BlockAttributes::JUSTIFICATION);

		let mut blocks = Vec::new();
		let mut block_id = from_block_id;
		while let Some(header) = self.chain.header(&block_id).unwrap_or(None) {
			if blocks.len() >= max_blocks as usize {
				break
			}

			let number = header.number().clone();
			let hash = header.hash();
			let parent_hash = header.parent_hash().clone();

			let block_data = api::v1::BlockData {
				hash: hash.encode(),
				header: if get_header {
					header.encode()
				} else {
					Vec::new()
				},
				body: if get_body {
					self.chain.body(&BlockId::Hash(hash))?
						.unwrap_or(Vec::new())
						.iter_mut()
						.map(|extrinsic| extrinsic.encode())
						.collect()
				} else {
					Vec::new()
				},
				receipt: Vec::new(),
				message_queue: Vec::new(),
				justification: if get_justification {
					self.chain.justification(&BlockId::Hash(hash))?.unwrap_or(Vec::new())
				} else {
					Vec::new()
				}
			};

			blocks.push(block_data);

			match direction {
				api::v1::Direction::Ascending => {
					block_id = BlockId::Number(number + One::one())
				}
				api::v1::Direction::Descending => {
					if number.is_zero() {
						break
					}
					block_id = BlockId::Hash(parent_hash)
				}
			}
		}

		Ok(api::v1::BlockResponse { id: request.id, blocks })
	}
}

impl<T, B> NetworkBehaviour for BlockRequests<T, B>
where
	T: AsyncRead + AsyncWrite,
	B: Block
{
	type ProtocolsHandler = OneShotHandler<T, Protocol, DeniedUpgrade, Event<T>>;
	type OutEvent = ();

	fn new_handler(&mut self) -> Self::ProtocolsHandler {
		let p = Protocol {
			max_request_len: self.config.max_request_len
		};
		OneShotHandler::new(SubstreamProtocol::new(p), Duration::from_secs(5))
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
			Event::BlockRequest(req, stream) => match self.on_block_request(&peer, &req) {
				Ok(res) => {
					trace!("enqueueing block response {} for peer {} with {} blocks", res.id, peer, res.blocks.len());
					let mut data = Vec::with_capacity(res.encoded_len());
					if let Err(e) = res.encode(&mut data) {
						debug!("error encoding block response {} for peer {}: {}", res.id, peer, e)
					} else {
						self.outgoing.push_back(write_one(stream, data))
					}
				}
				Err(e) => debug!("error handling block request {} from peer {}: {}", req.id, peer, e)
			}
		}
	}

	fn poll(&mut self, _: &mut impl PollParameters) -> Async<NetworkBehaviourAction<DeniedUpgrade, ()>> {
		let mut remaining = self.outgoing.len();
		while let Some(mut write_future) = self.outgoing.pop_front() {
			remaining -= 1;
			match write_future.poll() {
				Ok(Async::NotReady) => self.outgoing.push_back(write_future),
				Ok(Async::Ready(())) => {}
				Err(e) => debug!("error writing block response: {}", e)
			}
			if remaining == 0 {
				break
			}
		}

		if self.outgoing.is_empty() {
			Async::Ready(NetworkBehaviourAction::GenerateEvent(()))
		} else {
			Async::NotReady
		}
	}
}

// TODO: #[derive(Debug)]
pub enum Event<T> {
	BlockRequest(api::v1::BlockRequest, Negotiated<T>)
}

impl<T> From<Void> for Event<T> {
	fn from(v: Void) -> Self {
		unreachable(v)
	}
}

/// Substream upgrade protocol.
///
/// We attempt to parse an incoming protobuf encoded request (cf. `Event`)
/// which will be handled by the `BlockRequests` behaviour, i.e. the request
/// will become visible via `inject_node_event` which then dispatches to the
/// relevant callback to process the message and prepare a response.
#[derive(Debug, Clone)]
pub struct Protocol {
	max_request_len: usize
}

impl UpgradeInfo for Protocol {
    type Info = &'static [u8];
    type InfoIter = iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        iter::once(b"/substrate/1.0.0") // TODO
    }
}

impl<T: AsyncRead> InboundUpgrade<T> for Protocol {
    type Output = Event<T>;
    type Error = ReadOneError;
    type Future = ReadRespond<Negotiated<T>, (), fn(Negotiated<T>, Vec<u8>, ()) -> Result<Self::Output, Self::Error>>;

    fn upgrade_inbound(self, s: Negotiated<T>, _: Self::Info) -> Self::Future {
		read_respond(s, self.max_request_len, (), |s, buf, ()| {
			api::v1::BlockRequest::decode(buf)
				.map(move |r| Event::BlockRequest(r, s))
				.map_err(|decode_error| {
					ReadOneError::Io(std::io::Error::new(std::io::ErrorKind::Other, decode_error))
				})
		})
	}
}

