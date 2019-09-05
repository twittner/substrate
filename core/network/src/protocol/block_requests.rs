//! `NetworkBehaviour` implementation which handles incoming block requests.
//!
//! Every request is coming in on a separate connection substream which gets
//! closed after we have sent the response back. Incoming requests are encoded
//! as protocol buffers (cf. `api.v1.proto`).

use bytes::Bytes;
use codec::{Encode, Decode};
use crate::{
	chain::Client,
	config::ProtocolId,
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
	io,
	iter,
	sync::Arc,
	time::Duration
};
use tokio_io::{AsyncRead, AsyncWrite};
use void::{Void, unreachable};

// Type alias for convenience.
pub type Error = Box<dyn std::error::Error + 'static>;

/// Configuration options for `BlockRequests`.
#[derive(Debug, Clone)]
pub struct Config {
	max_block_data_response: u32,
	max_request_len: usize,
	inactivity_timeout: Duration,
	protocol: Bytes,
}

#[allow(unused)]
impl Config {
	/// Create a fresh configuration with the following options:
	///
	/// - max. block data in response = 128
	/// - max. request size = 1 MiB
	/// - inactivity timeout = 15s
	pub fn new(id: &ProtocolId) -> Self {
		let mut c = Config {
			max_block_data_response: 128,
			max_request_len: 1024 * 1024,
			inactivity_timeout: Duration::from_secs(15),
			protocol: Bytes::new(),
		};
		c.set_protocol(id);
		c
	}

	/// Limit the max. number of block data in a response.
	pub fn set_max_block_data_response(&mut self, v: u32) -> &mut Self {
		self.max_block_data_response = v;
		self
	}

	/// Limit the max. length of incoming block request bytes.
	pub fn set_max_request_len(&mut self, v: usize) -> &mut Self {
		self.max_request_len = v;
		self
	}

	/// Limit the max. duration the substream may remain inactive before closing it.
	pub fn set_inactivity_timeout(&mut self, v: Duration) -> &mut Self {
		self.inactivity_timeout = v;
		self
	}

	/// Set protocol to use for upgrade negotiation.
	pub fn set_protocol(&mut self, id: &ProtocolId) -> &mut Self {
		let mut v = Vec::new();
		v.extend_from_slice(b"/");
		v.extend_from_slice(id.as_bytes());
		v.extend_from_slice(b"/sync/1");
		self.protocol = v.into();
		self
	}
}

/// The block request handling behaviour.
pub struct BlockRequests<T, B: Block> {
	/// This behaviour's configuration.
	config: Config,
	/// Blockchain client.
	chain: Arc<dyn Client<B>>,
	/// Pending futures, sending back the block request response.
	outgoing: VecDeque<WriteOne<Negotiated<T>, Vec<u8>>>,
}

impl<T, B> BlockRequests<T, B>
where
	T: AsyncRead + AsyncWrite,
	B: Block,
{
	pub fn new(cfg: Config, chain: Arc<dyn Client<B>>) -> Self {
		BlockRequests {
			config: cfg,
			chain,
			outgoing: VecDeque::new(),
		}
	}

	/// Callback, invoked when a new block request has been received from remote.
	fn on_block_request
		( &mut self
		, peer: &PeerId
		, request: &api::v1::BlockRequest
		) -> Result<api::v1::BlockResponse, Error>
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
	type ProtocolsHandler = OneShotHandler<T, Protocol, DeniedUpgrade, Request<T>>;
	type OutEvent = Void;

	fn new_handler(&mut self) -> Self::ProtocolsHandler {
		let p = Protocol {
			max_request_len: self.config.max_request_len,
			protocol: self.config.protocol.clone(),
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

	fn inject_node_event(&mut self, peer: PeerId, Request(request, stream): Request<T>) {
		match self.on_block_request(&peer, &request) {
			Ok(res) => {
				trace!("enqueueing block response {} for peer {} with {} blocks", res.id, peer, res.blocks.len());
				let mut data = Vec::with_capacity(res.encoded_len());
				if let Err(e) = res.encode(&mut data) {
					debug!("error encoding block response {} for peer {}: {}", res.id, peer, e)
				} else {
					self.outgoing.push_back(write_one(stream, data))
				}
			}
			Err(e) => debug!("error handling block request {} from peer {}: {}", request.id, peer, e)
		}
	}

	fn poll(&mut self, _: &mut impl PollParameters) -> Async<NetworkBehaviourAction<DeniedUpgrade, Void>> {
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
		Async::NotReady
	}
}

/// The incoming block request.
///
/// Holds the protobuf value and the connection substream which made the
/// request and over which to send the response.
// TODO (after https://github.com/libp2p/rust-libp2p/pull/1226): #[derive(Debug)]
pub struct Request<T>(api::v1::BlockRequest, Negotiated<T>);

impl<T> From<Void> for Request<T> {
	fn from(v: Void) -> Self {
		unreachable(v)
	}
}

/// Substream upgrade protocol.
///
/// We attempt to parse an incoming protobuf encoded request (cf. `Request`)
/// which will be handled by the `BlockRequests` behaviour, i.e. the request
/// will become visible via `inject_node_event` which then dispatches to the
/// relevant callback to process the message and prepare a response.
#[derive(Debug, Clone)]
pub struct Protocol {
	/// The max. request length in bytes.
	max_request_len: usize,
	/// The protocol to use during upgrade negotiation.
	protocol: Bytes,
}

impl UpgradeInfo for Protocol {
    type Info = Bytes;
    type InfoIter = iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        iter::once(self.protocol.clone())
    }
}

impl<T: AsyncRead + AsyncWrite> InboundUpgrade<T> for Protocol {
    type Output = Request<T>;
    type Error = ReadOneError;
    type Future = ReadRespond<Negotiated<T>, (), fn(Negotiated<T>, Vec<u8>, ()) -> Result<Self::Output, Self::Error>>;

    fn upgrade_inbound(self, s: Negotiated<T>, _: Self::Info) -> Self::Future {
		read_respond(s, self.max_request_len, (), |s, buf, ()| {
			api::v1::BlockRequest::decode(buf)
				.map(move |r| Request(r, s))
				.map_err(|decode_error| {
					ReadOneError::Io(std::io::Error::new(std::io::ErrorKind::Other, decode_error))
				})
		})
	}
}

