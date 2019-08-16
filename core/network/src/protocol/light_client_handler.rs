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
	io,
	iter,
	sync::Arc,
	time::Duration
};
use tokio_io::{AsyncRead, AsyncWrite};
use void::{Void, unreachable};

// Type alias for convenience.
pub type Error = Box<dyn std::error::Error + 'static>;

/// Configuration options for `LightClientHandler`.
#[derive(Debug, Clone)]
pub struct Config {
	max_request_len: usize,
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
			max_request_len: 1024 * 1024,
			inactivity_timeout: Duration::from_secs(5)
		}
	}

	/// Limit the max. length of incoming request bytes.
	pub fn set_max_request_len(&mut self, v: usize) -> &mut Self {
		self.max_request_len = v;
		self
	}

	/// Limit the max. duration the substream may remain inactive before closing it.
	pub fn set_inactivity_timeout(&mut self, v: Duration) -> &mut Self {
		self.inactivity_timeout = v;
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
	/// Pending futures, sending back the responses.
	outgoing: VecDeque<WriteOne<Negotiated<T>, Vec<u8>>>
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
			outgoing: VecDeque::new()
		}
	}
}

impl<T, B> NetworkBehaviour for LightClientHandler<T, B>
where
	T: AsyncRead + AsyncWrite,
	B: Block
{
	type ProtocolsHandler = OneShotHandler<T, Protocol, DeniedUpgrade, Request<T>>;
	type OutEvent = Void;

	fn new_handler(&mut self) -> Self::ProtocolsHandler {
		let p = Protocol {
			max_request_len: self.config.max_request_len
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
	}

	fn poll(&mut self, _: &mut impl PollParameters) -> Async<NetworkBehaviourAction<DeniedUpgrade, Void>> {
		Async::NotReady
	}
}


// TODO (after https://github.com/libp2p/rust-libp2p/pull/1226): #[derive(Debug)]
pub struct Request<T>(api::v1::light::Request, Negotiated<T>);

impl<T> From<Void> for Request<T> {
	fn from(v: Void) -> Self {
		unreachable(v)
	}
}

/// Substream upgrade protocol.
#[derive(Debug, Clone)]
pub struct Protocol {
	/// The max. request length in bytes.
	max_request_len: usize
}

impl UpgradeInfo for Protocol {
    type Info = &'static [u8];
    type InfoIter = iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        iter::once(b"/polkadot/light/1")
    }
}

impl<T: AsyncRead> InboundUpgrade<T> for Protocol {
    type Output = Request<T>;
    type Error = ReadOneError;
    type Future = ReadRespond<Negotiated<T>, (), fn(Negotiated<T>, Vec<u8>, ()) -> Result<Self::Output, Self::Error>>;

    fn upgrade_inbound(self, s: Negotiated<T>, _: Self::Info) -> Self::Future {
		read_respond(s, self.max_request_len, (), |s, buf, ()| {
			api::v1::light::Request::decode(buf)
				.map(move |r| Request(r, s))
				.map_err(|decode_error| {
					ReadOneError::Io(std::io::Error::new(std::io::ErrorKind::Other, decode_error))
				})
		})
	}
}

