// This file is part of Substrate.

// Copyright (C) 2017-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::{Error, Network, MessageIntent, Validator, ValidatorContext, ValidationResult};

use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::iter;
use std::time;
use log::{error, trace};
use lru::LruCache;
use libp2p::PeerId;
use sp_runtime::traits::{Block as BlockT, Hash, HashFor};
use sp_runtime::ConsensusEngineId;
use sc_network::ObservedRole;
use wasm_timer::Instant;

// FIXME: Add additional spam/DoS attack protection: https://github.com/paritytech/substrate/issues/1115
const KNOWN_MESSAGES_CACHE_SIZE: usize = 4096;

const REBROADCAST_INTERVAL: time::Duration = time::Duration::from_secs(30);

pub(crate) const PERIODIC_MAINTENANCE_INTERVAL: time::Duration = time::Duration::from_millis(1100);

mod rep {
	use sc_network::ReputationChange as Rep;
	/// Reputation change when a peer sends us a gossip message that we didn't know about.
	pub const GOSSIP_SUCCESS: Rep = Rep::new(1 << 4, "Successfull gossip");
	/// Reputation change when a peer sends us a gossip message that we already knew about.
	pub const DUPLICATE_GOSSIP: Rep = Rep::new(-(1 << 2), "Duplicate gossip");
}

struct PeerConsensus<H> {
	known_messages: HashSet<H>,
}

/// Topic stream message with sender.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopicNotification {
	/// Message data.
	pub message: Vec<u8>,
	/// Sender if available.
	pub sender: Option<PeerId>,
}

struct MessageEntry<B: BlockT> {
	message_hash: B::Hash,
	topic: B::Hash,
	message: Vec<u8>,
	sender: Option<PeerId>,
}

/// Local implementation of `ValidatorContext`.
struct NetworkContext<'g, 'p, B: BlockT> {
	gossip: &'g mut ConsensusGossip<B>,
	network: &'p mut (dyn Network<B> + Send),
}

#[async_trait]
impl<'g, 'p, B: BlockT> ValidatorContext<B> for NetworkContext<'g, 'p, B> {
	/// Broadcast all messages with given topic to peers that do not have it yet.
	async fn broadcast_topic(&mut self, topic: B::Hash, force: bool) -> Result<(), Error> {
		self.gossip.broadcast_topic(self.network, topic, force).await
	}

	/// Broadcast a message to all peers that have not received it previously.
	async fn broadcast_message (
		&mut self,
		topic: B::Hash,
		message: Vec<u8>,
		force: bool
	) -> Result<(), Error> {
		self.gossip.multicast(
			self.network,
			topic,
			message,
			force,
		).await
	}

	/// Send addressed message to a peer.
	async fn send_message(&mut self, who: &PeerId, message: Vec<u8>) -> Result<(), Error> {
		self.network.write_notification(who.clone(), self.gossip.engine_id, message).await
	}

	/// Send all messages with given topic to a peer.
	async fn send_topic(&mut self, who: &PeerId, topic: B::Hash, force: bool) -> Result<(), Error> {
		self.gossip.send_topic(self.network, who, topic, force).await
	}
}

async fn propagate<'a, B: BlockT, I>(
	network: &mut (dyn Network<B> + Send),
	engine_id: ConsensusEngineId,
	messages: I,
	intent: MessageIntent,
	peers: &mut HashMap<PeerId, PeerConsensus<B::Hash>>,
	validator: &Arc<dyn Validator<B>>,
) -> Result<(), Error>
	// (msg_hash, topic, message)
	where I: Clone + IntoIterator<Item=(&'a B::Hash, &'a B::Hash, &'a Vec<u8>)>,
{
	for (id, ref mut peer) in peers.iter_mut() {
		for (message_hash, topic, message) in messages.clone() {
			let intent = match intent {
				MessageIntent::Broadcast { .. } =>
					if peer.known_messages.contains(&message_hash) {
						continue;
					} else {
						MessageIntent::Broadcast
					},
				MessageIntent::PeriodicRebroadcast =>
					if peer.known_messages.contains(&message_hash) {
						MessageIntent::PeriodicRebroadcast
					} else {
						// peer doesn't know message, so the logic should treat it as an
						// initial broadcast.
						MessageIntent::Broadcast
					},
				other => other,
			};

			if !validator.is_message_allowed(id, intent, &topic, &message) {
				continue;
			}

			peer.known_messages.insert(message_hash.clone());

			trace!(target: "gossip", "Propagating to {}: {:?}", id, message);
			network.write_notification(id.clone(), engine_id, message.clone()).await?
		}
	}
	Ok(())
}

/// Consensus network protocol handler. Manages statements and candidate requests.
pub struct ConsensusGossip<B: BlockT> {
	peers: HashMap<PeerId, PeerConsensus<B::Hash>>,
	messages: Vec<MessageEntry<B>>,
	known_messages: LruCache<B::Hash, ()>,
	engine_id: ConsensusEngineId,
	validator: Arc<dyn Validator<B>>,
	next_broadcast: Instant,
}

impl<B: BlockT> ConsensusGossip<B> {
	/// Create a new instance using the given validator.
	pub fn new(validator: Arc<dyn Validator<B>>, engine_id: ConsensusEngineId) -> Self {
		ConsensusGossip {
			peers: HashMap::new(),
			messages: Default::default(),
			known_messages: LruCache::new(KNOWN_MESSAGES_CACHE_SIZE),
			engine_id,
			validator,
			next_broadcast: Instant::now() + REBROADCAST_INTERVAL,
		}
	}

	/// Handle new connected peer.
	pub fn new_peer(&mut self, network: &mut (dyn Network<B> + Send), who: PeerId, role: ObservedRole) {
		// light nodes are not valid targets for consensus gossip messages
		if role.is_light() {
			return;
		}

		trace!(target:"gossip", "Registering {:?} {}", role, who);
		self.peers.insert(who.clone(), PeerConsensus {
			known_messages: HashSet::new(),
		});

		let validator = self.validator.clone();
		let mut context = NetworkContext { gossip: self, network };
		validator.new_peer(&mut context, &who, role.clone());
	}

	fn register_message_hashed(
		&mut self,
		message_hash: B::Hash,
		topic: B::Hash,
		message: Vec<u8>,
		sender: Option<PeerId>,
	) {
		if self.known_messages.put(message_hash.clone(), ()).is_none() {
			self.messages.push(MessageEntry {
				message_hash,
				topic,
				message,
				sender,
			});
		}
	}

	/// Registers a message without propagating it to any peers. The message
	/// becomes available to new peers or when the service is asked to gossip
	/// the message's topic. No validation is performed on the message, if the
	/// message is already expired it should be dropped on the next garbage
	/// collection.
	pub fn register_message(
		&mut self,
		topic: B::Hash,
		message: Vec<u8>,
	) {
		let message_hash = HashFor::<B>::hash(&message[..]);
		self.register_message_hashed(message_hash, topic, message, None);
	}

	/// Call when a peer has been disconnected to stop tracking gossip status.
	pub fn peer_disconnected(&mut self, network: &mut (dyn Network<B> + Send), who: PeerId) {
		let validator = self.validator.clone();
		let mut context = NetworkContext { gossip: self, network };
		validator.peer_disconnected(&mut context, &who);
		self.peers.remove(&who);
	}

	/// Perform periodic maintenance
	pub async fn tick(&mut self, network: &mut (dyn Network<B> + Send)) -> Result<(), Error> {
		self.collect_garbage();
		if Instant::now() >= self.next_broadcast {
			self.rebroadcast(network).await?;
			self.next_broadcast = Instant::now() + REBROADCAST_INTERVAL;
		}
		Ok(())
	}

	/// Rebroadcast all messages to all peers.
	async fn rebroadcast(&mut self, network: &mut (dyn Network<B> + Send)) -> Result<(), Error> {
		let messages = self.messages.iter()
			.map(|entry| (&entry.message_hash, &entry.topic, &entry.message))
			.collect::<Vec<_>>();
		propagate (
			network,
			self.engine_id,
			messages,
			MessageIntent::PeriodicRebroadcast,
			&mut self.peers,
			&self.validator
		).await
	}

	/// Broadcast all messages with given topic.
	pub async fn broadcast_topic (
		&mut self,
		network: &mut (dyn Network<B> + Send),
		topic: B::Hash,
		force: bool
	) -> Result<(), Error> {
		let messages = self.messages.iter()
			.filter_map(|entry|
				if entry.topic == topic {
					Some((&entry.message_hash, &entry.topic, &entry.message))
				} else { None }
			).collect::<Vec<_>>();
		let intent = if force { MessageIntent::ForcedBroadcast } else { MessageIntent::Broadcast };
		propagate(network, self.engine_id, messages, intent, &mut self.peers, &self.validator).await
	}

	/// Prune old or no longer relevant consensus messages. Provide a predicate
	/// for pruning, which returns `false` when the items with a given topic should be pruned.
	pub fn collect_garbage(&mut self) {
		let known_messages = &mut self.known_messages;
		let before = self.messages.len();

		let validator = &self.validator;
		self.messages.retain(|entry| {
			!validator.is_message_expired(&entry.topic, &entry.message)
		});

		trace!(target: "gossip", "Cleaned up {} stale messages, {} left ({} known)",
			before - self.messages.len(),
			self.messages.len(),
			known_messages.len(),
		);

		for (_, ref mut peer) in self.peers.iter_mut() {
			peer.known_messages.retain(|h| known_messages.contains(h));
		}
	}

	/// Get valid messages received in the past for a topic (might have expired meanwhile).
	pub fn messages_for(&mut self, topic: B::Hash) -> impl Iterator<Item = TopicNotification> + '_ {
		self.messages.iter()
			.filter(move |e| e.topic == topic)
			.map(|entry| TopicNotification {
				message: entry.message.clone(),
				sender: entry.sender.clone(),
			})
	}

	/// Register incoming messages and return the ones that are new and valid (according to a gossip
	/// validator) and should thus be forwarded to the upper layers.
	pub fn on_incoming(
		&mut self,
		network: &mut (dyn Network<B> + Send),
		who: PeerId,
		messages: Vec<Vec<u8>>,
	) -> Vec<(B::Hash, TopicNotification)> {
		let mut to_forward = vec![];

		if !messages.is_empty() {
			trace!(target: "gossip", "Received {} messages from peer {}", messages.len(), who);
		}

		for message in messages {
			let message_hash = HashFor::<B>::hash(&message[..]);

			if self.known_messages.contains(&message_hash) {
				trace!(target:"gossip", "Ignored already known message from {}", who);
				network.report_peer(who.clone(), rep::DUPLICATE_GOSSIP);
				continue;
			}

			// validate the message
			let validation = {
				let validator = self.validator.clone();
				let mut context = NetworkContext { gossip: self, network };
				validator.validate(&mut context, &who, &message)
			};

			let (topic, keep) = match validation {
				ValidationResult::ProcessAndKeep(topic) => (topic, true),
				ValidationResult::ProcessAndDiscard(topic) => (topic, false),
				ValidationResult::Discard => {
					trace!(target:"gossip", "Discard message from peer {}", who);
					continue;
				},
			};

			let peer = match self.peers.get_mut(&who) {
				Some(peer) => peer,
				None => {
					error!(target:"gossip", "Got message from unregistered peer {}", who);
					continue;
				}
			};

			network.report_peer(who.clone(), rep::GOSSIP_SUCCESS);
			peer.known_messages.insert(message_hash);
			to_forward.push((topic, TopicNotification {
				message: message.clone(),
				sender: Some(who.clone())
			}));

			if keep {
				self.register_message_hashed(
					message_hash,
					topic,
					message,
					Some(who.clone()),
				);
			}
		}

		to_forward
	}

	/// Send all messages with given topic to a peer.
	pub async fn send_topic(
		&mut self,
		network: &mut (dyn Network<B> + Send),
		who: &PeerId,
		topic: B::Hash,
		force: bool
	) -> Result<(), Error> {
		if let Some(ref mut peer) = self.peers.get_mut(who) {
			for entry in self.messages.iter().filter(|m| m.topic == topic) {
				let intent = if force {
					MessageIntent::ForcedBroadcast
				} else {
					MessageIntent::Broadcast
				};

				if !force && peer.known_messages.contains(&entry.message_hash) {
					continue;
				}

				if !self.validator.is_message_allowed(who, intent, &entry.topic, &entry.message) {
					continue;
				}

				peer.known_messages.insert(entry.message_hash.clone());

				trace!(target: "gossip", "Sending topic message to {}: {:?}", who, entry.message);
				network.write_notification(who.clone(), self.engine_id, entry.message.clone()).await?
			}
		}

		Ok(())
	}

	/// Multicast a message to all peers.
	pub async fn multicast(
		&mut self,
		network: &mut (dyn Network<B> + Send),
		topic: B::Hash,
		message: Vec<u8>,
		force: bool,
	) -> Result<(), Error> {
		let message_hash = HashFor::<B>::hash(&message);
		self.register_message_hashed(message_hash, topic, message.clone(), None);
		let intent = if force { MessageIntent::ForcedBroadcast } else { MessageIntent::Broadcast };
		propagate (
			network,
			self.engine_id,
			iter::once((&message_hash, &topic, &message)),
			intent,
			&mut self.peers,
			&self.validator
		).await
	}

	/// Send addressed message to a peer. The message is not kept or multicast
	/// later on.
	pub async fn send_message(
		&mut self,
		network: &mut (dyn Network<B> + Send),
		who: &PeerId,
		message: Vec<u8>,
	) -> Result<(), Error> {
		let peer = match self.peers.get_mut(who) {
			None => return Ok(()),
			Some(peer) => peer,
		};

		let message_hash = HashFor::<B>::hash(&message);

		trace!(target: "gossip", "Sending direct to {}: {:?}", who, message);

		peer.known_messages.insert(message_hash);
		network.write_notification(who.clone(), self.engine_id, message).await?;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use async_trait::async_trait;
	use futures::stream::BoxStream;
	use sc_network::{Event, ReputationChange};
	use sp_runtime::testing::{H256, Block as RawBlock, ExtrinsicWrapper};
	use std::{borrow::Cow, sync::{Arc, Mutex}};
	use super::*;

	type Block = RawBlock<ExtrinsicWrapper<u64>>;

	macro_rules! push_msg {
		($consensus:expr, $topic:expr, $hash: expr, $m:expr) => {
			if $consensus.known_messages.put($hash, ()).is_none() {
				$consensus.messages.push(MessageEntry {
					message_hash: $hash,
					topic: $topic,
					message: $m,
					sender: None,
				});
			}
		}
	}

	struct AllowAll;

	impl Validator<Block> for AllowAll {
		fn validate(
			&self,
			_context: &mut dyn ValidatorContext<Block>,
			_sender: &PeerId,
			_data: &[u8],
		) -> ValidationResult<H256> {
			ValidationResult::ProcessAndKeep(H256::default())
		}
	}

	struct DiscardAll;

	impl Validator<Block> for DiscardAll{
		fn validate(
			&self,
			_context: &mut dyn ValidatorContext<Block>,
			_sender: &PeerId,
			_data: &[u8],
		) -> ValidationResult<H256> {
			ValidationResult::Discard
		}
	}

	#[derive(Clone, Default)]
	struct NoOpNetwork {
		inner: Arc<Mutex<NoOpNetworkInner>>,
	}

	#[derive(Clone, Default)]
	struct NoOpNetworkInner {
		peer_reports: Vec<(PeerId, ReputationChange)>,
	}

	#[async_trait]
	impl<B: BlockT> Network<B> for NoOpNetwork {
		async fn event_stream(&mut self) -> Result<BoxStream<'static, Event>, Error> {
			unimplemented!();
		}

		fn report_peer(&mut self, peer_id: PeerId, reputation_change: ReputationChange) {
			self.inner.lock().unwrap().peer_reports.push((peer_id, reputation_change));
		}

		async fn disconnect_peer(&mut self, _: PeerId) -> Result<(), Error> {
			unimplemented!();
		}

		async fn write_notification(&mut self, _: PeerId, _: ConsensusEngineId, _: Vec<u8>) -> Result<(), Error> {
			unimplemented!();
		}

		async fn register_notifications_protocol(&mut self, _: ConsensusEngineId, _: Cow<'static, [u8]>) -> Result<(), Error> {
			Ok(())
		}

		async fn announce(&mut self, _: B::Hash, _: Vec<u8>) -> Result<(), Error> {
			unimplemented!();
		}
	}

	#[test]
	fn collects_garbage() {
		struct AllowOne;

		impl Validator<Block> for AllowOne {
			fn validate(
				&self,
				_context: &mut dyn ValidatorContext<Block>,
				_sender: &PeerId,
				data: &[u8],
			) -> ValidationResult<H256> {
				if data[0] == 1 {
					ValidationResult::ProcessAndKeep(H256::default())
				} else {
					ValidationResult::Discard
				}
			}

			fn is_message_expired(&self, _topic: &H256, data: &[u8]) -> bool {
				data[0] != 1
			}
		}

		let prev_hash = H256::random();
		let best_hash = H256::random();
		let mut consensus = ConsensusGossip::<Block>::new(Arc::new(AllowAll), [0, 0, 0, 0]);
		let m1_hash = H256::random();
		let m2_hash = H256::random();
		let m1 = vec![1, 2, 3];
		let m2 = vec![4, 5, 6];

		push_msg!(consensus, prev_hash, m1_hash, m1);
		push_msg!(consensus, best_hash, m2_hash, m2);
		consensus.known_messages.put(m1_hash, ());
		consensus.known_messages.put(m2_hash, ());

		consensus.collect_garbage();
		assert_eq!(consensus.messages.len(), 2);
		assert_eq!(consensus.known_messages.len(), 2);

		consensus.validator = Arc::new(AllowOne);

		// m2 is expired
		consensus.collect_garbage();
		assert_eq!(consensus.messages.len(), 1);
		// known messages are only pruned based on size.
		assert_eq!(consensus.known_messages.len(), 2);
		assert!(consensus.known_messages.contains(&m2_hash));
	}

	#[test]
	fn message_stream_include_those_sent_before_asking() {
		let mut consensus = ConsensusGossip::<Block>::new(Arc::new(AllowAll), [0, 0, 0, 0]);

		// Register message.
		let message = vec![4, 5, 6];
		let topic = HashFor::<Block>::hash(&[1,2,3]);
		consensus.register_message(topic, message.clone());

		assert_eq!(
			consensus.messages_for(topic).next(),
			Some(TopicNotification { message: message, sender: None }),
		);
	}

	#[test]
	fn can_keep_multiple_messages_per_topic() {
		let mut consensus = ConsensusGossip::<Block>::new(Arc::new(AllowAll), [0, 0, 0, 0]);

		let topic = [1; 32].into();
		let msg_a = vec![1, 2, 3];
		let msg_b = vec![4, 5, 6];

		consensus.register_message(topic, msg_a);
		consensus.register_message(topic, msg_b);

		assert_eq!(consensus.messages.len(), 2);
	}

	#[test]
	fn peer_is_removed_on_disconnect() {
		let mut consensus = ConsensusGossip::<Block>::new(Arc::new(AllowAll), [0, 0, 0, 0]);

		let mut network = NoOpNetwork::default();

		let peer_id = PeerId::random();
		consensus.new_peer(&mut network, peer_id.clone(), ObservedRole::Full);
		assert!(consensus.peers.contains_key(&peer_id));

		consensus.peer_disconnected(&mut network, peer_id.clone());
		assert!(!consensus.peers.contains_key(&peer_id));
	}

	#[test]
	fn on_incoming_ignores_discarded_messages() {
		let to_forward = ConsensusGossip::<Block>::new(
			Arc::new(DiscardAll),
			[0, 0, 0, 0],
		).on_incoming(
			&mut NoOpNetwork::default(),
			PeerId::random(),
			vec![vec![1, 2, 3]],
		);

		assert!(
			to_forward.is_empty(),
			"Expected `on_incoming` to ignore discarded message but got {:?}", to_forward,
		);
	}

	#[test]
	fn on_incoming_ignores_unregistered_peer() {
		let mut network = NoOpNetwork::default();
		let remote = PeerId::random();

		let to_forward = ConsensusGossip::<Block>::new(
			Arc::new(AllowAll),
			[0, 0, 0, 0],
		).on_incoming(
			&mut network,
			// Unregistered peer.
			remote.clone(),
			vec![vec![1, 2, 3]],
		);

		assert!(
			to_forward.is_empty(),
			"Expected `on_incoming` to ignore message from unregistered peer but got {:?}",
			to_forward,
		);
	}
}
