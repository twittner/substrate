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

use crate::{Error, Network, Validator};
use crate::state_machine::{ConsensusGossip, TopicNotification, PERIODIC_MAINTENANCE_INTERVAL};

use sc_network::{Event, ReputationChange};

use futures::{prelude::*, channel::mpsc::{self, channel, Sender, Receiver}, stream::BoxStream};
use futures_timer::Delay;
use libp2p::PeerId;
use log::trace;
use sp_runtime::{traits::Block as BlockT, ConsensusEngineId};
use std::{
	borrow::Cow,
	collections::{HashMap, hash_map::Entry},
	sync::Arc
};

#[derive(Debug)]
enum Command<B: BlockT> {
	Report(PeerId, ReputationChange),
	Register(B::Hash, Vec<u8>),
	Broadcast(B::Hash, bool),
	MessagesFor(B::Hash, Sender<TopicNotification>),
	SendTopic(PeerId, B::Hash, bool),
	GossipMessage(B::Hash, Vec<u8>, bool),
	SendMessage(Vec<PeerId>, Vec<u8>),
	Announce(B::Hash, Vec<u8>)
}

#[derive(Debug, Clone)]
pub struct GossipEngineControl<B: BlockT>(mpsc::Sender<Command<B>>);

impl<B: BlockT> GossipEngineControl<B> {
	pub async fn report(&mut self, who: PeerId, reputation: ReputationChange) -> Result<(), Error> {
		self.0.send(Command::Report(who, reputation)).await.map_err(|_| Error::EngineGone)
	}

	/// Registers a message without propagating it to any peers. The message
	/// becomes available to new peers or when the service is asked to gossip
	/// the message's topic. No validation is performed on the message, if the
	/// message is already expired it should be dropped on the next garbage
	/// collection.
	pub async fn register_gossip_message(
		&mut self,
		topic: B::Hash,
		message: Vec<u8>,
	) -> Result<(), Error> {
		self.0.send(Command::Register(topic, message)).await.map_err(|_| Error::EngineGone)
	}

	/// Broadcast all messages with given topic.
	pub async fn broadcast_topic(&mut self, topic: B::Hash, force: bool) -> Result<(), Error> {
		self.0.send(Command::Broadcast(topic, force)).await.map_err(|_| Error::EngineGone)
	}

	/// Get data of valid, incoming messages for a topic (but might have expired meanwhile).
	pub async fn messages_for(&mut self, topic: B::Hash) -> Result<Receiver<TopicNotification>, Error> {
		let (tx, rx) = channel(16);
		self.0.send(Command::MessagesFor(topic, tx)).await.map_err(|_| Error::EngineGone)?;
		Ok(rx)
	}

	/// Send all messages with given topic to a peer.
	pub async fn send_topic(
		&mut self,
		who: PeerId,
		topic: B::Hash,
		force: bool
	) -> Result<(), Error> {
		self.0.send(Command::SendTopic(who, topic, force)).await.map_err(|_| Error::EngineGone)
	}

	/// Multicast a message to all peers.
	pub async fn gossip_message(
		&mut self,
		topic: B::Hash,
		message: Vec<u8>,
		force: bool,
	) -> Result<(), Error> {
		self.0.send(Command::GossipMessage(topic, message, force)).await
			.map_err(|_| Error::EngineGone)
	}

	/// Send addressed message to the given peers. The message is not kept or multicast
	/// later on.
	pub async fn send_message(
		&mut self,
		who: Vec<sc_network::PeerId>,
		data: Vec<u8>
	) -> Result<(), Error> {
		self.0.send(Command::SendMessage(who, data)).await.map_err(|_| Error::EngineGone)
	}

	/// Notify everyone we're connected to that we have the given block.
	///
	/// Note: this method isn't strictly related to gossiping and should eventually be moved
	/// somewhere else.
	pub async fn announce(&mut self, block: B::Hash, associated_data: Vec<u8>) -> Result<(), Error> {
		self.0.send(Command::Announce(block, associated_data)).await.map_err(|_| Error::EngineGone)
	}
}

/// Wraps around an implementation of the `Network` type and provides gossiping capabilities on
/// top of it.
pub struct GossipEngine<B: BlockT> {
	engine_id: ConsensusEngineId,
	state_machine: ConsensusGossip<B>,
	network: Box<dyn Network<B> + Send>,
	periodic_maintenance_interval: stream::Fuse<BoxStream<'static, ()>>,
	network_event_stream: stream::Fuse<BoxStream<'static, Event>>,
	command_stream: mpsc::Receiver<Command<B>>,
	/// Outgoing events to the consumer.
	message_sinks: HashMap<B::Hash, Vec<Sender<TopicNotification>>>,
}

impl<B: BlockT> Unpin for GossipEngine<B> {}

impl<B: BlockT> GossipEngine<B> {
	/// Create a new instance.
	pub async fn new<N: Network<B> + Send + Clone + 'static>(
		mut network: N,
		engine_id: ConsensusEngineId,
		protocol_name: impl Into<Cow<'static, [u8]>>,
		validator: Arc<dyn Validator<B>>,
	) -> Result<(Self, GossipEngineControl<B>), Error> where B: 'static {
		// We grab the event stream before registering the notifications protocol,
		// otherwise we might miss events.
		let network_event_stream = network.event_stream().await?.fuse();
		network.register_notifications_protocol(engine_id, protocol_name.into()).await?;

		let periodic_maintenance_interval =
			stream::unfold(Delay::new(PERIODIC_MAINTENANCE_INTERVAL), |mut delay| async {
				(&mut delay).await;
				delay.reset(PERIODIC_MAINTENANCE_INTERVAL);
				Some(((), delay))
			})
			.boxed()
			.fuse();

		let (tx, rx) = mpsc::channel(1);
		let control = GossipEngineControl(tx);
		let engine = GossipEngine {
			engine_id,
			state_machine: ConsensusGossip::new(validator, engine_id),
			network: Box::new(network),
			periodic_maintenance_interval,
			network_event_stream,
			command_stream: rx,
			message_sinks: HashMap::new(),
		};

		Ok((engine, control))
	}

	pub async fn exec(mut self) -> Result<(), Error> {
		'outer: loop {
			futures::select! {
				command = self.command_stream.next() => if let Some(command) = command {
					match command {
						Command::Report(who, reputation) =>
							self.network.report_peer(who, reputation),
						Command::Register(topic, message) =>
							self.state_machine.register_message(topic, message),
						Command::Broadcast(topic, force) =>
							self.state_machine.broadcast_topic(&mut *self.network, topic, force).await?,
						Command::MessagesFor(topic, mut tx) => {
							for notification in self.state_machine.messages_for(topic) {
								if tx.send(notification).await.is_err() {
									continue 'outer
								}
							}
							self.message_sinks.entry(topic).or_default().push(tx)
						}
						Command::SendTopic(who, topic, force) =>
							self.state_machine.send_topic(&mut *self.network, &who, topic, force).await?,
						Command::GossipMessage(topic, message, force) =>
							self.state_machine.multicast(&mut *self.network, topic, message, force).await?,
						Command::Announce(block, associated_data) =>
							self.network.announce(block, associated_data).await?,
						Command::SendMessage(who, data) => for who in &who {
							self.state_machine.send_message(&mut *self.network, who, data.clone()).await?
						}
					}
				} else {
					return Ok(())
				},
				event = self.network_event_stream.next() => if let Some(event) = event {
					match event {
						Event::NotificationStreamOpened { remote, engine_id: msg_engine_id, role } => {
							if msg_engine_id != self.engine_id {
								continue;
							}
							self.state_machine.new_peer(&mut *self.network, remote, role);
						}
						Event::NotificationStreamClosed { remote, engine_id: msg_engine_id } => {
							if msg_engine_id != self.engine_id {
								continue;
							}
							self.state_machine.peer_disconnected(&mut *self.network, remote);
						},
						Event::NotificationsReceived { remote, messages } => {
							let messages = messages.into_iter().filter_map(|(engine, data)| {
								if engine == self.engine_id {
									Some(data.to_vec())
								} else {
									None
								}
							}).collect();

							let to_forward = self.state_machine.on_incoming(
								&mut *self.network,
								remote,
								messages,
							);

							for (topic, notification) in to_forward {
								if let Entry::Occupied(mut entry) = self.message_sinks.entry(topic) {
									trace!(
										target: "gossip",
										"Pushing consensus message to sinks for {}.", topic,
									);
									let sinks = entry.get_mut();
									sinks.retain(|sink| !sink.is_closed());
									for sink in sinks {
										if let Err(e) = sink.send(notification.clone()).await {
											trace!(
												target: "gossip",
												"Error broadcasting message notification: {:?}", e,
											);
										}
									}
									if entry.get().is_empty() {
										entry.remove_entry();
									}
								}
							}
						},
						Event::Dht(_) => {}
					}
				} else {
					return Ok(())
				},

				_ = self.periodic_maintenance_interval.next() => {
					self.state_machine.tick(&mut *self.network).await?;
					self.message_sinks.retain(|_, sinks| {
						sinks.retain(|sink| !sink.is_closed());
						!sinks.is_empty()
					});
				}
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use async_std::task::spawn;
	use async_trait::async_trait;
	use crate::{ValidationResult, ValidatorContext};
	use futures::{channel::mpsc::{unbounded, UnboundedSender}, executor::block_on_stream};
	use sc_network::ObservedRole;
	use sp_runtime::{testing::H256, traits::{Block as BlockT}};
	use std::sync::{Arc, Mutex};
	use substrate_test_runtime_client::runtime::Block;
	use super::*;

	#[derive(Clone, Default)]
	struct TestNetwork {
		inner: Arc<Mutex<TestNetworkInner>>,
	}

	#[derive(Clone, Default)]
	struct TestNetworkInner {
		event_senders: Vec<UnboundedSender<Event>>,
	}

	#[async_trait]
	impl<B: BlockT> Network<B> for TestNetwork {
		async fn event_stream(&mut self) -> Result<BoxStream<'static, Event>, Error> {
			let (tx, rx) = unbounded();
			self.inner.lock().unwrap().event_senders.push(tx);
			Ok(rx.boxed())
		}

		fn report_peer(&mut self, _: PeerId, _: ReputationChange) {
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

	/// Regression test for the case where the `GossipEngine.network_event_stream` closes. One
	/// should not ignore a `Poll::Ready(None)` as `poll_next_unpin` will panic on subsequent calls.
	///
	/// See https://github.com/paritytech/substrate/issues/5000 for details.
	#[test]
	fn returns_when_network_event_stream_closes() {
		let network = TestNetwork::default();
		let (gossip_engine, _gossip_ctrl) =
			futures::executor::block_on(GossipEngine::<Block>::new(
				network.clone(),
				[1, 2, 3, 4],
				"my_protocol".as_bytes(),
				Arc::new(AllowAll{}),
			)).unwrap();

		// Drop network event stream sender side.
		drop(network.inner.lock().unwrap().event_senders.pop());

		futures::executor::block_on(gossip_engine.exec()).unwrap();
	}

	#[test]
	fn keeps_multiple_subscribers_per_topic_updated_with_both_old_and_new_messages() {
		async_std::task::block_on(async {
			let topic = H256::default();
			let engine_id = [1, 2, 3, 4];
			let remote_peer = PeerId::random();
			let network = TestNetwork::default();

			let (gossip_engine, mut gossip_ctrl) =
				GossipEngine::<Block>::new(
					network.clone(),
					engine_id.clone(),
					"my_protocol".as_bytes(),
					Arc::new(AllowAll{}),
				).await.unwrap();

			spawn(gossip_engine.exec());

			let mut event_sender = network.inner.lock()
				.unwrap()
				.event_senders
				.pop()
				.unwrap();

			// Register the remote peer.
			event_sender.start_send(
				Event::NotificationStreamOpened {
					remote: remote_peer.clone(),
					engine_id: engine_id.clone(),
					role: ObservedRole::Authority,
				}
			).unwrap();

			let messages = vec![vec![1], vec![2]];
			let events = messages.iter().cloned().map(|m| {
				Event::NotificationsReceived {
					remote: remote_peer.clone(),
					messages: vec![(engine_id, m.into())]
				}
			}).collect::<Vec<_>>();

			// Send first event before subscribing.
			event_sender.start_send(events[0].clone()).unwrap();
			let mut subscribers = vec![];
			for _ in 0..2 {
				subscribers.push(gossip_ctrl.messages_for(topic).await.unwrap());
			}

			// Send second event after subscribing.
			event_sender.start_send(events[1].clone()).unwrap();

			let mut subscribers = subscribers.into_iter()
				.map(|s| block_on_stream(s))
				.collect::<Vec<_>>();

			// Expect each subscriber to receive both events.
			for message in messages {
				for subscriber in subscribers.iter_mut() {
					assert_eq!(
						subscriber.next(),
						Some(TopicNotification {
							message: message.clone(),
							sender: Some(remote_peer.clone()),
						}),
					);
				}
			}
		})
	}
}
