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

use async_trait::async_trait;
use crate::Error;
use sc_network::{ObservedRole, PeerId};
use sp_runtime::traits::Block as BlockT;

/// Validates consensus messages.
pub trait Validator<B: BlockT>: Send + Sync {
	/// New peer is connected.
	fn new_peer(&self, _context: &mut dyn ValidatorContext<B>, _who: &PeerId, _role: ObservedRole) {
	}

	/// New connection is dropped.
	fn peer_disconnected(&self, _context: &mut dyn ValidatorContext<B>, _who: &PeerId) {
	}

	/// Validate consensus message.
	fn validate(
		&self,
		context: &mut dyn ValidatorContext<B>,
		sender: &PeerId,
		data: &[u8]
	) -> ValidationResult<B::Hash>;

	/// TODO
	fn is_message_expired(&self, _topic: &B::Hash, _data: &[u8]) -> bool {
		false
	}

	/// TODO
	fn is_message_allowed(&self, _who: &PeerId, _intent: MessageIntent, _topic: &B::Hash, _data: &[u8]) -> bool {
		true
	}
}

/// Validation context. Allows reacting to incoming messages by sending out further messages.
#[async_trait]
pub trait ValidatorContext<B: BlockT> {
	/// Broadcast all messages with given topic to peers that do not have it yet.
	async fn broadcast_topic(&mut self, topic: B::Hash, force: bool) -> Result<(), Error>;
	/// Broadcast a message to all peers that have not received it previously.
	async fn broadcast_message (
		&mut self,
		topic: B::Hash,
		message: Vec<u8>,
		force: bool
	) -> Result<(), Error>;
	/// Send addressed message to a peer.
	async fn send_message(&mut self, who: &PeerId, message: Vec<u8>) -> Result<(), Error>;
	/// Send all messages with given topic to a peer.
	async fn send_topic(&mut self, who: &PeerId, topic: B::Hash, force: bool) -> Result<(), Error>;
}

/// The reason for sending out the message.
#[derive(Eq, PartialEq, Copy, Clone)]
#[cfg_attr(test, derive(Debug))]
pub enum MessageIntent {
	/// Requested broadcast.
	Broadcast,
	/// Requested broadcast to all peers.
	ForcedBroadcast,
	/// Periodic rebroadcast of all messages to all peers.
	PeriodicRebroadcast,
}

/// Message validation result.
pub enum ValidationResult<H> {
	/// Message should be stored and propagated under given topic.
	ProcessAndKeep(H),
	/// Message should be processed, but not propagated.
	ProcessAndDiscard(H),
	/// Message should be ignored.
	Discard,
}

/// A gossip message validator that discards all messages.
pub struct DiscardAll;

impl<B: BlockT> Validator<B> for DiscardAll {
	fn validate(
		&self,
		_context: &mut dyn ValidatorContext<B>,
		_sender: &PeerId,
		_data: &[u8],
	) -> ValidationResult<B::Hash> {
		ValidationResult::Discard
	}

	fn is_message_expired(&self, _topic: &B::Hash, _data: &[u8]) -> bool {
		true
	}

	fn is_message_allowed(&self, _who: &PeerId, _intent: MessageIntent, _topic: &B::Hash, _data: &[u8]) -> bool {
		false
	}
}
