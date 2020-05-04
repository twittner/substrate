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
//! Substrate network possible errors.

use futures::channel::mpsc::SendError;
use libp2p::{PeerId, Multiaddr};
use thiserror::Error;

/// Result type alias for the network.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type for the network.
#[derive(Debug, Error)]
pub enum Error {
	/// Io error
	#[error("i/o error: {0}")]
	Io(#[from] std::io::Error),

	/// Client error
	#[error("client error: {0}")]
	Client(#[from] sp_blockchain::Error),
	/// The same bootnode (based on address) is registered with two different peer ids.
	#[error("The same bootnode (`{address}`) is registered with two different peer ids: `{first_id}` and `{second_id}`")]
	DuplicateBootnode {
		/// The address of the bootnode.
		address: Multiaddr,
		/// The first peer id that was found for the bootnode.
		first_id: PeerId,
		/// The second peer id that was found for the bootnode.
		second_id: PeerId,
	},
	/// Prometheus metrics error.
	#[error("prometheus error: {0}")]
	Prometheus(#[from] prometheus_endpoint::PrometheusError),
}

/// TODO
#[derive(Debug, Error)]
pub enum ServiceError {
	/// The network worker no longer exists.
	#[error("network worker is gone")]
	NetworkWorkerGone,
	/// Failed to parse a multi address.
	#[error("parse failure: {0}")]
	ParseError(#[from] crate::config::ParseErr)
}

impl From<SendError> for ServiceError {
	fn from(_: SendError) -> Self {
		ServiceError::NetworkWorkerGone
	}
}
