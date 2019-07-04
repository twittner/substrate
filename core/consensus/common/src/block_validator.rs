// Copyright 2019 Parity Technologies (UK) Ltd.
// This file is part of Substrate.
//
// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Substrate.  If not, see <http://www.gnu.org/licenses/>.

use runtime_primitives::traits::Block;
use std::error::Error;

/// Result of `BlockAnnounceValidator::validate`.
///
/// In addition to success or failure, a validation may be inconclusive.
#[derive(Debug, PartialEq, Eq)]
pub enum Validation {
	/// Valid block announcement.
	Success,
	/// Invalid block announcement.
	Failure,
	/// At this point, the validation is inconclusive.
	Unknown
}

/// Type which checks incoming block announcements.
pub trait BlockAnnounceValidator<B: Block> {
	/// Validate the announced header and its associated data.
	fn validate(&mut self, header: &B::Header, data: &[u8]) -> Result<Validation, Box<dyn Error + Send + Sync>>;
}

