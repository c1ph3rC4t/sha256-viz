// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 c1ph3rC4t

/// An error type
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failure while getting and item from a list, string or iterator.
    #[error("Failed to get.")]
    GetError,

    /// Error for when chunking something fails.
    #[error("Failed to chunk.")]
    ChunkingFailure,

    /// Error while getting system time.
    ///
    /// Derived from [`std::time::SystemTimeError`].
    #[error("System time error: {0}")]
    SystemTimeError(#[from] std::time::SystemTimeError),

    /// Error when using try from for a slice.
    ///
    /// Derived from [`std::array::TryFromSliceError`].
    #[error("System time error: {0}")]
    TryFromSliceError(#[from] std::array::TryFromSliceError),

    /// Error in I/O.
    ///
    /// Derived from [`std::io::Error`].
    #[error("I/O error: {0}")]
    IOError(#[from] std::io::Error),
}
