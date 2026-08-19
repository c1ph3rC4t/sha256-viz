// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 c1ph3rC4t

//! Title
//!
//! Description

/// Base operators for SHA2-256
pub mod base_ops;
/// Constants specified by SHA2-256
pub mod consts;
/// An error type.
pub mod error;
/// A result type.
pub mod result;

use std::{
    num::Wrapping,
    ops::{Index, IndexMut},
};

#[allow(clippy::wildcard_imports)]
use base_ops::*;
pub use consts::{H_VALS, K_CONSTS};
use error::Error;
use result::Result;

use crate::Sha256Stage::{BlockLoad, Compression, Finished, MessageExpansion, PreProc};

/// A struct used to represent the message blocks in SHA2-256
#[derive(Clone, PartialEq, Eq)]
pub struct Message(pub Vec<[u32; 16]>);

impl Message {
    /// Writes up to `count` display styled blocks starting at index `start` of `self` to `f`.
    ///
    /// # Errors
    ///
    /// Will return a [`std::fmt::Error`] if [`write`] or [`std::fmt::Write::write_str`] fails.
    pub fn debug_range(
        &self,
        f: &mut impl std::fmt::Write,
        start: usize,
        count: usize,
    ) -> std::fmt::Result {
        let end = (start + count).min(self.0.len());
        let mut sep = "";
        for chunk in &self.0[start..end] {
            f.write_str(sep)?;
            for byte_chunk in chunk {
                write!(
                    f,
                    "{sep}{:08b} {:08b} {:08b} {:08b}",
                    byte_chunk >> 24,
                    (byte_chunk >> 16) & 0xFF,
                    (byte_chunk >> 8) & 0xFF,
                    byte_chunk & 0xFF
                )?;
                sep = "\n";
            }
        }
        Ok(())
    }

    /// Creates a sub-message from the blocks at index `start` to index `start + count`.
    #[must_use]
    pub fn sub_message(&self, start: usize, count: usize) -> Self {
        Self(self.0[start..start + count].to_vec())
    }
}

impl TryFrom<&[u8]> for Message {
    type Error = Error;

    fn try_from(message: &[u8]) -> Result<Self> {
        let mut result = vec![];
        let mut chunks = vec![];
        let mut message = message.to_vec();
        let message_len = message.len() as u64 * 8;
        message.push(0b1000_0000u8);
        message.extend(std::iter::repeat_n(
            0b0000_0000u8,
            ((Wrapping(56) - Wrapping(message.len())) % Wrapping(64)).0,
        ));

        for chunk_bytes in message.chunks(64) {
            let mut chunk = vec![];
            for part in chunk_bytes.chunks(4) {
                chunk.push(u32::from_be_bytes(part.try_into()?));
            }
            chunks.push(chunk);
        }
        let chunks_len = chunks.len();
        chunks[chunks_len - 1].push((message_len >> 32) as u32);
        chunks[chunks_len - 1].push((message_len << 32 >> 32) as u32);

        for chunk in chunks {
            result.push(chunk.try_into().map_err(|_| Error::ChunkingFailure)?);
        }

        Ok(Self(result))
    }
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sep = "";
        for chunk in &self.0 {
            f.write_str(sep)?;
            for byte_chunk in chunk {
                f.write_str(&format!(
                    "{sep}{:08b} {:08b} {:08b} {:08b}",
                    (byte_chunk >> 24),
                    (byte_chunk >> 16) & 0xFF,
                    (byte_chunk >> 8) & 0xFF,
                    byte_chunk & 0xFF
                ))?;
                sep = "\n";
            }
        }

        Ok(())
    }
}

impl Index<usize> for Message {
    type Output = [u32; 16];
    fn index(&self, i: usize) -> &[u32; 16] {
        &self.0[i]
    }
}

impl IndexMut<usize> for Message {
    fn index_mut(&mut self, i: usize) -> &mut [u32; 16] {
        &mut self.0[i]
    }
}

impl std::ops::Add for &Message {
    type Output = Message;
    fn add(self, rhs: Self) -> Message {
        Message([&self.0[..], &rhs.0[..]].concat())
    }
}

/// A struct used to represent the message schedule in SHA2-256
#[derive(Clone, PartialEq, Eq)]
pub struct MessageSchedule(pub [u32; 64]);

impl MessageSchedule {
    const fn new() -> Self {
        Self([0b0000_0000_0000_0000_0000_0000_0000_0000u32; 64])
    }
}

impl std::fmt::Debug for MessageSchedule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sep = "";
        for (idx, chunk) in self.0.iter().enumerate() {
            f.write_str(&format!("{sep}w{idx:02} {chunk:032b}"))?;
            sep = "\n";
        }

        Ok(())
    }
}

impl Index<usize> for MessageSchedule {
    type Output = u32;
    fn index(&self, i: usize) -> &u32 {
        &self.0[i]
    }
}

impl IndexMut<usize> for MessageSchedule {
    fn index_mut(&mut self, i: usize) -> &mut u32 {
        &mut self.0[i]
    }
}

/// A struct used to represent the 8 working variables in SHA2-256
#[derive(Clone, PartialEq, Eq)]
pub struct WorkingVars(pub [u32; 8]);

impl WorkingVars {
    const fn new() -> Self {
        Self(H_VALS)
    }
}

impl std::fmt::Debug for WorkingVars {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "a = {:032b}
b = {:032b}
c = {:032b}
d = {:032b}
e = {:032b}
f = {:032b}
g = {:032b}
h = {:032b}",
            self[0], self[1], self[2], self[3], self[4], self[5], self[6], self[7],
        ))?;

        Ok(())
    }
}

impl Index<usize> for WorkingVars {
    type Output = u32;
    fn index(&self, i: usize) -> &u32 {
        &self.0[i]
    }
}

impl IndexMut<usize> for WorkingVars {
    fn index_mut(&mut self, i: usize) -> &mut u32 {
        &mut self.0[i]
    }
}

/// A struct used to represent the 8 hash values in SHA2-256
#[derive(Clone, PartialEq, Eq)]
pub struct HashVals(pub [u32; 8]);

impl HashVals {
    const fn new() -> Self {
        Self(H_VALS)
    }
}

impl std::fmt::Debug for HashVals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for chunk in &self.0 {
            f.write_str(&format!("{chunk:08x}"))?;
        }

        Ok(())
    }
}

impl Index<usize> for HashVals {
    type Output = u32;
    fn index(&self, i: usize) -> &u32 {
        &self.0[i]
    }
}

impl IndexMut<usize> for HashVals {
    fn index_mut(&mut self, i: usize) -> &mut u32 {
        &mut self.0[i]
    }
}

/// A type used to represent the expression for computing the result of one round of message expansion in SHA2-256.
pub type MessageExpansionRoundComp = Add232<
    Add232<Add232<LabeledU32, SmallSigma0<LabeledU32>>, LabeledU32>,
    SmallSigma1<LabeledU32>,
>;
/// A type used to represent the expression for computing the temp1 during one round of compression in SHA2-256.
pub type Temp1Comp = Add232<
    Add232<
        Add232<Add232<LabeledU32, BigSigma1<LabeledU32>>, Ch<LabeledU32, LabeledU32, LabeledU32>>,
        LabeledU32,
    >,
    LabeledU32,
>;
/// A type used to represent the expression for computing the temp2 during one round of compression in SHA2-256.
pub type Temp2Comp = Add232<Maj<LabeledU32, LabeledU32, LabeledU32>, BigSigma0<LabeledU32>>;

/// A enum used to represent the current stage of SHA2-256 as well as [`MessageExpansionRoundComp`], [`Temp1Comp`] and [`Temp2Comp`] used for computing rounds of SHA2-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sha256Stage {
    /// Represents the preprocessing stage of SHA2-256.
    PreProc,
    /// Represents the block loading stage of SHA2-256.
    BlockLoad,
    /// Represents the message expansion stage of SHA2-256 and stores [`MessageExpansionRoundComp`] data used for round computation.
    MessageExpansion(Box<MessageExpansionRoundComp>),
    /// Represents the Compression stage of SHA2-256 and stores [`Temp1Comp`] and [`Temp2Comp`] data used for round computation.
    Compression {
        /// Stores previous working variables.
        prev_working_vars: WorkingVars,
        /// Stores [`Temp1Comp`] data used for round computation.
        temp1: Box<Temp1Comp>,
        /// Stores [`Temp2Comp`] data used for round computation.
        temp2: Box<Temp2Comp>,
    },
    /// Represents the finished state of SHA2-256.
    Finished,
}

/// A iterator that computes SHA2-256 and stores all internals publicly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sha256 {
    /// A enum used to represent the current stage of SHA2-256 as well as [`MessageExpansionRoundComp`], [`Temp1Comp`] and [`Temp2Comp`] used for computing rounds of SHA2-256.
    pub stage: Sha256Stage,
    /// Current block 0-n.
    pub block: usize,
    /// Current round 0-43 | 0-63.
    pub round: usize,
    /// All message blocks.
    pub message: Message,
    /// Current message schedule.
    pub schedule: MessageSchedule,
    /// Current working variables.
    pub working_vars: WorkingVars,
    /// Current hash values.
    pub hash_vals: HashVals,
}

impl Sha256 {
    /// Type for creating a new [`Sha256`].
    pub fn new<M>(message: M) -> Self
    where
        M: Into<Message>,
    {
        Self {
            stage: Sha256Stage::PreProc,
            block: 0,
            round: 0,
            message: message.into(),
            schedule: MessageSchedule::new(),
            working_vars: WorkingVars::new(),
            hash_vals: HashVals::new(),
        }
    }

    /// Type for creating a new [`Sha256`].
    ///
    /// # Errors
    ///
    /// Will return [`Error::TryFromSliceError`] upon failure to create a [`Message`] from `message`
    pub fn try_new<M>(message: M) -> Result<Self>
    where
        M: TryInto<Message>,
        Error: From<M::Error>,
    {
        Ok(Self {
            stage: Sha256Stage::PreProc,
            block: 0,
            round: 0,
            message: message.try_into()?,
            schedule: MessageSchedule::new(),
            working_vars: WorkingVars::new(),
            hash_vals: HashVals::new(),
        })
    }

    fn pre_proc(&mut self) {
        self.stage = BlockLoad;
    }

    fn load_block(&mut self, result: &mut Self) {
        self.schedule = MessageSchedule::new();
        for (idx, item) in self.message[self.block].iter().enumerate() {
            self.schedule[idx] = *item;
        }
        self.round = 0;
        result.stage = self.stage.clone();
        result.schedule = self.schedule.clone();
        self.stage = MessageExpansion(Box::new(Add232::new(
            Add232::new(
                Add232::new(
                    LabeledU32::from((format!("w{:02}", self.round), self.schedule[self.round])),
                    SmallSigma0::new(LabeledU32::from((
                        format!("w{:02}", self.round + 1),
                        self.schedule[self.round + 1],
                    ))),
                ),
                LabeledU32::from((
                    format!("w{:02}", self.round + 9),
                    self.schedule[self.round + 9],
                )),
            ),
            SmallSigma1::new(LabeledU32::from((
                format!("w{:02}", self.round + 14),
                self.schedule[self.round + 14],
            ))),
        )));
    }

    fn expand_message(&mut self, result: &mut Self) {
        if let MessageExpansion(comp) = &mut self.stage {
            self.schedule[self.round + 16] = comp.compute();
        }
        self.round += 1;
        result.stage = self.stage.clone();
        result.schedule = self.schedule.clone();
        if self.round <= 47 {
            self.stage = MessageExpansion(Box::new(Add232::new(
                Add232::new(
                    Add232::new(
                        LabeledU32::from((
                            format!("w{:02}", self.round),
                            self.schedule[self.round],
                        )),
                        SmallSigma0::new(LabeledU32::from((
                            format!("w{:02}", self.round + 1),
                            self.schedule[self.round + 1],
                        ))),
                    ),
                    LabeledU32::from((
                        format!("w{:02}", self.round + 9),
                        self.schedule[self.round + 9],
                    )),
                ),
                SmallSigma1::new(LabeledU32::from((
                    format!("w{:02}", self.round + 14),
                    self.schedule[self.round + 14],
                ))),
            )));
        } else {
            self.round = 0;
            result.working_vars = self.working_vars.clone();
            self.stage = Compression {
                prev_working_vars: self.working_vars.clone(),
                temp1: Box::new(Add232::new(
                    Add232::new(
                        Add232::new(
                            Add232::new(
                                LabeledU32::from(("h", self.working_vars[7])),
                                BigSigma1::new(LabeledU32::from(("e", self.working_vars[4]))),
                            ),
                            Ch::new(
                                LabeledU32::from(("e", self.working_vars[4])),
                                LabeledU32::from(("f", self.working_vars[5])),
                                LabeledU32::from(("g", self.working_vars[6])),
                            ),
                        ),
                        LabeledU32::from((format!("k{:02}", self.round), K_CONSTS[self.round])),
                    ),
                    LabeledU32::from((format!("w{:02}", self.round), self.schedule[self.round])),
                )),
                temp2: Box::new(Add232::new(
                    Maj::new(
                        LabeledU32::from(("a", self.working_vars[0])),
                        LabeledU32::from(("b", self.working_vars[1])),
                        LabeledU32::from(("c", self.working_vars[2])),
                    ),
                    BigSigma0::new(LabeledU32::from(("a", self.working_vars[0]))),
                )),
            }
        }
    }

    fn compress(&mut self, result: &mut Self) {
        if let Compression { temp1, temp2, .. } = &mut self.stage {
            let prev_working_vars = self.working_vars.clone();
            self.working_vars[7] = self.working_vars[6];
            self.working_vars[6] = self.working_vars[5];
            self.working_vars[5] = self.working_vars[4];
            self.working_vars[4] = self.working_vars[3].wrapping_add(temp1.compute());
            self.working_vars[3] = self.working_vars[2];
            self.working_vars[2] = self.working_vars[1];
            self.working_vars[1] = self.working_vars[0];
            self.working_vars[0] = temp1.result.wrapping_add(temp2.compute());
            self.round += 1;
            result.stage = self.stage.clone();
            result.working_vars = self.working_vars.clone();
            if self.round <= 63 {
                self.stage = Compression {
                    prev_working_vars,
                    temp1: Box::new(Add232::new(
                        Add232::new(
                            Add232::new(
                                Add232::new(
                                    LabeledU32::from(("h", self.working_vars[7])),
                                    BigSigma1::new(LabeledU32::from(("e", self.working_vars[4]))),
                                ),
                                Ch::new(
                                    LabeledU32::from(("e", self.working_vars[4])),
                                    LabeledU32::from(("f", self.working_vars[5])),
                                    LabeledU32::from(("g", self.working_vars[6])),
                                ),
                            ),
                            LabeledU32::from((format!("k{:02}", self.round), K_CONSTS[self.round])),
                        ),
                        LabeledU32::from((
                            format!("w{:02}", self.round),
                            self.schedule[self.round],
                        )),
                    )),
                    temp2: Box::new(Add232::new(
                        Maj::new(
                            LabeledU32::from(("a", self.working_vars[0])),
                            LabeledU32::from(("b", self.working_vars[1])),
                            LabeledU32::from(("c", self.working_vars[2])),
                        ),
                        BigSigma0::new(LabeledU32::from(("a", self.working_vars[0]))),
                    )),
                }
            } else {
                for (idx, item) in self.working_vars.0.iter().enumerate() {
                    self.hash_vals[idx] = self.hash_vals[idx].wrapping_add(*item);
                }
                result.hash_vals = self.hash_vals.clone();
                self.working_vars = WorkingVars(self.hash_vals.0);
                self.block += 1;
                if self.block < self.message.0.len() {
                    self.stage = BlockLoad;
                } else {
                    self.stage = Finished;
                }
            }
        }
    }
}

impl Iterator for Sha256 {
    type Item = Self;
    fn next(&mut self) -> Option<Self::Item> {
        let mut result = self.clone();

        match self.stage {
            PreProc => self.pre_proc(),
            BlockLoad => self.load_block(&mut result),
            MessageExpansion(_) => self.expand_message(&mut result),
            Compression { .. } => self.compress(&mut result),
            Finished => {
                if self.block <= self.message.0.len() {
                    self.block += 1;
                    result.block -= 1;
                } else {
                    return None;
                }
            }
        }

        Some(result)
    }
}

#[must_use]
fn join_blocks_horizontally(blocks: &[String]) -> String {
    let grids: Vec<Vec<String>> = blocks
        .iter()
        .map(|s| {
            let lines: Vec<&str> = s.lines().collect();
            let max_width = lines.iter().map(|l| l.len()).max().unwrap_or(0);
            lines.iter().map(|l| format!("{l:<max_width$}")).collect()
        })
        .collect();
    let max_height = grids.iter().map(std::vec::Vec::len).max().unwrap_or(0);
    (0..max_height)
        .map(|i| {
            grids
                .iter()
                .map(|g| {
                    g.get(i).map_or_else(
                        || " ".repeat(g.first().map_or(0, std::string::String::len)),
                        std::clone::Clone::clone,
                    )
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn display_pre_proc(sha: &Sha256, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let mut message = String::new();
    sha.message.debug_range(&mut message, sha.block, 3)?;
    write!(
        f,
        "\n  Currently processing block #{}\n{}",
        sha.block + 1,
        join_blocks_horizontally(&[
            String::from("  "),
            format!("{message}      \n                                         "),
            format!("{:#?}", sha.schedule),
        ])
    )
}

fn display_block_load(sha: &Sha256, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let mut message = String::new();
    sha.message.debug_range(&mut message, sha.block, 3)?;
    write!(
        f,
        "\n  Currently processing block #{}\n{}",
        sha.block + 1,
        join_blocks_horizontally(&[
            String::from("  "),
            format!("{message}\n                                   "),
            " <  > \n".repeat(16),
            format!("{:#?}      ", sha.schedule),
            format!("{:#?}", sha.hash_vals),
            " ".repeat(48)
        ])
    )
}

fn display_message_expansion(
    sha: &Sha256,
    comp: &MessageExpansionRoundComp,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    let mut message = String::new();
    sha.message.debug_range(&mut message, sha.block + 1, 3)?;
    write!(
        f,
        "\n  Currently processing block #{}\n{}",
        sha.block + 1,
        join_blocks_horizontally(&[
            String::from("  "),
            format!("{message}      \n                                         "),
            format!("{:#?}", sha.schedule),
            "\n".repeat(sha.round)
                + " <\n <"
                + "\n".repeat(8).as_str()
                + " <"
                + "\n".repeat(5).as_str()
                + " <\n\n <    ",
            format!(
                "{:032b}   < {}
{:-<44}
{:032b}   < r7
{:032b} ^ < r18
{:032b} ^ < s3
{:-<44}
{:032b}   > σ0({})

{:032b}   < {}
{:-<44}
{:032b}   < r17
{:032b} ^ < r19
{:032b} ^ < s10
{:-<44}
{:032b}   > σ1({})

{:032b}   < {}
{:032b} + < σ0({})
{:032b} + < {}
{:032b} + < σ1({})
{:-<44}
{:032b}   > w{}

{:#?}",
                comp.input.0.input.0.input.1.input.1,
                comp.input.0.input.0.input.1.input.0,
                "",
                comp.input.0.input.0.input.1.r7,
                comp.input.0.input.0.input.1.r18,
                comp.input.0.input.0.input.1.s3,
                "",
                comp.input.0.input.0.input.1.result,
                comp.input.0.input.0.input.1.input.0,
                comp.input.1.input.1,
                comp.input.1.input.0,
                "",
                comp.input.1.r17,
                comp.input.1.r19,
                comp.input.1.s10,
                "",
                comp.input.0.input.0.input.1.result,
                comp.input.1.input.0,
                comp.input.0.input.0.input.0.1,
                comp.input.0.input.0.input.0.0,
                comp.input.0.input.0.input.1.result,
                comp.input.0.input.0.input.1.input.0,
                comp.input.0.input.1.1,
                comp.input.0.input.1.0,
                comp.input.0.input.0.input.1.result,
                comp.input.1.input.0,
                "",
                comp.result,
                sha.round + 16,
                sha.hash_vals
            ),
            " ".repeat(48)
        ])
    )
}

#[allow(clippy::too_many_lines)]
fn display_compression(
    sha: &Sha256,
    prev_working_vars: &WorkingVars,
    temp1: &Temp1Comp,
    temp2: &Temp2Comp,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    let mut message = String::new();
    sha.message.debug_range(&mut message, sha.block + 1, 3)?;
    write!(
        f,
        "\n  Currently processing block #{}\n{}",
        sha.block + 1,
        join_blocks_horizontally(&[
            String::from("  "),
            format!("{message}      \n                                         "),
            format!("{:#?}", sha.schedule),
            "\n".repeat(sha.round) + " <    ",
            format!(
                "{:#?}

{:032b}   < e
{:-<42}
{:032b}   < r6
{:032b} ^ < r11
{:032b} ^ < r25
{:-<42}
{:032b}   > Σ1(e)

{:032b} < e
{:-<46}
{:032b} < f
{:032b} < g
{:-<46}
{:032b} > Ch(e, f, g)

{:032b}   < {}
{:032b} + < Σ1(e)
{:032b} + < Ch(e, f, g)
{:032b} + < {}
{:032b} + < {}
{:-<48}
{:032b}   > temp1

{:032b}   < a
{:-<42}
{:032b}   < r2
{:032b} ^ < r13
{:032b} ^ < r22
{:-<42}
{:032b}   > Σ0(a)

{:032b} < a
{:032b} < b
{:032b} < c
{:-<47}
{:032b} > Maj(a, b, c)

{:032b}   < Maj(a, b, c)
{:032b} + < Σ0(a)
{:-<49}
{:032b}   > Temp2

{}

{:#?}",
                prev_working_vars,
                temp1.input.0.input.0.input.0.input.1.input.1,
                "",
                temp1.input.0.input.0.input.0.input.1.r6,
                temp1.input.0.input.0.input.0.input.1.r11,
                temp1.input.0.input.0.input.0.input.1.r25,
                "",
                temp1.input.0.input.0.input.0.input.1.result,
                temp1.input.0.input.0.input.1.input.0.1,
                "",
                temp1.input.0.input.0.input.1.input.1.1,
                temp1.input.0.input.0.input.1.input.2.1,
                "",
                temp1.input.0.input.0.input.1.result,
                temp1.input.0.input.0.input.0.input.0.1,
                temp1.input.0.input.0.input.0.input.0.0,
                temp1.input.0.input.0.input.0.input.1.result,
                temp1.input.0.input.0.input.1.result,
                temp1.input.0.input.1.1,
                temp1.input.0.input.1.0,
                temp1.input.1.1,
                temp1.input.1.0,
                "",
                temp1.result,
                temp2.input.1.input.1,
                "",
                temp2.input.1.r2,
                temp2.input.1.r13,
                temp2.input.1.r22,
                "",
                temp2.input.1.result,
                temp2.input.0.input.0.1,
                temp2.input.0.input.1.1,
                temp2.input.0.input.2.1,
                "",
                temp2.input.0.result,
                temp2.input.0.result,
                temp2.input.1.result,
                "",
                temp2.result,
                join_blocks_horizontally(&[
                    format!("{:#?}", sha.working_vars),
                    String::from(
                        " < temp1 + temp2    \n < a\n < b\n < c\n < d + temp1\n < e\n < f\n < g"
                    )
                ]),
                sha.hash_vals
            ),
            "\n".repeat(sha.round) + "    > ",
            K_CONSTS
                .iter()
                .enumerate()
                .map(|(i, c)| format!("k{i:02} {c:032b}"))
                .collect::<Vec<_>>()
                .join("\n")
        ])
    )
}

fn display_finalized(sha: &Sha256, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
        f,
        "\n  Blocks processed: {}                       \n{}",
        sha.block + 1,
        join_blocks_horizontally(&[
            String::from("  "),
            format!("{:#?}      ", sha.schedule),
            format!("{:#?}", sha.hash_vals),
            " ".repeat(83)
        ])
    )
}

impl std::fmt::Display for Sha256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.stage {
            PreProc => display_pre_proc(self, f),
            BlockLoad => display_block_load(self, f),
            MessageExpansion(ref comp) => display_message_expansion(self, comp, f),
            Compression {
                ref prev_working_vars,
                ref temp1,
                ref temp2,
            } => display_compression(self, prev_working_vars, temp1, temp2, f),
            Finished => display_finalized(self, f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_validity() -> Result<()> {
        let sha = Sha256::try_new(
            ">Hey, just wondering if you got your photos printed?\n>Bogos binted?\n>What\n>👽"
                .as_bytes(),
        )?;
        assert_eq!(
            sha.last().ok_or(error::Error::GetError)?.hash_vals.0,
            [
                0xa335_e5da,
                0x0fc3_245d,
                0xc487_bf92,
                0x1d81_5fd9,
                0xc66_0e431,
                0x0540_5314,
                0x5a5_abd44,
                0x9541_185b
            ]
        );
        Ok(())
    }
}
