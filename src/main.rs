// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 c1ph3rC4t

//! sha256-viz
//!
//! A SHA2-256 visualizer
//!
//! # Usage
//!
//! `sha256-viz <FILE>`

use sha256_viz::{
    Message, Sha256,
    Sha256Stage::{BlockLoad, Compression, Finished, MessageExpansion, PreProc},
    result::Result,
};
use std::{fs::File, io::Read, path::PathBuf, thread::sleep, time::Duration};

const PRE_PROC_SLEEP_DUR: Duration = Duration::from_millis(500);
const BLOCK_LOAD_SLEEP_DUR: Duration = Duration::from_millis(500);
const MESSAGE_EXPANSION_SLEEP_DUR: Duration = Duration::from_millis(50);
const COMPRESSION_SLEEP_DUR: Duration = Duration::from_millis(50);
const GIB: u64 = 1024_u64.pow(3);
const MAX: u64 = GIB;

fn render(sha: &Sha256) {
    println!("\x1b[0;0H{sha}");
    match sha.stage.clone() {
        PreProc => {
            sleep(PRE_PROC_SLEEP_DUR);
        }
        BlockLoad => {
            sleep(BLOCK_LOAD_SLEEP_DUR);
        }
        MessageExpansion(_) => {
            sleep(MESSAGE_EXPANSION_SLEEP_DUR);
        }
        Compression {
            prev_working_vars: _,
            temp1: _,
            temp2: _,
        } => {
            sleep(COMPRESSION_SLEEP_DUR);
        }
        Finished => {}
    }
}

fn main() -> Result<()> {
    let path: PathBuf = std::env::args_os().nth(1).map_or_else(
        || {
            println!("usage: prog <file>");
            std::process::exit(0)
        },
        std::convert::Into::into,
    );

    let mut buf = Vec::new();
    File::open(path)?.take(MAX).read_to_end(&mut buf)?;

    let message: Message = buf.as_slice().try_into()?;

    let preload = message.0.len().min(4);
    let mut next_block = preload;
    let mut sha = Sha256::new(message.sub_message(0, preload));

    println!("\x1b[2J");

    while let Some(cur) = sha.next() {
        render(&cur);
        if sha.stage == BlockLoad && next_block < message.0.len() {
            sha.message = &sha.message + &message.sub_message(next_block, 1);
            next_block += 1;
        }
    }

    Ok(())
}
