# sha256-viz

[![Crates.io](https://img.shields.io/crates/v/sha256-viz.svg?style=for-the-badge&logo=rust)](https://crates.io/crates/sha256-viz)
[![CI](https://img.shields.io/github/actions/workflow/status/c1ph3rC4t/sha256-viz/ci.yml?style=for-the-badge&logo=github)](https://github.com/c1ph3rC4t/sha256-viz/actions)
[![License](https://img.shields.io/crates/l/sha256-viz.svg?style=for-the-badge)](LICENSE)

**A visualizer for SHA2-256.**

![Demo](assets/demo.gif)

## Overview

A library and CLI for visualizing SHA2-256. Library gives you a iterator and a very good way to eat your entire RAM using `.collect::<Vec<_>>`.

## Usage

From the command line `sha256-viz <FILE>`. Try it out on `file.ext`.
As for the library just use it like a normal iterator, just maybe dont `.collect::<Vec<_>>` on larger inputs unless you wanna eat up 64GB RAM in seconds.

## Example

```rs
fn main() -> sha256_viz::result::Result<()> {
    let sha = sha256_viz::Sha256::new(
        "Shadow Wizard Money Gang
We love casting spells
This song is sponsored by The Shadow Government
Legalize nuclear bombs"
        .as_bytes(),
    )?;

    println!("\x1b[2J");

    for sha in sha {
        println!("\x1b[0;0H{sha}");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    Ok(())
}
```

## Contributing

Open an issue or PR on [GitHub](https://github.com/c1ph3rC4t/sha256-viz) if you wanna.

## License

[MPL-2.0](LICENSE)
