#!/usr/bin/env -S just --justfile

alias r := run

alias b := build

alias c := check
alias t := check
alias test := check

# Run the project using a specific profile
[group('run')]
run PROFILE="dev":
    cargo run {{ if PROFILE =~ "^(release|rel|r)$" { "--release" } else if PROFILE == "dev" { "" } else { "--profile " + PROFILE } }}

# Build using a specific profile
[group('build')]
build PROFILE="dev":
    cargo build {{ if PROFILE =~ "^(release|rel|r)$" { "--release" } else if PROFILE == "dev" { "" } else { "--profile " + PROFILE } }}

# Run check script
[group('test')]
check ARGS="":
    ./check.sh {{ ARGS }}
