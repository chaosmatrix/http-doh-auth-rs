#!/bin/bash

set -x
#cargo fmt && cargo build --target=x86_64-unknown-linux-musl
cargo fmt && cargo build --target=wasm32-unknown-unknown
set +x

