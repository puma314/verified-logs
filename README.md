# Verified Logs with SP1

## Overview

This repository contains a program that can be run in a zkVM to prove the contents of a log at a given log index in a block. In particular, the program takes in a `block_hash` and a `log_index` as public inputs, and returns the log at the provided index as a public output (an illustrative function signature is below).  

```
fn log_at_index(block_hash: B256, log_index: u64) -> Log
```

The program is written in Rust and in the `program` directory at `program/src/main.rs`. It is compiled to RISC-V bytecode (contained in `program/elf/riscv32im-succinct-zkvm-elf`) and can be run in the SP1 zkVM. To run the program in a zkVM and generate a proof, use the `script` directory. The `script` directory contains logic to get necesary private inputs to the program (such as the full block header and block receipts) and uses `SP1` to generate and verify the proof.

## Generate Proof

To generate a proof, run the following command in the `script` directory:

```bash
cd script;
RUST_LOG=info cargo run --release
```

Proof generation should take 2-3 minutes on a Mac M1. 

You can change the `block_hash` and `log_index` in the `script/src/main.rs` file to generate a proof for a different block and log index.