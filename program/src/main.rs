//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use reth_primitives::proofs::ordered_trie_root_with_encoder;
use reth_primitives::{Header, Receipt, B256};

pub fn main() {
    // Public inputs from onchain
    // f(block_hash, target_log_index) -> log
    let block_hash = sp1_zkvm::io::read::<B256>();
    let target_log_index = sp1_zkvm::io::read::<u64>();
    println!("target_log_index: {:?}", target_log_index);
    // These are "private inputs" that are used as "witness data", but not present onchain.
    let header = sp1_zkvm::io::read::<Header>();
    println!("got header");
    let receipts = sp1_zkvm::io::read::<Vec<Receipt>>();
    println!("got all inputs");

    let mut log_at_index = None;
    let mut log_index = 0;

    // Iterate through all receipts and find the one with the desired log index.
    // TODO: this can be made more efficient by just verifying a merkle proof for the particular
    // receipt against the block's receipt root.
    let receipts_with_bloom = receipts
        .iter()
        .map(|receipt| {
            for log in receipt.logs.iter() {
                if log_index == target_log_index {
                    log_at_index = Some(log.clone());
                }
                log_index += 1;
            }
            receipt.clone().with_bloom()
        })
        .collect::<Vec<_>>();

    println!("cycle-tracker-start: compute-receipt-root");
    let receipts_root = ordered_trie_root_with_encoder(&receipts_with_bloom, |receipt, buf| {
        receipt.encode_inner(buf, false);
    });
    println!("cycle-tracker-end: compute-receipt-root");

    // assert_eq!(receipts_root, header.receipts_root);
    // println!("verified that receipts root matches header");
    assert_eq!(header.hash_slow(), block_hash, "block hash mismatch");
    let log_at_index = log_at_index.expect("log not found");
    println!("log_at_index: {:?}", log_at_index);
    sp1_zkvm::io::write(&log_at_index);
}
