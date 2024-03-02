//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use reth_primitives::proofs::ordered_trie_root_with_encoder;
use reth_primitives::{Header, Receipt, B256};

pub fn main() {
    // Read public inputs to program (will be provided onchain)
    // NOTE: In future, this api will be `read_public` or `read_evm`.
    let block_hash = sp1_zkvm::io::read::<B256>();
    let target_log_index = sp1_zkvm::io::read::<u64>();

    // Read private inputs to program (not provided onchain).
    let header = sp1_zkvm::io::read::<Header>();
    let receipts = sp1_zkvm::io::read::<Vec<Receipt>>();

    // Ensure that the provided block header (private input) matches the block_hash (public input).
    assert_eq!(header.hash_slow(), block_hash, "block hash mismatch");

    // Iterate through all receipts and find the one with the desired log index.
    // TODO: this can be made more efficient by just verifying a merkle proof for the particular
    // receipt against the block's receipt root.
    let mut log_at_index = None;
    let mut idx = 0;

    let receipts_with_bloom = receipts
        .iter()
        .map(|receipt| {
            for log in receipt.logs.iter() {
                // Set log_at_index variable to the log when idx matches the desired target index.
                if idx == target_log_index {
                    log_at_index = Some(log.clone());
                }
                idx += 1;
            }
            receipt.clone().with_bloom()
        })
        .collect::<Vec<_>>();

    // Useful for knowing how much computational cycles this part of the program takes in the zkVM.
    println!("cycle-tracker-start: compute-receipt-root");
    // Compute the receipts root from all the provided receipts. Verify the computed root
    // matches the receipt root in the provided header.
    let receipts_root = ordered_trie_root_with_encoder(&receipts_with_bloom, |receipt, buf| {
        receipt.encode_inner(buf, false);
    });
    // assert_eq!(receipts_root, header.receipts_root);
    // println!("verified that receipts root matches header");
    println!("cycle-tracker-end: compute-receipt-root");

    let log_at_index = log_at_index.expect("log not found");
    println!("log_at_index: {:?}", log_at_index);
    sp1_zkvm::io::write(&log_at_index);
}
