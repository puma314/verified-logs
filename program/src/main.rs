//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_rlp::{Decodable, BytesMut, Encodable};
use reth_primitives::{Header, B256, Bytes, ReceiptWithBloom};

mod mpt;

pub fn main() {
    // Read public inputs to program (will be provided onchain)
    // NOTE: In future, this api will be `read_public` or `read_evm`.
    let block_hash = sp1_zkvm::io::read::<B256>();
    let receipt_index = sp1_zkvm::io::read::<usize>();
    let receipt_proof = sp1_zkvm::io::read::<Vec<Bytes>>();
    let inner_log_index = sp1_zkvm::io::read::<usize>();
    let expected_log_data = sp1_zkvm::io::read::<Bytes>();

    // Read private inputs to program (not provided onchain).
    let header = sp1_zkvm::io::read::<Header>();

    // Ensure that the provided block header (private input) matches the block_hash (public input).
    assert_eq!(header.hash_slow(), block_hash, "block hash mismatch");

    let receipt_rlp = mpt::get(
        &receipts_mpt_key(receipt_index),
        &receipt_proof,
        header.receipts_root,
    )
    .expect("Failed to fetch receipt from receipts MPT");
    let ReceiptWithBloom { receipt, .. } = ReceiptWithBloom::decode(&mut &receipt_rlp[..])
        .expect("Failed to decode receipt from RLP");

    // Ensure that the log at the provided index within the receipt matches the expected log data.
    let log_at_index = receipt
        .logs
        .get(inner_log_index as usize)
        .expect("log not found");
    assert_eq!(log_at_index.data, expected_log_data, "log data mismatch");

    // Write the log at the provided index to the output.
    sp1_zkvm::io::write(&log_at_index);
}

/// Helper to compute the key for a receipt in the receipts MPT within an Ethereum block header.
fn receipts_mpt_key(receipt_index: usize) -> Bytes {
    let mut index_buffer = BytesMut::new();
    receipt_index.encode(&mut index_buffer);
    index_buffer.freeze().into()
}
