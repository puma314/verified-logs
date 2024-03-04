//! The host program for the `mpt-log-verifier` zkVM program.

use alloy_rlp::Encodable;
use reth_primitives::proofs::adjust_index_for_rlp;
use reth_primitives::trie::{HashBuilder, Nibbles};
use reth_primitives::{Bytes, BytesMut, Log, ReceiptWithBloom, B256};
use sp1_core::utils;
use sp1_core::{SP1Prover, SP1Stdin, SP1Verifier};
use std::str::FromStr;

mod util;

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

#[tokio::main]
async fn main() {
    // Generate a proof that a block with the provided block_hash has a particular log at the
    // provided log_index.
    let block_hash = "0x72a5d38fcb067e4432ec19be69fc15102d61008e0502558f6dacbe2dcdfd1f55";

    // To prove this computation, we need certain witnesses such as the full block header
    // and all the transaction receipts in block (these will be "private inputs" to our program).
    // The "block_hash" and "log_index" will be "public inputs" to our program and be provided onchain.
    // Our "program" will first verify that the witnessed block header matches the block hash.
    // Then, it will verify that the witnessed receipts match the receipt root in the block header.
    // This ensures that the provided block_receipts to the program are indeed the block_receipts
    // corresponding to the block_hash public input. Then, the program will return the log at
    // the provided log_index, which is also a public input to the program.
    let (block_header, block_receipts) = util::get_witness_inputs(block_hash).await;

    let receipt_index = 0usize;
    let inner_log_index = 0usize;

    let receipts_with_bloom = block_receipts
        .into_iter()
        .map(ReceiptWithBloom::from)
        .collect::<Vec<ReceiptWithBloom>>();
    let mut receipts_trie_hasher =
        receipts_trie_builder(receipts_with_bloom.as_ref(), receipt_index);
    let receipts_root = receipts_trie_hasher.root();
    let receipt_proof = receipts_trie_hasher
        .take_proofs()
        .values()
        .cloned()
        .collect::<Vec<Bytes>>();
    let ReceiptWithBloom { receipt, .. } = receipts_with_bloom
        .get(receipt_index)
        .expect("receipt not found");

    println!("Sanity checking receipts root");
    assert_eq!(block_header.receipts_root, receipts_root);
    println!("Receipts root is good.");

    // Setup logger for SP1.
    utils::setup_logger();
    let mut stdin = SP1Stdin::new();

    // Write public and private inputs for the program's consumption.
    stdin.write(&B256::from_str(block_hash).unwrap()); // Write the block hash as a public input.
    stdin.write(&receipt_index); // Write the target receipt index within the MPT as a public input.
    stdin.write(&receipt_proof); // Write the receipts root MPT proof as a public input.
    stdin.write(&inner_log_index); // Write the target log index as a public input.
    stdin.write(
        &receipt
            .logs
            .get(inner_log_index)
            .expect("Log not found")
            .data,
    ); // Write the expected log data as a public input.
    stdin.write(&block_header); // Write the full block header as a private input (witness data).

    // Prove the execution of the program.
    let mut proof = SP1Prover::prove(ELF, stdin).expect("proving failed");

    // Read the log at the provided index as an output (public).
    let log_at_index = proof.stdout.read::<Log>();
    println!(
        "log at relative index {inner_log_index} in receipt index {receipt_index}: {:?}",
        log_at_index
    );

    // Verify proof.
    SP1Verifier::verify(ELF, &proof).expect("verification failed");

    // To verify this proof onchain, your Solidity code might look something like this:
    // function xchainLog(bytes memory proof, bytes32 blockhash, uint64 logIndex, Log log_at_index) public {
    //     bytes memory input = abi.encode(blockHash, logIndex);
    //     bytes memory output = abi.encode(log_at_index);
    //     ISP1Verifier.verifyProof(proof, input, output); // will revert if proof doesn't verify
    //     // TODO: use the log_at_index for rest of logic...
    // }

    // Save proof.
    proof
        .save("proof-with-io.json")
        .expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!")
}

/// Build a [HashBuilder] for the receipts MPT, given a slice of [ReceiptWithBloom] and a key index to retain a MPT
/// proof for.
pub fn receipts_trie_builder(items: &[ReceiptWithBloom], key_index: usize) -> HashBuilder {
    let mut index_buffer = BytesMut::new();
    let mut value_buffer = BytesMut::new();
    let items_len = items.len();

    // Assign proof retention for the receipt index passed.
    let key = receipts_mpt_key(key_index);
    let mut hb = HashBuilder::default().with_proof_retainer(vec![Nibbles::unpack(key)]);

    for i in 0..items_len {
        let index = adjust_index_for_rlp(i, items_len);

        index_buffer.clear();
        index.encode(&mut index_buffer);

        value_buffer.clear();
        items[index].encode_inner(&mut value_buffer, false);

        hb.add_leaf(Nibbles::unpack(&index_buffer), &value_buffer);
    }

    hb
}

/// Helper to compute the key for a receipt in the receipts MPT within an Ethereum block header.
fn receipts_mpt_key(receipt_index: usize) -> Bytes {
    let mut index_buffer = BytesMut::new();
    receipt_index.encode(&mut index_buffer);
    index_buffer.freeze().into()
}
