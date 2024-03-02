//! A simple script to generate and verify the proof of a given program.

mod util;
use reth_primitives::{Log, B256};
use sp1_core::utils;
use sp1_core::{SP1Prover, SP1Stdin, SP1Verifier};
use std::str::FromStr;

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

#[tokio::main]
async fn main() {
    // Generate a proof that a block with the provided block_hash has a particular log at the
    // provided log_index.
    let block_hash = "0x72a5d38fcb067e4432ec19be69fc15102d61008e0502558f6dacbe2dcdfd1f55";
    let log_index = 0u64;

    // To prove this computation, we need certain witnesses such as the full block header
    // and all the transaction receipts in block (these will be "private inputs" to our program).
    // The "block_hash" and "log_index" will be "public inputs" to our program and be provided onchain.
    // Our "program" will first verify that the witnessed block header matches the block hash.
    // Then, it will verify that the witnessed receipts match the receipt root in the block header.
    // This ensures that the provided block_receipts to the program are indeed the block_receipts
    // corresponding to the block_hash public input. Then, the program will return the log at
    // the provided log_index, which is also a public input to the program.
    let (block_header, block_receipts) = util::get_witness_inputs(block_hash).await;

    utils::setup_logger(); // Setup logger for SP1.
    let mut stdin = SP1Stdin::new();

    stdin.write(&B256::from_str(block_hash).unwrap()); // Write the block hash as a public input.
    stdin.write(&log_index); // Write the target log index as a public input.
    stdin.write(&block_header); // Write the full block header as a private input (witness data).
    stdin.write(&block_receipts); // Write all block receipts as a private input (witness data).

    let mut proof = SP1Prover::prove(ELF, stdin).expect("proving failed");

    // Read the log at the provided index as an output (public).
    let log_at_index = proof.stdout.read::<Log>();
    println!("log at index: {:?}", log_at_index);

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
