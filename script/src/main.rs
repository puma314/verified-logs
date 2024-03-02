//! A simple script to generate and verify the proof of a given program.

use alloy_providers::provider::HttpProvider;
use alloy_providers::provider::TempProvider;
use alloy_rpc_types::Header as AlloyHeader;
use alloy_transport_http::Http;
use reth_primitives::{Header as RethHeader, TxType, U64};
use reth_primitives::{Log, Receipt};
use sp1_core::utils;
use sp1_core::{SP1Prover, SP1Stdin, SP1Verifier};
use url::Url;

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

#[tokio::main]
async fn main() {
    let block_number = 19344302;
    let rpc_url = "https://docs-demo.quiknode.pro/";
    let log_index = 0u64;

    // Generate proof.
    let mut stdin = SP1Stdin::new();
    // Initialize the provider.
    let http = Http::new(Url::parse(&rpc_url).expect("invalid rpc url"));
    let provider: HttpProvider = HttpProvider::new(http);

    println!("Fetching block");
    // Get the block.
    let block = provider
        .get_block_by_number((block_number).into(), false)
        .await
        .expect("getting block failed")
        .expect("block not found");
    let header = block.header;
    println!("Got block, fetching block receipts");
    let transaction_receipts = provider
        .get_block_receipts((block_number).into())
        .await
        .expect("getting block receipts failed")
        .expect("block receipts not found");
    println!("Got transaction receipts");
    let receipts = transaction_receipts
        .iter()
        .map(|receipt| {
            let mut reth_logs = vec![];
            for log in receipt.logs.iter() {
                reth_logs.push(Log {
                    address: log.address,
                    topics: log.topics.clone(),
                    data: log.data.clone(),
                })
            }
            let success = receipt.status_code.unwrap().eq(&U64::ZERO);
            let tx_type: u8 = receipt.transaction_type.try_into().unwrap();
            Receipt {
                tx_type: TxType::try_from(tx_type).unwrap(),
                success,
                cumulative_gas_used: receipt.cumulative_gas_used.try_into().unwrap(),
                logs: reth_logs,
            }
        })
        .collect::<Vec<_>>();
    println!("Got receipts, generating proof");

    let reth_header = header.clone().into_reth();
    let block_hash = reth_header.hash_slow();
    assert_eq!(block_hash, header.hash.unwrap(), "block hash mismatch");

    utils::setup_logger();

    stdin.write(&block_hash);
    stdin.write(&log_index);
    stdin.write(&reth_header);
    stdin.write(&receipts);

    let mut proof = SP1Prover::prove(ELF, stdin).expect("proving failed");

    // Read output.
    let log_at_index = proof.stdout.read::<Log>();
    println!("log at index: {:?}", log_at_index);

    // Verify proof.
    SP1Verifier::verify(ELF, &proof).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-io.json")
        .expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!")
}

pub trait IntoReth<T> {
    fn into_reth(self) -> T;
}

impl IntoReth<RethHeader> for AlloyHeader {
    fn into_reth(self) -> RethHeader {
        RethHeader {
            parent_hash: self.parent_hash.0.into(),
            ommers_hash: self.uncles_hash.0.into(),
            beneficiary: self.miner.0.into(),
            state_root: self.state_root.0.into(),
            transactions_root: self.transactions_root.0.into(),
            receipts_root: self.receipts_root.0.into(),
            withdrawals_root: self.withdrawals_root,
            logs_bloom: self.logs_bloom.0.into(),
            difficulty: self.difficulty,
            number: self.number.unwrap().try_into().unwrap(),
            gas_limit: self.gas_limit.try_into().unwrap(),
            gas_used: self.gas_used.try_into().unwrap(),
            timestamp: self.timestamp.try_into().unwrap(),
            extra_data: self.extra_data.0.into(),
            mix_hash: self.mix_hash.unwrap(),
            nonce: u64::from_be_bytes(self.nonce.unwrap().0),
            base_fee_per_gas: Some(self.base_fee_per_gas.unwrap().try_into().unwrap()),
            blob_gas_used: self.blob_gas_used.map(|x| x.try_into().unwrap()),
            excess_blob_gas: self.excess_blob_gas.map(|x| x.try_into().unwrap()),
            parent_beacon_block_root: self.parent_beacon_block_root,
        }
    }
}
