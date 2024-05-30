#![no_main]

use sha2::{Sha384, Digest};
use alloy_primitives::FixedBytes;
use bls_signatures::{PublicKey, Signature, verify_messages, Serialize};
use alloy_sol_types::{sol, SolValue};
use risc0_zkvm::guest::env;
use serde::Deserialize;

sol! {
    struct PublicInputs {
        bytes merkle_root;
        bytes leaf;
        bytes bls_pubkey;
        bytes bls_signature;
    }
}

// Function to verify a Merkle proof
fn compute_merkle_root(leaf: &[u8; 48], merkle_path: &[[u8; 48]; 256]) -> [u8; 48] {
    let mut hash = Sha384::digest(leaf);
    
    for sibling in merkle_path {
        let mut combined = [0u8; 96];
        if hash.as_slice() < sibling {
            combined[..48].copy_from_slice(&hash);
            combined[48..].copy_from_slice(sibling);
        } else {
            combined[..48].copy_from_slice(sibling);
            combined[48..].copy_from_slice(&hash);
        }
        hash = Sha384::digest(&combined);
    }
    
    let mut result = [0u8; 48];
    result.copy_from_slice(&hash);
    result
}

#[derive(Debug, Deserialize)]
struct PrivateInputs {
    pub merkle_root: FixedBytes<48>,
    pub leaf: FixedBytes<48>,
    pub bls_pubkey: FixedBytes<48>, // BLS public key size will always be 48 bytes
    pub bls_signature: FixedBytes<96>, // BLS signature size will always be 96 bytes
    pub serialized_path: FixedBytes<12288> // 48 * 256 length
}

risc0_zkvm::guest::entry!(main);
fn main() {
    let start = env::cycle_count();
    let private_inputs = env::read::<PrivateInputs>();

    let merkle_path: &[[u8; 48]; 256] = unsafe {
        &*(private_inputs.serialized_path.as_slice().as_ptr() as *const [[u8; 48]; 256])
    };

    let diff = env::cycle_count();
    env::log(&format!("cycle count after reading private inputs: {}", diff - start));

    let computed_root = compute_merkle_root(&private_inputs.leaf, merkle_path);
    let diff = env::cycle_count();
    env::log(&format!("cycle count after merkle root: {}", diff - start));

    assert_eq!(computed_root, *private_inputs.merkle_root.as_slice());

    // Verify the BLS signature
    let pubkey = PublicKey::from_bytes(private_inputs.bls_pubkey.as_slice()).expect("Invalid public key");
    let signature = Signature::from_bytes(private_inputs.bls_signature.as_slice()).expect("Invalid signature");

    assert!(verify_messages(&signature, &[&computed_root], &[&pubkey]), "Invalid verification");

    let diff = env::cycle_count();
    env::log(&format!("cycle count after BLS signature verification: {}", diff - start));

    // Encode the public values of the program.
    let public_inputs = PublicInputs {
        merkle_root: computed_root.to_vec().into(),
        leaf: private_inputs.leaf.to_vec().into(),
        bls_pubkey: private_inputs.bls_pubkey.to_vec().into(),
        bls_signature: private_inputs.bls_signature.to_vec().into()
    };
    // Commit to the public values of the program.
    env::commit_slice(&public_inputs.abi_encode());

    let diff = env::cycle_count();
    env::log(&format!("total cycle count: {}", diff - start));
}
