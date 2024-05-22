#![no_main]

use sha2::{Sha384, Digest};
use alloy_primitives::FixedBytes;
use bls_signatures::{PublicKey, Signature, verify_messages, Serialize};

use alloy_sol_types::{sol, SolValue};

sol! {
    struct PublicInputs {
        bytes merkle_root;
        bytes leaf;
        bytes bls_pubkey;
        bytes bls_signature;
    }
}

use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

// Function to verify a Merkle proof
fn compute_merkle_root(leaf: FixedBytes<48>, merkle_path: Vec<FixedBytes<48>>) -> [u8; 48] {
    let mut hash = Sha384::digest(leaf.as_slice());
    
    for sibling in merkle_path {
        let sibling_slice = sibling.as_slice();
        let mut combined = Vec::with_capacity(96);
        if hash.as_slice() < sibling_slice {
            combined.extend_from_slice(&hash);
            combined.extend_from_slice(&sibling_slice);
        } else {
            combined.extend_from_slice(&sibling_slice);
            combined.extend_from_slice(&hash);
        }
        hash = Sha384::digest(&combined);
    }
    
    let mut result = [0u8; 48];
    result.copy_from_slice(hash.as_slice());
    result
}

fn main() {

    let merkle_root: FixedBytes<48> = env::read();
    let leaf: FixedBytes<48> = env::read();
    let bls_pubkey: FixedBytes<48> = env::read(); // BLS public key size will always be 48 bytes
    let bls_signature: FixedBytes<96> = env::read(); // BLS public key size will always be 96 bytes
    let merkle_path: Vec<FixedBytes<48>> = env::read();

    println!("merkle_root: {:?}", merkle_root);
    println!("leaf: {:?}", leaf);
    println!("bls_pubkey: {:?}", bls_pubkey);
    println!("bls_signature: {:?}", bls_signature);
    println!("merkle_path: {:?}", merkle_path);

    let computed_root: [u8; 48] = compute_merkle_root(leaf, merkle_path);
    
    println!("computed_root: {:?}", computed_root);

    assert_eq!(computed_root, merkle_root.as_slice());

    // Verify the BLS signature
    let pubkey = PublicKey::from_bytes(&bls_pubkey.as_slice()).expect("Invalid public key");
    let signature = Signature::from_bytes(&bls_signature.as_slice()).expect("Invalid signature");

    println!("PublicKey: {:?}", bls_pubkey);
    println!("Signature: {:?}", bls_signature);
    
    assert!(verify_messages(&signature, &[computed_root.as_slice()], &[pubkey]), "Invalid verification");

    // Encocde the public values of the program.
    let public_inputs: PublicInputs = PublicInputs {
        merkle_root: computed_root.to_vec().into(),
        leaf: leaf.to_vec().into(),
        bls_pubkey: bls_pubkey.to_vec().into(),
        bls_signature: bls_signature.to_vec().into()
    };
    // Commit to the public values of the program.
    env::commit_slice(&(public_inputs.abi_encode()));

}