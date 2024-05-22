include!(concat!(env!("OUT_DIR"), "/methods.rs"));

#[cfg(test)]
mod tests {
    use alloy_primitives::FixedBytes;
    //use bls_signatures::{PublicKey, PrivateKey, Signature, Serialize};

    use risc0_zkvm::{default_executor, ExecutorEnv};
    use std::str::FromStr;
    
    use sha2::{Sha384, Digest};

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

    #[test]
    fn test_verify() {

        // Precomputed example inputs
        let leaf_data = b"example leaf data";
        let leaf_hash = Sha384::digest(leaf_data);
        let leaf = FixedBytes::<48>::from_slice(leaf_hash.as_slice());

        let mut merkle_path: Vec<FixedBytes<48>> = vec![];
        let mut sibling_data = [0u8; 48];
        for i in 0..256 {
            sibling_data[0] = i as u8;  // Just a simple example for siblings
            merkle_path.push(FixedBytes::<48>::new(sibling_data));
        }

        let computed_root: [u8; 48] = compute_merkle_root(leaf.clone(), merkle_path.clone());
        println!("initial computed_root: {:?}", computed_root);

        let merkle_root = FixedBytes::<48>::new(computed_root);
        // let bls_privkey: PrivateKey = PrivateKey::generate(&mut rand::thread_rng());
        // let bls_pubkey: PublicKey = bls_privkey.public_key();
        // let bls_signature: Signature = bls_privkey.sign(&(merkle_root.as_slice()));

        let bls_pubkey = FixedBytes::<48>::from_str("af991965245f23d0e8c498f95fb0293c3923f9ff68b24b93866570f49d9eb66afc19f156934f80edd52f42c3dcf41784").unwrap();
        let bls_signature = FixedBytes::<96>::from_str("82249048863ff610b4f1ac9396a3d1d7ef636cadd022a32ee01e28740dc5fc0b731627a46f5f0ae3b339912d68906b0a0db56c39a5a00a563cb53cad71d9c90d804f09bd51d7aed9114b23ef1fe83b2ddcf60af6747b76d90fd984c692a45ad1").unwrap();
        
        let env = ExecutorEnv::builder()
            .write(&merkle_root).unwrap()
            .write(&leaf).unwrap()
            .write(&bls_pubkey).unwrap()
            .write(&bls_signature).unwrap()
            .write(&merkle_path).unwrap()
            .build().unwrap();

        // NOTE: Use the executor to run tests without proving.
        let session_info = default_executor().execute(env, super::MAIN_ELF).unwrap();

        // Call the verification function
        // verify_commitment(tx_hash, l1_block_number, signed_commitment, sequencer_pubkey, sequencing_data);
    }
}
