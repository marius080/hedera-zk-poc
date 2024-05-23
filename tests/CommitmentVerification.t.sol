// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.20;

import {RiscZeroCheats} from "risc0/RiscZeroCheats.sol";
import {console2} from "forge-std/console2.sol";
import {Test} from "forge-std/Test.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {CommitmentVerification} from "../contracts/CommitmentVerification.sol";
import {Elf} from "./Elf.sol"; // auto-generated contract after running `cargo build`.

import { Sha2Ext } from "./Sha2Ext.sol";

contract CommitmentVerificationTest is RiscZeroCheats, Test {
    CommitmentVerification public commitmentVerification;

    function setUp() public {
        IRiscZeroVerifier verifier = deployRiscZeroVerifier();
        commitmentVerification = new CommitmentVerification(verifier);

    }

    function test_works() public {
        // mock transaction hash, just a random value
        //bytes memory leafData = "example leaf data";
        //(bytes32 b1, bytes16 b2) = Sha2Ext.sha384(leafData);
        //bytes memory leaf = abi.encode(b1, b2);
        //console2.logBytes(leaf);
        //48 bytes sha384 of b"example leaf data"
        bytes memory leaf = hex"0efa1c3008184a4b9c562a787d26b2084a4c4624095cfc448c4f3c6158a32d6af0489b873c794325cf128882666bc736";

        bytes memory merkleRoot = hex"7656838873538ff82acc1c5925967f1193a97c684265e5f6d7c1ddb632caa26843a91106172a880e14c0e8bd9585f1a0";

        // BLS12-381 pubkey corresponding to secret key 586896d5c9e7da928a27ce83b984a5da8f0979647bca86aff0aa97745724c35e
        // generated using https://iancoleman.io/blsttc_ui/
        bytes memory blsPubKey = hex"af991965245f23d0e8c498f95fb0293c3923f9ff68b24b93866570f49d9eb66afc19f156934f80edd52f42c3dcf41784";
        
        // generated using https://iancoleman.io/blsttc_ui/
        bytes memory blsSignature = hex"af08d283cbf25c4863294e49d08080b6bb9861e92d7ccc16434c4d355bf3c22f7858e7cb63fc3461d3250ce250822f9a1274952d7282c1f585a48b2572497c727beaf295ba817c5c112d5a4603c0fe864caeadab040c9ad5db47441ac8aef259";

        bytes memory input = bytes.concat(merkleRoot, leaf, blsPubKey, blsSignature);

        bytes[] memory merklePath = new bytes[](256);
        for (uint256 i = 0; i < 256; i++) {
            bytes memory element = new bytes(48);
            assembly {
                mstore(add(add(element, 48), 0), i) // Store index value at the beginning of the bytes element
            }
            merklePath[i] = element;
            input = bytes.concat(input, merklePath[i]);

            //console2.logBytes(merklePath[i]);
        }

        //console2.logBytes(input);


        //(bytes memory journal, bytes32 post_state_digest, bytes memory seal) = prove(Elf.MAIN_PATH, abi.encodePacked(merkleRoot, leaf, blsPubKey, blsSignature, merklePath));
        (bytes memory journal, bytes32 post_state_digest, bytes memory seal) = prove(Elf.MAIN_PATH, input);

        (bytes memory computedMerkleRoot, bytes memory computedLeaf, bytes memory computedPubkey, bytes memory computedSignature) = abi.decode(journal, (bytes, bytes, bytes, bytes));

        require(compareBytes(computedMerkleRoot, merkleRoot), "merkle roots don't match");

        require(compareBytes(computedLeaf, leaf), "leaf doesn't match");

        require(compareBytes(computedPubkey, blsPubKey), "pubKey doesn't match");

        require(compareBytes(computedSignature, blsSignature), "signature doesn't match");

        commitmentVerification.verify(journal, post_state_digest, seal);
    }
}

function compareBytes(bytes memory a, bytes memory b) pure returns (bool) {
    if(a.length != b.length) {
        return false;
    }
    for(uint i=0; i<a.length; i++) {
        if(a[i] != b[i]) {
            return false;
        }
    }
    return true;
}