// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Runtime tests for sp-crypto-ec-utils

use sp_crypto_ec_utils::{Bls12_377, Bls12_381};

#[cfg(test)]
mod test_client;

#[test]
fn test_bls12_381_groth16_in_runtime() {
	// Get runtime client for testing
	let test_client = get_test_client().expect("Test client builds");

	// Call into the host function
	let result = test_client
		.runtime_api()
		.groth16_test_mimc_runtime::<Bls12_381>(test_client.chain_info().genesis_hash)
		.expect("Runtime execution of groth16 verifies");
}

#[test]
fn test_bls12_377_groth16_in_runtime() {
	// Get runtime client for testing
	let test_client = get_test_client().expect("Test client builds");

	// Call into the host function
	let result = test_client
		.runtime_api()
		.test_groth16_bls12_377_runtime::<Bls12_377>(test_client.chain_info().genesis_hash)
		.expect("Runtime execution of groth16 verifies");
}

// #[test]
// fn test_bw6_761_groth16_in_runtime() {
// 	// Get runtime client for testing
// 	let test_client = get_test_client().expect("Test client builds");

// 	// Call into the host function
// 	let result = test_client
// 		.runtime_api()
// 		.test_groth16_bls12_377_runtime(test_client.chain_info().genesis_hash)
// 		.expect("Runtime execution of groth16 verifies");
// }
