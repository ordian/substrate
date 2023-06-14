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

//! Integration tests for bls12_381 elliptc curve

use crate::test_client::get_test_client;
use ark_bls12_381::G1Projective;
use ark_ec::Group;
use ark_scale::hazmat::ArkScaleProjective;
use codec::{Decode, Encode};
use sp_api::ProvideRuntimeApi;
use sp_crypto_ec_utils_test_runtime::{EccError, TestAPI};

const HOST_CALL: ark_scale::Usage = ark_scale::HOST_CALL;
type ArkScale<T> = ark_scale::ArkScale<T, HOST_CALL>;

#[test]
fn test_bls12_381_g1_mul_projective_in_runtime() {
	// Get runtime client for testing
	let test_client = get_test_client().expect("Test client builds");

	// Compose test data
	let base: ArkScaleProjective<G1Projective> = G1Projective::generator().into();
	let scalar = vec![2u64];
	let scalar: ArkScale<&[u64]> = (&scalar[..]).into();

	// Call into the host function
	let result = test_client
		.runtime_api()
		.test_bls12_381_g1_mul_projective_crypto(
			test_client.chain_info().genesis_hash,
			base.encode(),
			scalar.encode(),
		)
		.expect("Runtime call of bls12_381_g1_mul_projective succesfull")
		.expect("Computation of mul for g1 on bls12_381 in runtime succesfull");

	// Decode the result
	let result = <ArkScaleProjective<G1Projective> as Decode>::decode(&mut result.as_slice())
		.expect("Decoding result works for bls12_381_g1_mul_projective works");

	assert_eq!(G1Projective::generator().mul_bigint(&[2u64]), result.0);
}
