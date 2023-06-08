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

//! Integration tests for bls12_381
use ark_bls12_381::G1Projective;
use ark_ec::Group;
use ark_scale::hazmat::ArkScaleProjective;
use codec::{Decode, Encode};
use sc_client_api::{
	execution_extensions::{ExecutionExtensions, ExecutionStrategies},
	HeaderBackend,
};
use sc_executor::WasmExecutor;
use sp_api::ProvideRuntimeApi;
use sp_keystore::testing::MemoryKeystore;
use sp_state_machine::ExecutionStrategy;
use sp_std::vec;
use sp_wasm_interface::ExtendedHostFunctions;
use std::sync::Arc;
use substrate_test_runtime::TestAPI;
use substrate_test_runtime_client::{
	new, DefaultTestClientBuilderExt, TestClientBuilder, TestClientBuilderExt,
};

const HOST_CALL: ark_scale::Usage = ark_scale::HOST_CALL;
type ArkScale<T> = ark_scale::ArkScale<T, HOST_CALL>;

// Our native executor instance, with HostFunctions extended by elliptic_curve host functions.
#[derive(Clone)]
pub struct ExecutorDispatch;
impl sc_executor::NativeExecutionDispatch for ExecutorDispatch {
	type ExtendHostFunctions = sp_crypto_ec_utils::elliptic_curves::HostFunctions;

	fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
		substrate_test_runtime_client::runtime::api::dispatch(method, data)
	}

	fn native_version() -> sc_executor::NativeVersion {
		substrate_test_runtime_client::runtime::native_version()
	}
}

#[test]
fn test_bls12_381_g1_mul_projective_in_runtime() {
	// We need to assemble our own TestClient, since we need to provide to hostcalls
	// from sp_crypto_ec_utils::elliptic_curves which are not part of sp_io
	let keystore = Arc::new(MemoryKeystore::new());
	let executor = WasmExecutor::<
		ExtendedHostFunctions<
			sp_io::SubstrateHostFunctions,
			sp_crypto_ec_utils::elliptic_curves::HostFunctions,
		>,
	>::builder()
	.build();
	let executor: sc_executor::NativeElseWasmExecutor<_> =
		sc_executor::NativeElseWasmExecutor::<ExecutorDispatch>::new_with_wasm_executor(executor);
	let backend =
		Arc::new(substrate_test_runtime_client::Backend::new_test(std::u32::MAX, std::u64::MAX));
	let client_config = substrate_test_runtime_client::client::ClientConfig::default();
	let strategies = ExecutionStrategies {
		syncing: ExecutionStrategy::AlwaysWasm,
		importing: ExecutionStrategy::AlwaysWasm,
		block_construction: ExecutionStrategy::AlwaysWasm,
		offchain_worker: ExecutionStrategy::AlwaysWasm,
		other: ExecutionStrategy::AlwaysWasm,
	};
	let execution_extensions = ExecutionExtensions::new(
		strategies.clone(),
		Some(keystore.clone()),
		sc_offchain::OffchainDb::factory_from_backend(&*backend.clone()),
		Arc::new(executor.clone()),
	);
	let executor = sc_service::client::LocalCallExecutor::<
		substrate_test_runtime::Block,
		substrate_test_runtime_client::Backend,
		sc_executor::NativeElseWasmExecutor<ExecutorDispatch>,
	>::new(backend.clone(), executor, client_config, execution_extensions)
	.expect("");
	let (test_client, _) = substrate_test_client::TestClientBuilder::<
		substrate_test_runtime::Block,
		sc_service::client::LocalCallExecutor<
			substrate_test_runtime::Block,
			substrate_test_runtime_client::Backend,
			sc_executor::NativeElseWasmExecutor<ExecutorDispatch>,
		>,
		substrate_test_runtime_client::Backend,
		substrate_test_runtime_client::GenesisParameters,
	>::default()
	// .set_execution_strategy(ExecutionStrategy::AlwaysWasm)
	// .set_keystore(keystore)
	.build_with_executor::<substrate_test_runtime::RuntimeApi>(executor);

	// substrate_test_runtime::TestAPI

	// Prepare the test input data

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
		.expect("bls12_381_g1_mul_projective");

	// Decode the result

	let result =
		<ArkScaleProjective<G1Projective> as Decode>::decode(&mut result.as_slice()).expect("");

	assert_eq!(G1Projective::generator().mul_bigint(&[2u64]), result.0);
}
