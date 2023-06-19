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
use sc_client_api::execution_extensions::{ExecutionExtensions, ExecutionStrategies};
use sc_executor::{
	NativeElseWasmExecutor, NativeExecutionDispatch, NativeVersion, WasmExecutionMethod,
	WasmExecutor, WasmtimeInstantiationStrategy,
};
use sc_offchain::OffchainDb;
use sc_service::client::Client;
use sp_api::ApiError;
use sp_crypto_ec_utils::elliptic_curves;
use sp_crypto_ec_utils_test_runtime as runtime;
use sp_crypto_ec_utils_test_runtime::{genesismap::GenesisStorageBuilder, Block, RuntimeApi};
use sp_keystore::testing::MemoryKeystore;
use sp_state_machine::ExecutionStrategy;
use sp_storage::Storage;
use sp_wasm_interface::ExtendedHostFunctions;
use std::{process::Command, sync::Arc};
use substrate_test_provider::TestClientBuilder;
use substrate_test_runtime_client::client::{ClientConfig, LocalCallExecutor};
use crate:OsString;

pub type Backend = substrate_test_client::Backend<Block>;

/// Parameters of test-client builder with test-runtime.
#[derive(Default)]
pub struct GenesisParameters {
	heap_pages_override: Option<u64>,
	extra_storage: Storage,
	wasm_code: Option<Vec<u8>>,
}

impl GenesisParameters {}

impl substrate_test_client::GenesisInit for GenesisParameters {
	fn genesis_storage(&self) -> Storage {
		GenesisStorageBuilder::default()
			.with_heap_pages(self.heap_pages_override)
			.with_wasm_code(&self.wasm_code)
			.with_extra_storage(self.extra_storage.clone())
			.build()
	}
}

// Our native executor instance, with HostFunctions extended by elliptic_curve host functions.
#[derive(Clone)]
pub struct ExecutorDispatch;
impl NativeExecutionDispatch for ExecutorDispatch {
	type ExtendHostFunctions = elliptic_curves::HostFunctions;

	fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
		runtime::api::dispatch(method, data)
	}
	fn native_version() -> NativeVersion {
		runtime::native_version()
	}
}

// Add assertions or further test code as needed...
type EccExecutor = LocalCallExecutor<Block, Backend, NativeElseWasmExecutor<ExecutorDispatch>>;

pub(crate) fn compose_test_client(
	stack_size: i32,
) -> Result<Client<Backend, EccExecutor, Block, RuntimeApi>, ApiError> {
	let stack_size = OsString::from(stack_size.to_string());
	let keystore = Arc::new(MemoryKeystore::new());
	let method = WasmExecutionMethod::Compiled {
		instantiation_strategy: WasmtimeInstantiationStrategy::RecreateInstance,
	};
	let executor = WasmExecutor::<
		ExtendedHostFunctions<
			sp_io::SubstrateHostFunctions,
			<ExecutorDispatch as NativeExecutionDispatch>::ExtendHostFunctions,
		>,
	>::builder()
	.with_execution_method(method)
	.with_max_runtime_instances(1)
	.with_runtime_cache_size(2)
	.build();
	let executor: NativeElseWasmExecutor<ExecutorDispatch> =
		NativeElseWasmExecutor::<ExecutorDispatch>::new_with_wasm_executor(executor);
	let backend = Arc::new(sc_client_db::Backend::new_test(std::u32::MAX, std::u64::MAX));
	let execution_extensions = ExecutionExtensions::new(
		ExecutionStrategies::default(),
		Some(keystore.clone()),
		OffchainDb::factory_from_backend(&*backend.clone()),
		Arc::new(executor.clone()),
	);
	let ecc_executor =
		EccExecutor::new(backend.clone(), executor, ClientConfig::default(), execution_extensions)?;
	
	let (test_client, _) =
		<TestClientBuilder<Block, EccExecutor, Backend, GenesisParameters>>::with_backend(backend)
			.set_keystore(keystore)
			.set_execution_strategy(ExecutionStrategy::Both)
			.build_with_executor::<RuntimeApi>(ecc_executor);
	Ok(test_client)
}
