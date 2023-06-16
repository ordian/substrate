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

//! The Substrate runtime. This can be compiled with `#[no_std]`, ready for Wasm.

#![cfg_attr(not(feature = "std"), no_std)]

mod errors;
#[cfg(feature = "std")]
pub use substrate_test_runtime::extrinsic;
#[cfg(feature = "std")]
pub use substrate_test_runtime::genesismap;

// mod bls12_377;
// mod bls12_381;
// mod bw6_761;
// mod ed_on_bls12_377;
// mod ed_on_bls12_381_bandersnatch;

pub use errors::EccError;
use frame_support::{construct_runtime, traits::ConstU32};
use frame_system::{CheckNonce, CheckWeight};
use sp_api::{decl_runtime_apis, impl_runtime_apis};
pub use sp_core::hash::H256;
use sp_runtime::traits::Block as BlockT;
use sp_std::prelude::*;
use sp_version::RuntimeVersion;
pub use substrate_test_runtime::{
	AccountId, Address, Balance, BlockNumber, Digest, DigestItem, Hash, Hashing, Header, Index,
	Signature, VERSION,
};

use codec::Error;
use errors::EccError;

#[cfg(feature = "std")]
pub use extrinsic::{ExtrinsicBuilder, Transfer};

// Include the WASM binary
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

#[cfg(feature = "std")]
pub use substrate_test_runtime::wasm_binary_logging_disabled;

/// Wasm binary unwrapped. If built with `SKIP_WASM_BUILD`, the function panics.
#[cfg(feature = "std")]
pub use substrate_test_runtime::wasm_binary_unwrap;

/// Wasm binary unwrapped. If built with `SKIP_WASM_BUILD`, the function panics.
#[cfg(feature = "std")]
pub use substrate_test_runtime::wasm_binary_logging_disabled_unwrap;

fn version() -> RuntimeVersion {
	VERSION
}

/// Native version.
#[cfg(any(feature = "std", test))]
pub use substrate_test_runtime::native_version;
/// The SignedExtension to the basic transaction logic.
pub type SignedExtra = (CheckNonce<Runtime>, CheckWeight<Runtime>);
/// The payload being signed in transactions.
pub type SignedPayload = sp_runtime::generic::SignedPayload<RuntimeCall, SignedExtra>;
/// Unchecked extrinsic type as expected by this runtime.
pub type Extrinsic =
	sp_runtime::generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;
// The test runtime Block
pub type Block = sp_runtime::generic::Block<Header, Extrinsic>;

decl_runtime_apis! {
	#[api_version(2)]
	pub trait TestAPI {
		/// Tests a projective mul for g1 on bls12_381
		fn test_bls12_381_g1_mul_projective_crypto(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, ArkScaleError>;
	}
}

construct_runtime!(
	pub enum Runtime where
		Block = Block,
		NodeBlock = Block,
		UncheckedExtrinsic = Extrinsic
	{
		System: frame_system,
	}
);

impl frame_system::pallet::Config for Runtime {
	type BaseCallFilter = frame_support::traits::Everything;
	type BlockWeights = ();
	type BlockLength = ();
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeCall = RuntimeCall;
	type Index = Index;
	type BlockNumber = BlockNumber;
	type Hash = H256;
	type Hashing = Hashing;
	type AccountId = AccountId;
	type Lookup = sp_runtime::traits::IdentityLookup<Self::AccountId>;
	type Header = Header;
	type RuntimeEvent = RuntimeEvent;
	type BlockHashCount = ();
	type DbWeight = ();
	type Version = ();
	type PalletInfo = PalletInfo;
	type AccountData = ();
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type SS58Prefix = ();
	type OnSetCode = ();
	type MaxConsumers = ConstU32<16>;
}

impl_runtime_apis! {
	impl sp_api::Core<Block> for Runtime {
		fn version() -> RuntimeVersion {
			version()
		}

		fn execute_block(_block: Block) {
			unimplemented!()
		}

		fn initialize_block(_header: &<Block as BlockT>::Header) {
			unimplemented!()
		}
	}

	impl self::TestAPI<Block> for Runtime {
		// bls12 377 runtime apis
		fn bls12_377_multi_miller_loop_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, ArkScaleError> {
			sp_crypto_ec_utils::elliptic_curves::bls12_377_multi_miller_loop(base, scalar)
			.map_err(|_| EccError::Bls12_377MULTI_MILLER_LOOP)
		}
		fn bls12_377_final_exponentiation_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, ArkScaleError> {
			sp_crypto_ec_utils::elliptic_curves::bls12_377_final_exponentiation(base, scalar)
			.map_err(|_| EccError::Bls12_377FINAL_EXPONENTIATION)
		}
		fn bls12_377_g1_mul_projective_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, ArkScaleError> {
			sp_crypto_ec_utils::elliptic_curves::bls12_377_mul_projective_g1(base, scalar)
			.map_err(|_| EccError::Bls12_377G1PROJECTIVE)
		}
		fn bls12_377_g2_mul_projective_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, ArkScaleError> {
			sp_crypto_ec_utils::elliptic_curves::bls12_377_mul_projective_g2(base, scalar)
			.map_err(|_| EccError::Bls12_377G2PROJECTIVE)
		}
		// bls12 381 runtime apis
		fn bls12_381_g2_mul_projective_g1_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, ArkScaleError> {
			sp_crypto_ec_utils::elliptic_curves::bls12_381_mul_projective_g1(base, scalar)
			.map_err(|_| EccError::Bls12_381G1PROJECTIVE)
		}
		fn bls12_381_g2_mul_projective_g2_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, ArkScaleError> {
			sp_crypto_ec_utils::elliptic_curves::bls12_381_mul_projective_g2(base, scalar)
			.map_err(|_| EccError::Bls12_381G2PROJECTIVE)
		}
		fn bls12_381_multi_miller_loop_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, ArkScaleError> {
			sp_crypto_ec_utils::elliptic_curves::bls12_381_multi_miller_loop(base, scalar)
			.map_err(|_| EccError::Bls12_381MULTI_MILLER_LOOP)
		}
		fn bls12_381_final_exponentiation_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, ArkScaleError> {
			sp_crypto_ec_utils::elliptic_curves::bls12_381_final_exponentiation(base, scalar)
			.map_err(|_| EccError::Bls12_381FINAL_EXPONENTIATION)
		}
		// bw6 761 runtime apis
		fn bw6_761_mul_projective_g1_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, ArkScaleError> {
			sp_crypto_ec_utils::elliptic_curves::bw6_761_mul_projective_g1(base, scalar)
			.map_err(|_| EccError::BW6_761G1PROJECTIVE)
		}
		fn bw6_761_mul_projective_g2_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, ArkScaleError> {
			sp_crypto_ec_utils::elliptic_curves::bw6_761_mul_projective_g2(base, scalar)
			.map_err(|_| EccError::BW6_761G2PROJECTIVE)
		}
		fn bw6_761_msm_g1_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, ArkScaleError> {
			sp_crypto_ec_utils::elliptic_curves::bw6_761_msm_g1(base, scalar)
			.map_err(|_| EccError::BW6_761MSM_G1)
		}
		fn bw6_761_msm_g2_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, ArkScaleError> {
			sp_crypto_ec_utils::elliptic_curves::bw6_761_msm_g2(base, scalar)
			.map_err(|_| EccError::BW6_761MSM_G2)
		}
		fn bw6_761_multi_miller_loop_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, ArkScaleError> {
			sp_crypto_ec_utils::elliptic_curves::bw6_761_multi_miller_loop(base, scalar)
			.map_err(|_| EccError::BW6_761MULTI_MILLER_LOOP)
		}
		fn bw6_761_final_exponentiation_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, ArkScaleError> {
			sp_crypto_ec_utils::elliptic_curves::bw6_761_final_exponentiation(base, scalar)
			.map_err(|_| EccError::BW6_761FINAL_EXPONENTIATION)
		}
		// ed on bls12 377 runtime apis
		fn ed_on_bls12_377_mul_projective_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, ArkScaleError> {
			sp_crypto_ec_utils::elliptic_curves::ed_on_bls12_377_mul_projective(base, scalar)
			.map_err(|_| EccError::ED_ON_BLS12_377MUL_PROJECTIVE)
		}
		fn ed_on_bls12_377_msm_runtime(base: Vec<u8>, scalar: Vec<u8>) {
			sp_crypto_ec_utils::elliptic_curves::ed_on_bls12_377_msm(base, scalar)
			.map_err(|_| EccError::ED_ON_BLS12_377MSM)
		}
		// ed on bls12 381 runtime apis
		fn ed_on_bls12_381_bandersnatch_sw_mul_projective_runtime() {
			sp_crypto_ec_utils::elliptic_curves::ed_on_bls12_381_bandersnatch_sw_mul_projective(base, scalar)
			.map_err(|_| EccError::ED_ON_BLS12_381_BANDERSNATCH_SW_MUL_PROJECTIVE)
		}
		fn ed_on_bls12_381_bandersnatch_te_mul_projective_runtime() {
			sp_crypto_ec_utils::elliptic_curves::ed_on_bls12_381_bandersnatch_te_mul_projective(base, scalar)
			.map_err(|_| EccError::ED_ON_BLS12_381_BANDERSNATCH_TE_MUL_PROJECTIVE)
		}
		fn ed_on_bls12_381_bandersnatch_sw_msm_runtime(base: Vec<u8>, scalar: Vec<u8>) {
			sp_crypto_ec_utils::elliptic_curves::ed_on_bls12_381_bandersnatch_sw_msm(base, scalar)
			.map_err(|_| EccError::ED_ON_BLS12_381_BANDERSNATCH_SW_MSM)
		}
		fn ed_on_bls12_381_bandersnatch_te_msm_runtime() {
			sp_crypto_ec_utils::elliptic_curves::ed_on_bls12_381_bandersnatch_te_msm(base, scalar)
			.map_err(|_| EccError::ED_ON_BLS12_381_BANDERSNATCH_TE_MSM)
		}

}
}
