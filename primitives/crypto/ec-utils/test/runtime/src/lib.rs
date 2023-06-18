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
#![cfg(test)]

#[cfg(feature = "std")]
pub use substrate_test_runtime::extrinsic;
#[cfg(feature = "std")]
pub use substrate_test_runtime::genesismap;

// mod aggregation;
mod errors;
mod groth16;

use crate::groth16::test_mimc_groth16;
pub use errors::{EccError, Groth16Error};
use frame_support::{construct_runtime, traits::ConstU32};
use frame_system::{CheckNonce, CheckWeight};
use sp_api::{decl_runtime_apis, impl_runtime_apis};
pub use sp_core::hash::H256;
use sp_crypto_ec_utils::bls12_381::Bls12_381;
use sp_runtime::traits::Block as BlockT;
use sp_std::prelude::*;
pub use substrate_test_runtime::{
	AccountId, Address, Balance, BlockNumber, Digest, DigestItem, Hash, Hashing, Header, Index,
	Signature, VERSION,
};

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

#[cfg(any(feature = "std", test))]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;

fn version() -> RuntimeVersion {
	VERSION
}

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
		fn bls12_377_g1_mul_projective_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError>;
		fn bls12_377_g2_mul_projective_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError>;
		fn bls12_377_multi_miller_loop_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError>;
		fn bls12_377_final_exponentiation_runtime(target: Vec<u8>) -> Result<Vec<u8>, EccError>;
		// bls12 381 runtime apis
		fn bls12_381_mul_projective_g1_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError>;
		fn bls12_381_mul_projective_g2_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError>;
		fn bls12_381_multi_miller_loop_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError>;
		fn bls12_381_final_exponentiation_runtime(target: Vec<u8>) -> Result<Vec<u8>, EccError>;
		// bw6 761 runtime apis
		fn bw6_761_mul_projective_g1_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError>;
		fn bw6_761_mul_projective_g2_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError>;
		fn bw6_761_msm_g1_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError>;
		fn bw6_761_msm_g2_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError>;
		fn bw6_761_multi_miller_loop_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError>;
		fn bw6_761_final_exponentiation_runtime(target: Vec<u8>) -> Result<Vec<u8>, EccError>;
		// ed on bls12 377 runtime apis
		fn ed_on_bls12_377_mul_projective_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError>;
		fn ed_on_bls12_377_msm_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError>;
		// ed on bls12 381 runtime apis
		fn ed_on_bls12_381_bandersnatch_sw_mul_projective_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError>;
		fn ed_on_bls12_381_bandersnatch_te_mul_projective_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError>;
		fn ed_on_bls12_381_bandersnatch_sw_msm_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError>;
		fn ed_on_bls12_381_bandersnatch_te_msm_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError>;
		// groth16 runtime
		// fn groth16_aggregation();
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
		fn bls12_377_g1_mul_projective_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError> {
			sp_crypto_ec_utils::elliptic_curves::bls12_377_mul_projective_g1(base, scalar)
			.map_err(|_| EccError::Bls12_377G1Projective)
		}
		fn bls12_377_g2_mul_projective_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError> {
			sp_crypto_ec_utils::elliptic_curves::bls12_377_mul_projective_g2(base, scalar)
			.map_err(|_| EccError::Bls12_377G2Projective)
		}
		fn bls12_377_multi_miller_loop_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError> {
			sp_crypto_ec_utils::elliptic_curves::bls12_377_multi_miller_loop(base, scalar)
			.map_err(|_| EccError::Bls12_377MultiMillerLoop)
		}
		fn bls12_377_final_exponentiation_runtime(target: Vec<u8>) -> Result<Vec<u8>, EccError> {
			sp_crypto_ec_utils::elliptic_curves::bls12_377_final_exponentiation(target)
			.map_err(|_| EccError::Bls12_377FinalExponentiation)
		}
		// bls12 381 runtime apis
		fn bls12_381_mul_projective_g1_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError> {
			sp_crypto_ec_utils::elliptic_curves::bls12_381_mul_projective_g1(base, scalar)
			.map_err(|_| EccError::Bls12_381G1Projective)
		}
		fn bls12_381_mul_projective_g2_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError> {
			sp_crypto_ec_utils::elliptic_curves::bls12_381_mul_projective_g2(base, scalar)
			.map_err(|_| EccError::Bls12_381G2Projective)
		}
		fn bls12_381_multi_miller_loop_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError> {
			sp_crypto_ec_utils::elliptic_curves::bls12_381_multi_miller_loop(base, scalar)
			.map_err(|_| EccError::Bls12_381MultiMillerLoop)
		}
		fn bls12_381_final_exponentiation_runtime(target: Vec<u8>) -> Result<Vec<u8>, EccError> {
			sp_crypto_ec_utils::elliptic_curves::bls12_381_final_exponentiation(target)
			.map_err(|_| EccError::Bls12_381FinalExponentiation)
		}
		fn test_groth16_bls12_381_runtime() {
			test_mimc_groth16::<Bls12_381>();
		}
		// fn test_groth16_aggregation_bls12_381_runtime() {
		// 	groth16_aggregation();
		// }

		// bw6 761 runtime apis
		fn bw6_761_mul_projective_g1_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError> {
			sp_crypto_ec_utils::elliptic_curves::bw6_761_mul_projective_g1(base, scalar)
			.map_err(|_| EccError::Bw6_761G1Projective)
		}
		fn bw6_761_mul_projective_g2_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError> {
			sp_crypto_ec_utils::elliptic_curves::bw6_761_mul_projective_g2(base, scalar)
			.map_err(|_| EccError::Bw6_761G2Projective)
		}
		fn bw6_761_msm_g1_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError> {
			sp_crypto_ec_utils::elliptic_curves::bw6_761_msm_g1(base, scalar)
			.map_err(|_| EccError::Bw6_761MsmG1)
		}
		fn bw6_761_msm_g2_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError> {
			sp_crypto_ec_utils::elliptic_curves::bw6_761_msm_g2(base, scalar)
			.map_err(|_| EccError::Bw6_761MsmG2)
		}
		fn bw6_761_multi_miller_loop_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError> {
			sp_crypto_ec_utils::elliptic_curves::bw6_761_multi_miller_loop(base, scalar)
			.map_err(|_| EccError::Bw6_761MultiMillerLoop)
		}
		fn bw6_761_final_exponentiation_runtime(target: Vec<u8>) -> Result<Vec<u8>, EccError> {
			sp_crypto_ec_utils::elliptic_curves::bw6_761_final_exponentiation(target)
			.map_err(|_| EccError::Bw6_761FinalExponentiation)
		}
		// ed on bls12 377 runtime apis
		fn ed_on_bls12_377_mul_projective_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError> {
			sp_crypto_ec_utils::elliptic_curves::ed_on_bls12_377_mul_projective(base, scalar)
			.map_err(|_| EccError::EdOnBls12_377MulProjective)
		}
		fn ed_on_bls12_377_msm_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError> {
			sp_crypto_ec_utils::elliptic_curves::ed_on_bls12_377_msm(base, scalar)
			.map_err(|_| EccError::EdOnBls12_377Msm)
		}
		// ed on bls12 381 runtime apis
		fn ed_on_bls12_381_bandersnatch_sw_mul_projective_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError> {
			sp_crypto_ec_utils::elliptic_curves::ed_on_bls12_381_bandersnatch_sw_mul_projective(base, scalar)
			.map_err(|_| EccError::EdOnBls12_381BandersnatchSwMulProjective)
		}
		fn ed_on_bls12_381_bandersnatch_te_mul_projective_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError> {
			sp_crypto_ec_utils::elliptic_curves::ed_on_bls12_381_bandersnatch_te_mul_projective(base, scalar)
			.map_err(|_| EccError::EdOnBls12_381BandersnatchTeMulProjective)
		}
		fn ed_on_bls12_381_bandersnatch_sw_msm_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError> {
			sp_crypto_ec_utils::elliptic_curves::ed_on_bls12_381_bandersnatch_sw_msm(base, scalar)
			.map_err(|_| EccError::EdOnBls12_381BandersnatchSwMsm)
		}
		fn ed_on_bls12_381_bandersnatch_te_msm_runtime(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, EccError> {
			sp_crypto_ec_utils::elliptic_curves::ed_on_bls12_381_bandersnatch_te_msm(base, scalar)
			.map_err(|_| EccError::EdOnBls12_381BandersnatchTeMsm)
		}
}
}

#[runtime_interface]
pub trait Logging {
	/// Request to print a log message on the host.
	///
	/// Note that this will be only displayed if the host is enabled to display log messages with
	/// given level and target.
	///
	/// Instead of using directly, prefer setting up `RuntimeLogger` and using `log` macros.
	fn log(level: LogLevel, target: &str, message: &[u8]) {
		if let Ok(message) = std::str::from_utf8(message) {
			log::log!(target: target, log::Level::from(level), "{}", message)
		}
	}

	/// Returns the max log level used by the host.
	fn max_level() -> LogLevelFilter {
		log::max_level().into()
	}
}

#[panic_handler]
#[no_mangle]
pub fn panic(info: &core::panic::PanicInfo) -> ! {
	let message = sp_std::alloc::format!("{}", info);
	#[cfg(feature = "improved_panic_error_reporting")]
	{
		panic_handler::abort_on_panic(&message);
	}
	#[cfg(not(feature = "improved_panic_error_reporting"))]
	{
		logging::log(LogLevel::Error, "runtime", message.as_bytes());
		core::arch::wasm32::unreachable();
	}
}