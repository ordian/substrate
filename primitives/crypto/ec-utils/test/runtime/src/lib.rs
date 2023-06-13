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

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(any(feature = "std", test))]

use sp_version::NativeVersion;
use sp_api::{
	decl_runtime_apis, impl_runtime_apis, mock_impl_runtime_apis, ApiError, ApiExt, ApiRef,
	ConstructRuntimeApi, ProvideRuntimeApi, RuntimeApiInfo,
};
use sp_version::{create_apis_vec, create_runtime_str, RuntimeVersion};
use sp_core::{OpaqueMetadata, RuntimeDebug};
use sp_core::hash::Hash;
use sp_runtime::traits::Block as BlockT;
use sp_runtime::generic::UncheckedExtrinsic;
use sp_crypto_ec_utils::elliptic_curves;
use codec::{Encode, Decode};
use sp_consensus_grandpa::{
	AuthorityList, EquivocationProof, GrandpaApi, OpaqueKeyOwnershipProof, GRANDPA_ENGINE_ID,
};
use frame_support::{
	metadata_ir::{
		RuntimeApiMetadataIR, RuntimeApiMethodMetadataIR, RuntimeApiMethodParamMetadataIR,
	},
	traits::ConstU32,
};
use frame_system::{CheckNonce, CheckWeight};
use scale_info::{form::MetaForm, meta_type};
use sp_runtime::traits::SignedExtension;
use scale_info::TypeInfo;

pub mod substrate_test_pallet;

#[cfg(feature = "std")]
pub type Pair = sp_core::sr25519::Pair;

pub type Address = sp_core::sr25519::Public;
pub type BlockNumber = u32;
pub type Index = u64;
pub type Signature = sr25519::Signature;

#[derive(Copy, Clone, PartialEq, Eq, Encode, Decode, RuntimeDebug, TypeInfo)]
pub struct CheckSubstrateCall;

impl sp_runtime::traits::Printable for CheckSubstrateCall {
	fn print(&self) {
		"CheckSubstrateCall".print()
	}
}

impl sp_runtime::traits::Dispatchable for CheckSubstrateCall {
	type RuntimeOrigin = CheckSubstrateCall;
	type Config = CheckSubstrateCall;
	type Info = CheckSubstrateCall;
	type PostInfo = CheckSubstrateCall;

	fn dispatch(
		self,
		_origin: Self::RuntimeOrigin,
	) -> sp_runtime::DispatchResultWithInfo<Self::PostInfo> {
		panic!("This implementation should not be used for actual dispatch.");
	}
}

/// Transfer data extracted from Extrinsic containing `Balances::transfer_allow_death`.
#[derive(Clone, PartialEq, Eq, Encode, Decode, RuntimeDebug, TypeInfo)]
pub struct TransferData {
	pub from: AccountId,
	pub to: AccountId,
	pub amount: Balance,
	pub nonce: Index,
}

impl sp_runtime::traits::SignedExtension for CheckSubstrateCall {
	type AccountId = AccountId;
	type Call = RuntimeCall;
	type AdditionalSigned = ();
	type Pre = ();
	const IDENTIFIER: &'static str = "CheckSubstrateCall";

	fn additional_signed(
		&self,
	) -> sp_std::result::Result<Self::AdditionalSigned, TransactionValidityError> {
		Ok(())
	}

	fn validate(
		&self,
		_who: &Self::AccountId,
		call: &Self::Call,
		_info: &DispatchInfoOf<Self::Call>,
		_len: usize,
	) -> TransactionValidity {
		log::trace!(target: LOG_TARGET, "validate");
		match call {
			RuntimeCall::SubstrateTest(ref substrate_test_call) =>
				substrate_test_pallet::validate_runtime_call(substrate_test_call),
			_ => Ok(Default::default()),
		}
	}

	fn pre_dispatch(
		self,
		who: &Self::AccountId,
		call: &Self::Call,
		info: &sp_runtime::traits::DispatchInfoOf<Self::Call>,
		len: usize,
	) -> Result<Self::Pre, TransactionValidityError> {
		self.validate(who, call, info, len).map(drop)
	}
}

pub type SignedExtra = (CheckNonce<Runtime>, CheckWeight<Runtime>, CheckSubstrateCall);
pub type SignedPayload = sp_runtime::generic::SignedPayload<RuntimeCall, SignedExtra>;
pub type Header = sp_runtime::generic::Header<BlockNumber, sp_runtime::traits::BlakeTwo256>;
pub type Extrinsic = sp_runtime::generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;
pub type Block = sp_runtime::generic::Block<Header, Extrinsic>;

impl frame_system::Config for Runtime {
	type BlockWeights = ();
	type BlockLength = ();
	type DbWeight = ();
	type BaseCallFilter = frame_support::traits::Everything;
	type RuntimeOrigin = RuntimeOrigin;
	type Index = u64;
	type BlockNumber = u32;
	type RuntimeCall = RuntimeCall;
	type Hash = sp_core::H256;
	type Hashing = sp_runtime::traits::BlakeTwo256;
	type AccountId = u64;
	type Lookup = sp_runtime::traits::IdentityLookup<Self::AccountId>;
	type Header = Header;
	type RuntimeEvent = RuntimeEvent;
	type BlockHashCount = ConstU32<250>;
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

frame_support::construct_runtime!(
	pub enum Runtime where
		Block = Block,
		NodeBlock = Block,
		UncheckedExtrinsic = Extrinsic
	{
		System: frame_system,
		SubstrateTest: substrate_test_pallet::pallet,
	}
);

decl_runtime_apis! {
	#[api_version(3)]
	pub trait Api<Block> {
		fn test_bls12_381_g1_mul_projective_crypto(base: Vec<u8>, scalar: Vec<u8>) -> Vec<u8>;
	}
}

mock_impl_runtime_apis! {
	impl self::Api<Block> for Runtime {
		fn test_bls12_381_g1_mul_projective_crypto(base: Vec<u8>, scalar: Vec<u8>) -> Vec<u8> {
			let result = sp_crypto_ec_utils::elliptic_curves::bls12_381_mul_projective_g1(base, scalar)
			.expect("Projective mul works for g1 in bls12_381")
		}
	}

	impl sp_api::Core<Block> for Runtime {
		fn version() -> sp_version::RuntimeVersion {
			unimplemented!()
		}
		fn execute_block(_: Block) {
			unimplemented!()
		}
		fn initialize_block(_: &<Block as BlockT>::Header) {
			unimplemented!()
		}
	}
}

/// Test runtime version.
#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
	spec_name: create_runtime_str!("test"),
	impl_name: create_runtime_str!("parity-test-ecc-host-functions"),
	authoring_version: 1,
	spec_version: 1,
	impl_version: 1,
	apis: RUNTIME_API_VERSIONS,
	transaction_version: 1,
	state_version: 1,
};

fn version() -> RuntimeVersion {
	VERSION
}

/// Native version.
#[cfg(any(feature = "std", test))]
pub fn native_version() -> NativeVersion {
	NativeVersion { runtime_version: VERSION, can_author_with: Default::default() }
}
