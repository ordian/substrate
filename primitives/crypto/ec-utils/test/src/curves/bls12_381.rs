// This file is part of Substrate.

// Copyright (C) 2017-2022 Parity Technologies (UK) Ltd.
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

//! Support functions for bls12_381 to improve the performance of
//! multi_miller_loop, final_exponentiation, msm's and projective
//! multiplications by host function calls

use ark_bls12_381::{g1, g2, Bls12_381};
use sp_std::vec::Vec;

use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::{fields::Field, One, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::{rand::Rng, test_rng, vec, UniformRand};
use sp_ark_bls12_381::{
	fq::Fq, fq2::Fq2, fr::Fr, Bls12_381 as Bls12_381Host, G1Affine as G1AffineHost,
	G1Projective as G1ProjectiveHost, G2Affine as G2AffineHost, G2Projective as G2ProjectiveHost,
	HostFunctions,
};
use sp_ark_models::pairing::PairingOutput;

#[derive(PartialEq, Eq)]
struct Host;

impl HostFunctions for Host {
	fn bls12_381_multi_miller_loop(a: Vec<u8>, b: Vec<u8>) -> Result<Vec<u8>, ()> {
		crate::elliptic_curves::bls12_381_multi_miller_loop(a, b)
	}
	fn bls12_381_final_exponentiation(f12: Vec<u8>) -> Result<Vec<u8>, ()> {
		crate::elliptic_curves::bls12_381_final_exponentiation(f12)
	}
	fn bls12_381_msm_g1(bases: Vec<u8>, bigints: Vec<u8>) -> Result<Vec<u8>, ()> {
		crate::elliptic_curves::bls12_381_msm_g1(bases, bigints)
	}
	fn bls12_381_msm_g2(bases: Vec<u8>, bigints: Vec<u8>) -> Result<Vec<u8>, ()> {
		crate::elliptic_curves::bls12_381_msm_g2(bases, bigints)
	}
	fn bls12_381_mul_projective_g1(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, ()> {
		crate::elliptic_curves::bls12_381_mul_projective_g1(base, scalar)
	}
	fn bls12_381_mul_projective_g2(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, ()> {
		crate::elliptic_curves::bls12_381_mul_projective_g2(base, scalar)
	}
}

pub type Bls12_381 = Bls12_381Host<Host>;
type G1Projective = G1ProjectiveHost<Host>;
type G2Projective = G2ProjectiveHost<Host>;
type G1Affine = G1AffineHost<Host>;
type G2Affine = G2AffineHost<Host>;
