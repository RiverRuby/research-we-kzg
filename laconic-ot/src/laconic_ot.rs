use std::sync::mpsc::Receiver;

use crate::kzg_utils::plain_kzg_com;
use crate::{kzg_fk_open::all_openings_single, kzg_types::CommitmentKey};

use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::Group;
use ark_ff::BigInteger;
use ark_ff::CyclotomicMultSubgroup;
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::CanonicalSerialize;
use ark_std::One;
use ark_std::UniformRand;
use ark_std::Zero;
use rand::Rng;

const MSG_SIZE: usize = 32;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Choice {
    Zero,
    One,
}

impl Choice {
    pub fn random<R: Rng>(rng: &mut R) -> Self {
        let b: bool = rng.gen();
        if b {
            Choice::One
        } else {
            Choice::Zero
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Msg<E: Pairing> {
    h: [(E::G2Affine, [u8; MSG_SIZE]); 2],
}

pub struct LaconicOT<E: Pairing, D: EvaluationDomain<E::ScalarField>> {
    ck: CommitmentKey<E, D>,
}

pub struct LaconicOTRecv<'a, E: Pairing, D: EvaluationDomain<E::ScalarField>> {
    ck: &'a CommitmentKey<E, D>,
    qs: Vec<E::G1>,
    com: E::G1,
    bits: Vec<Choice>,
}

pub struct LaconicOTSender<'a, E: Pairing, D: EvaluationDomain<E::ScalarField>> {
    ck: &'a CommitmentKey<E, D>,
    com: E::G1,
}

impl<'a, E: Pairing, D: EvaluationDomain<E::ScalarField>> LaconicOTRecv<'a, E, D> {
    pub fn new(ck: &'a CommitmentKey<E, D>, bits: &[Choice]) -> Self {
        let mut elems: Vec<_> = bits
            .iter()
            .map(|b| {
                if *b == Choice::One {
                    E::ScalarField::one()
                } else {
                    E::ScalarField::zero()
                }
            })
            .collect();

        // pad with random elements
        assert!(elems.len() <= ck.domain.size());
        elems.resize_with(ck.domain.size(), || {
            E::ScalarField::rand(&mut ark_std::test_rng())
        });

        // compute commitment
        let com = plain_kzg_com(ck, &elems);

        // compute all openings
        let qs = all_openings_single::<E, D>(&ck.y, &ck.domain, &elems);

        Self {
            ck,
            qs,
            com: com.into(),
            bits: bits.to_vec(),
        }
    }

    pub fn recv(&self, i: usize, msg: Msg<E>) -> [u8; MSG_SIZE] {
        let j: usize = if self.bits[i] == Choice::One { 1 } else { 0 };
        let h = msg.h[j].0;
        let c = msg.h[j].1;
        let m = E::pairing(self.qs[i], h);
        decrypt::<E, MSG_SIZE>(m.0, &c)
    }

    pub fn commitment(&self) -> E::G1 {
        self.com
    }
}

fn encrypt<E: Pairing, const N: usize>(pad: E::TargetField, msg: &[u8; N]) -> [u8; N] {
    // hash the pad
    let mut hsh = blake3::Hasher::new();
    pad.serialize_uncompressed(&mut hsh).unwrap();

    // xor the message with the pad
    let mut xof = hsh.finalize_xof();
    let mut res = [0u8; N];
    xof.fill(&mut res);

    for i in 0..N {
        res[i] ^= msg[i];
    }
    res
}

fn decrypt<E: Pairing, const N: usize>(pad: E::TargetField, ct: &[u8; N]) -> [u8; N] {
    encrypt::<E, N>(pad, ct)
}

impl<'a, E: Pairing, D: EvaluationDomain<E::ScalarField>> LaconicOTSender<'a, E, D> {
    pub fn new(ck: &'a CommitmentKey<E, D>, com: E::G1) -> Self {
        Self { ck, com }
    }

    pub fn send_precompute_squares<R: Rng>(
        &self,
        rng: &mut R,
        i: usize,
        m0: [u8; MSG_SIZE],
        m1: [u8; MSG_SIZE],
        com0_squares: &[PairingOutput<E>],
        com1_squares: &[PairingOutput<E>],
    ) -> Msg<E> {
        let x = self.ck.domain.element(i);
        let r0 = E::ScalarField::rand(rng);
        let r1 = E::ScalarField::rand(rng);

        let g2 = self.ck.g2;
        let tau = self.ck.r;

        // Compute msk0 and msk1 using the precomputed squares
        let msk0 = self.scalar_mul_with_precomputed_squares(com0_squares, r0);
        let msk1 = self.scalar_mul_with_precomputed_squares(com1_squares, r1);

        // h0, h1
        let g2x = g2 * x;
        let cm: E::G2 = Into::<E::G2>::into(tau) - g2x;
        let h0: E::G2 = cm * r0;
        let h1: E::G2 = cm * r1;

        // encapsulate the messages
        Msg {
            h: [
                (h0.into(), encrypt::<E, MSG_SIZE>(msk0.0, &m0)),
                (h1.into(), encrypt::<E, MSG_SIZE>(msk1.0, &m1)),
            ],
        }
    }

    pub fn send_precompute_naf<R: Rng>(
        &self,
        rng: &mut R,
        i: usize,
        m0: [u8; MSG_SIZE],
        m1: [u8; MSG_SIZE],
        com0_precomp: &[(PairingOutput<E>, PairingOutput<E>)],
        com1_precomp: &[(PairingOutput<E>, PairingOutput<E>)],
    ) -> Msg<E> {
        let x = self.ck.domain.element(i);
        let r0 = E::ScalarField::rand(rng);
        let r1 = E::ScalarField::rand(rng);

        let g2 = self.ck.g2;
        let tau = self.ck.r;

        // Compute msk0 and msk1 using the precomputed squares
        let msk0 = self.scalar_mul_with_precomputed_naf(com0_precomp, r0);
        let msk1 = self.scalar_mul_with_precomputed_naf(com1_precomp, r1);

        // h0, h1
        let g2x = g2 * x;
        let cm: E::G2 = Into::<E::G2>::into(tau) - g2x;
        let h0: E::G2 = cm * r0;
        let h1: E::G2 = cm * r1;

        // encapsulate the messages
        Msg {
            h: [
                (h0.into(), encrypt::<E, MSG_SIZE>(msk0.0, &m0)),
                (h1.into(), encrypt::<E, MSG_SIZE>(msk1.0, &m1)),
            ],
        }
    }

    pub fn send_precompute_pairings<R: Rng>(
        &self,
        rng: &mut R,
        i: usize,
        m0: [u8; MSG_SIZE],
        m1: [u8; MSG_SIZE],
        com0: PairingOutput<E>,
        com1: PairingOutput<E>,
    ) -> Msg<E> {
        let x = self.ck.domain.element(i);
        let r0 = E::ScalarField::rand(rng);
        let r1 = E::ScalarField::rand(rng);

        let g2 = self.ck.g2;
        let tau = self.ck.r;

        // m0, m1
        let msk0 = com0 * r0;
        let msk1 = com1 * r1;

        // h0, h1
        let cm = Into::<E::G2>::into(tau) - g2 * x;
        let h0: E::G2 = cm * r0;
        let h1: E::G2 = cm * r1;

        // encapsulate the messages
        Msg {
            h: [
                (h0.into(), encrypt::<E, MSG_SIZE>(msk0.0, &m0)),
                (h1.into(), encrypt::<E, MSG_SIZE>(msk1.0, &m1)),
            ],
        }
    }

    pub fn send<R: Rng>(
        &self,
        rng: &mut R,
        i: usize,
        m0: [u8; MSG_SIZE],
        m1: [u8; MSG_SIZE],
    ) -> Msg<E> {
        let x = self.ck.domain.element(i);
        let r0 = E::ScalarField::rand(rng);
        let r1 = E::ScalarField::rand(rng);

        let g1 = self.ck.u[0];
        let g2 = self.ck.g2;
        let tau = self.ck.r;

        // y = 0/1
        let l0 = self.com * r0; // r * (c - [y])
        let l1 = (self.com - g1) * r1; // r * (c - [y])

        // m0, m1
        let msk0 = E::pairing(l0, self.ck.g2);
        let msk1 = E::pairing(l1, self.ck.g2);

        // h0, h1
        let cm = Into::<E::G2>::into(tau) - g2 * x;
        let h0: E::G2 = cm * r0;
        let h1: E::G2 = cm * r1;

        // encapsulate the messages
        Msg {
            h: [
                (h0.into(), encrypt::<E, MSG_SIZE>(msk0.0, &m0)),
                (h1.into(), encrypt::<E, MSG_SIZE>(msk1.0, &m1)),
            ],
        }
    }

    fn scalar_mul_with_precomputed_squares(
        &self,
        precomp: &[PairingOutput<E>],
        scalar: E::ScalarField,
    ) -> PairingOutput<E> {
        let mut result = PairingOutput::<E>::zero();

        for (i, num) in scalar.into_bigint().to_bits_le().iter().enumerate() {
            if *num {
                result += precomp[i];
            }
        }
        result
    }

    fn scalar_mul_with_precomputed_naf(
        &self,
        precomp: &[(PairingOutput<E>, PairingOutput<E>)],
        scalar: E::ScalarField,
    ) -> PairingOutput<E> {
        let mut result = PairingOutput::<E>::zero();

        for (i, num) in scalar
            .into_bigint()
            .find_wnaf(2)
            .unwrap()
            .iter()
            .enumerate()
        {
            if *num == 1 {
                result += precomp[i].0;
            } else if *num == -1 {
                result += precomp[i].1;
            }
        }
        result
    }
}

#[test]
fn test_laconic_ot() {
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;

    let rng = &mut test_rng();

    let degree = 4;
    let ck = CommitmentKey::<Bls12_381, Radix2EvaluationDomain<Fr>>::setup(rng, degree).unwrap();

    let receiver = LaconicOTRecv::new(&ck, &[Choice::Zero, Choice::One, Choice::Zero, Choice::One]);
    let sender = LaconicOTSender::new(&ck, receiver.commitment());

    let m0 = [0u8; MSG_SIZE];
    let m1 = [1u8; MSG_SIZE];

    // precompute pairing
    let l0 = receiver.commitment();
    let l1 = receiver.commitment() - sender.ck.u[0];

    // m0, m1
    let com0 = Bls12_381::pairing(l0, receiver.ck.g2);
    let com1 = Bls12_381::pairing(l1, receiver.ck.g2);

    // test normal send
    let msg = sender.send(rng, 0, m0, m1);
    let res = receiver.recv(0, msg);
    assert_eq!(res, m0);

    // test without precomputation
    let msg = sender.send_precompute_pairings(rng, 1, m0, m1, com0, com1);
    let res = receiver.recv(1, msg);
    assert_eq!(res, m1);

    // precompute naf data
    let mut com0_precomp = vec![(com0, -com0)];
    let mut com1_precomp = vec![(com1, -com1)];
    let mut com0_squares = vec![com0];
    let mut com1_squares = vec![com1];
    for _ in 1..381 {
        let com0_square = *com0_precomp.last().unwrap().0.clone().double_in_place();
        let com1_square = *com1_precomp.last().unwrap().0.clone().double_in_place();
        let com0_square_inv = *com0_precomp.last().unwrap().1.clone().double_in_place();
        let com1_square_inv = *com1_precomp.last().unwrap().1.clone().double_in_place();
        com0_squares.push(com0_square);
        com1_squares.push(com1_square);
        com0_precomp.push((com0_square, com0_square_inv));
        com1_precomp.push((com1_square, com1_square_inv));
    }

    // test with precompute squares
    let msg = sender.send_precompute_squares(rng, 2, m0, m1, &com0_squares, &com1_squares);
    let res = receiver.recv(2, msg);
    assert_eq!(res, m0);

    // test with precompute naf
    let msg = sender.send_precompute_naf(rng, 3, m0, m1, &com0_precomp, &com1_precomp);
    let res = receiver.recv(3, msg);
    assert_eq!(res, m1);
}
