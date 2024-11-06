use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::{pairing::Pairing, Group};
use ark_poly::Radix2EvaluationDomain;
use ark_std::rand::Rng;
use ark_std::test_rng;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use laconic_ot::{Choice, CommitmentKey, LaconicOTRecv, LaconicOTSender};

const MIN_LOG_SIZE: usize = 3;
const MAX_LOG_SIZE: usize = 10;

fn laconic_ot_benchmarks(c: &mut Criterion) {
    let name = "laconic_ot";

    let mut commit_benchmarks = c.benchmark_group(format!("{0}/commit", name));
    commit_benchmarks.sample_size(10);
    for log_len in MIN_LOG_SIZE..=MAX_LOG_SIZE {
        commit_benchmarks.bench_with_input(
            BenchmarkId::from_parameter(log_len),
            &log_len,
            |b, _| {
                let rng = &mut test_rng();
                let num = 1 << log_len;

                let mut bits = Vec::with_capacity(log_len);
                for _ in 0..num {
                    bits.push(Choice::random(rng));
                }

                b.iter(|| {
                    let ck =
                        CommitmentKey::<Bls12_381, Radix2EvaluationDomain<Fr>>::setup(rng, num)
                            .unwrap();

                    let _sender = LaconicOTRecv::new(&ck, &bits);
                })
            },
        );
    }
    commit_benchmarks.finish();

    let mut send_benchmarks = c.benchmark_group(format!("{0}/send_all", name));
    for log_len in MIN_LOG_SIZE..=MAX_LOG_SIZE {
        let rng = &mut test_rng();
        let num = 1 << log_len;

        let mut bits = Vec::with_capacity(log_len);
        for _ in 0..num {
            bits.push(Choice::random(rng));
        }

        let ck = CommitmentKey::<Bls12_381, Radix2EvaluationDomain<Fr>>::setup(rng, num).unwrap();
        let recv = LaconicOTRecv::new(&ck, &bits);

        let m0 = [0u8; 32];
        let m1 = [1u8; 32];

        send_benchmarks.bench_with_input(BenchmarkId::from_parameter(log_len), &log_len, |b, _| {
            b.iter(|| {
                let sender = LaconicOTSender::new(&ck, recv.commitment());
                // precompute pairing
                let l0 = recv.commitment();
                let l1 = recv.commitment() - ck.u[0];

                // m0, m1
                let com0 = Bls12_381::pairing(l0, ck.g2);
                let com1 = Bls12_381::pairing(l1, ck.g2);

                let mut com0_precomp = vec![(com0, -com0)];
                let mut com1_precomp = vec![(com1, -com1)];
                for _ in 1..381 {
                    let com0_square = *com0_precomp.last().unwrap().0.clone().double_in_place();
                    let com1_square = *com1_precomp.last().unwrap().0.clone().double_in_place();
                    let com0_square_inv = *com0_precomp.last().unwrap().1.clone().double_in_place();
                    let com1_square_inv = *com1_precomp.last().unwrap().1.clone().double_in_place();
                    com0_precomp.push((com0_square, com0_square_inv));
                    com1_precomp.push((com1_square, com1_square_inv));
                }

                for i in 0..num {
                    let _msg =
                        sender.send_precompute_naf(rng, i, m0, m1, &com0_precomp, &com1_precomp);
                }
            })
        });
    }
    send_benchmarks.finish();

    let mut recv_benchmarks = c.benchmark_group(format!("{0}/recv_all", name));

    for log_len in MIN_LOG_SIZE..=MAX_LOG_SIZE {
        let rng = &mut test_rng();
        let num = 1 << log_len;

        let mut bits = Vec::with_capacity(log_len);
        for _ in 0..num {
            bits.push(Choice::random(rng));
        }

        let ck = CommitmentKey::<Bls12_381, Radix2EvaluationDomain<Fr>>::setup(rng, num).unwrap();
        let recv = LaconicOTRecv::new(&ck, &bits);

        let m0 = [0u8; 32];
        let m1 = [1u8; 32];

        let sender = LaconicOTSender::new(&ck, recv.commitment());

        // Simulate all sends
        let msgs: Vec<_> = (0..num).map(|i| sender.send(rng, i, m0, m1)).collect();

        recv_benchmarks.bench_with_input(BenchmarkId::from_parameter(log_len), &log_len, |b, _| {
            b.iter(|| {
                for i in 0..num {
                    let _res = recv.recv(i, msgs[i].clone());
                }
            })
        });
    }
}

criterion_group! {
    name = laconic_ot;
    config = Criterion::default().sample_size(10);
    targets = laconic_ot_benchmarks, // ipa_benchmarks
}
criterion_main!(laconic_ot);
