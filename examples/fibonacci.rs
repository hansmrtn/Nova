use ff::Field;
use flate2::{write::ZlibEncoder, Compression};
use nova_snark::{
  frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError},
  nova::{CompressedSNARK, PublicParams, RecursiveSNARK},
  provider::{Bn256EngineKZG, GrumpkinEngine},
  traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait, Engine, Group},
};
use std::time::Instant;

type E1 = Bn256EngineKZG;
type E2 = GrumpkinEngine;

type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;

type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;

// Represents a single step in the Fibonacci sequence
// At step i, F(i) and F(i + 1) compute F(i + 2) = F(i) + F(i + 1)
#[derive(Clone, Debug)]
struct FibonacciCircuit<G: Group> {
  _phantom: std::marker::PhantomData<G>,
}

impl<G: Group> FibonacciCircuit<G> {
  // Create a new circuit
  fn new() -> Self {
    Self {
      _phantom: std::marker::PhantomData,
    }
  }
}

impl<G: Group> StepCircuit<G::Scalar> for FibonacciCircuit<G> {
  fn arity(&self) -> usize {
    2
  }

  fn synthesize<CS: ConstraintSystem<G::Scalar>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<G::Scalar>],
  ) -> Result<Vec<AllocatedNum<G::Scalar>>, SynthesisError> {
    // z[0] = F[i]
    // z[1] = F[i + 1]
    let f_i = z[0].clone();
    let f_i_plus_1 = z[1].clone();

    // compute F(i + 2) = F(i) + F(i + 1)
    let f_i_plus_2 = AllocatedNum::alloc(cs.namespace(|| "f_i_plus_2"), || {
      let a = f_i.get_value().ok_or(SynthesisError::AssignmentMissing)?;
      let b = f_i_plus_1
        .get_value()
        .ok_or(SynthesisError::AssignmentMissing)?;
      Ok(a + b)
    })?;

    cs.enforce(
      || "f_i_plus_2 = f_i + f_i_plus_1",
      |lc| lc + f_i.get_variable(),
      |lc| lc + CS::one(),
      |lc| lc + f_i_plus_2.get_variable() - f_i_plus_1.get_variable(),
    );

    Ok(vec![f_i_plus_1, f_i_plus_2])
  }
}

fn fib_helper(n: usize) -> Vec<u64> {
  let mut fib = vec![0u64, 1u64];
  for i in 2..=n {
    let next = fib[i - 1].wrapping_add(fib[i - 2]);
    fib.push(next);
  }
  fib
}

fn u64_to_scalar<G: Group>(n: u64) -> G::Scalar {
  G::Scalar::from(n)
}

fn main() {
  println!("Nova Fibonacci Sequence Proof");
  println!("-----------------------------");

  let test_cases = vec![1, 10, 100];
  for num_steps in test_cases {
    println!("computing Fibonacci sequence fopr {} steps", num_steps);

    let circuit = FibonacciCircuit::<<E1 as Engine>::GE>::new();

    // Public params
    let start = Instant::now();

    println!("creating public params...");

    let pp = PublicParams::<E1, E2, FibonacciCircuit<<E1 as Engine>::GE>>::setup(
      &circuit,
      &*S1::ck_floor(),
      &*S2::ck_floor(),
    )
    .unwrap();

    println!("pp setup took {:?}", start.elapsed());

    println!(
      "# of constraints per step (primary): {}",
      pp.num_constraints().0
    );
    println!(
      "# of constraints per step (secondary): {}",
      pp.num_constraints().1
    );

    println!(
      "# of variables per step (primary): {}",
      pp.num_variables().0
    );
    println!(
      "# of variables per step (secondary): {}",
      pp.num_variables().1
    );

    let z0 = vec![u64_to_scalar::<<E1 as Engine>::GE>(0), 
                    u64_to_scalar::<<E1 as Engine>::GE>(1)];

    // create recursive snark
    type C = FibonacciCircuit<<E1 as Engine>::GE>; 

    println!("SNARKing..."); 
    let mut snark: RecursiveSNARK<E1, E2, C> = RecursiveSNARK::<E1, E2, C>::new(&pp, &circuit, &z0).unwrap();

    let prove_start = Instant::now(); 
    for i in 0..num_steps {
        let step_start = Instant::now(); 
        let res = snark.prove_step(&pp, &circuit); 
        assert!(res.is_ok()); 

        println!("Progress: {} / {} steps, last step took {:?}", i + 1, num_steps, step_start.elapsed()); 
    }

    let total_prove_time = prove_start.elapsed(); 
    println!(
        "Total proving time for {} steps: {:?}", num_steps, total_prove_time); 

    // verify
    
    println!("Verifying the snark!..."); 
    let start = Instant::now(); 
    let res = snark.verify(&pp, num_steps, &z0); 
    println!("RecursiveSNARK.::verify: {:?}, took: {:?}", res.is_ok(), start.elapsed()); 
    assert!(res.is_ok());

  }
}
