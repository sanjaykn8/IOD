//! The membership AIR (algebraic intermediate representation).
//!
//! One row = one Poseidon2-BabyBear-16 permutation plus control columns.
//! Rows:  [0..6)  leaf sponge blocks (absorb the 48-limb leaf stream)
//!        [6..6+D) Merkle levels (D = tree depth)
//!        rest    padding (needed for the hiding-FRI budget)
//!
//! A one-hot selector FSM fixes the row type of every row, so a malicious
//! prover cannot reorder, skip or duplicate steps. The root check
//! `out == R_G` is guarded by the selector of the last Merkle level, and a
//! last-row constraint forces the FSM to have reached that state (this
//! closes the "truncated trace" attack). Every public value is bound by an
//! AIR constraint (the uni-stark verifier relies on that).
//!
//! The Poseidon2 round evaluation below is adapted from
//! `p3-poseidon2-air` (MIT/Apache-2.0), whose `eval` is crate-private.

use crate::zkhash::*;
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{
    GenericPoseidon2LinearLayersBabyBear as Lin, BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
    BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL, BABYBEAR_POSEIDON2_RC_16_INTERNAL,
};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{
    generate_trace_rows, num_cols, FullRound, PartialRound, Poseidon2Cols, RoundConstants,
};
use p3_symmetric::Permutation;

pub const W: usize = 16;
pub const SBOX: u64 = 7;
pub const REGS: usize = 1;
pub const HALF: usize = 4;
pub const PARTIAL: usize = 13;
pub type P2Cols<T> = Poseidon2Cols<T, W, SBOX, REGS, HALF, PARTIAL>;
pub const P2W: usize = num_cols::<W, SBOX, REGS, HALF, PARTIAL>();

/// Public-value layout (field elements).
pub const PV_PROTO: usize = 0;
pub const PV_VG: usize = 1;
pub const PV_G: usize = 2; // 11
pub const PV_ROOT: usize = PV_G + HASH_LIMBS; // 8
pub const PV_COMM: usize = PV_ROOT + DIGEST_LEN; // 11
pub const PV_META: usize = PV_COMM + HASH_LIMBS; // 11
pub const PV_SESSION: usize = PV_META + HASH_LIMBS; // 11
pub const NUM_PV: usize = PV_SESSION + HASH_LIMBS; // 54

// Extra-column layout (offsets after the permutation columns).
const C_BLK: usize = P2W; // 8: leaf message block
const C_BIT: usize = C_BLK + 8; // 1: Merkle path bit
const C_SIB: usize = C_BIT + 1; // 8: Merkle sibling
const C_PC: usize = C_SIB + 8; // 2 + 11: copies of proto, V_G, session
const NPC: usize = 2 + HASH_LIMBS;
const C_SEL: usize = C_PC + NPC;

#[derive(Clone)]
pub struct MembershipAir {
    pub depth: usize,
    pub constants: RoundConstants<Bb, W, HALF, PARTIAL>,
}

impl MembershipAir {
    pub fn new(depth: usize) -> Self {
        assert!(depth >= 1 && depth <= 32);
        let constants = RoundConstants::new(
            BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
            BABYBEAR_POSEIDON2_RC_16_INTERNAL,
            BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
        );
        MembershipAir { depth, constants }
    }
    /// Selector indices: leaf blocks 0..6, Merkle levels 6..6+D, pad 6+D.
    pub fn nsel(&self) -> usize {
        LEAF_BLOCKS + self.depth + 1
    }
    pub fn s_merkle(&self, i: usize) -> usize {
        LEAF_BLOCKS + i
    }
    pub fn s_pad(&self) -> usize {
        LEAF_BLOCKS + self.depth
    }
    pub fn min_rows(&self) -> usize {
        LEAF_BLOCKS + self.depth + 1
    }
    pub fn trace_width(&self) -> usize {
        C_SEL + self.nsel()
    }
}

impl BaseAir<Bb> for MembershipAir {
    fn width(&self) -> usize {
        self.trace_width()
    }
    fn num_public_values(&self) -> usize {
        NUM_PV
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

fn sbox7<AB: AirBuilder<F = Bb>>(
    sb: &p3_poseidon2_air::SBox<AB::Var, SBOX, REGS>,
    x: &mut AB::Expr,
    b: &mut AB,
) {
    let x3: AB::Expr = sb.0[0].into();
    b.assert_eq(x3.clone(), x.clone().cube());
    *x = x3.square() * x.clone();
}

fn full_round<AB: AirBuilder<F = Bb>>(
    state: &mut [AB::Expr; W],
    r: &FullRound<AB::Var, W, SBOX, REGS>,
    rc: &[Bb; W],
    b: &mut AB,
) {
    for i in 0..W {
        state[i] += AB::Expr::from(rc[i]);
        sbox7::<AB>(&r.sbox[i], &mut state[i], b);
    }
    Lin::external_linear_layer(state);
    for i in 0..W {
        b.assert_eq(state[i].clone(), r.post[i]);
        state[i] = r.post[i].into();
    }
}

fn partial_round<AB: AirBuilder<F = Bb>>(
    state: &mut [AB::Expr; W],
    r: &PartialRound<AB::Var, SBOX, REGS>,
    rc: &Bb,
    b: &mut AB,
) {
    state[0] += AB::Expr::from(*rc);
    sbox7::<AB>(&r.sbox, &mut state[0], b);
    b.assert_eq(state[0].clone(), r.post_sbox);
    state[0] = r.post_sbox.into();
    Lin::internal_linear_layer(state);
}

fn eval_perm<AB: AirBuilder<F = Bb>>(air: &MembershipAir, b: &mut AB, p: &P2Cols<AB::Var>) {
    let mut state: [AB::Expr; W] = p.inputs.map(|x| x.into());
    Lin::external_linear_layer(&mut state);
    for r in 0..HALF {
        full_round::<AB>(&mut state, &p.beginning_full_rounds[r], &air.constants.beginning_full_round_constants()[r], b);
    }
    for r in 0..PARTIAL {
        partial_round::<AB>(&mut state, &p.partial_rounds[r], &air.constants.partial_round_constants()[r], b);
    }
    for r in 0..HALF {
        full_round::<AB>(&mut state, &p.ending_full_rounds[r], &air.constants.ending_full_round_constants()[r], b);
    }
}

fn out_of<T: Copy>(p: &P2Cols<T>) -> [T; W] {
    p.ending_full_rounds[HALF - 1].post
}

impl<AB: AirBuilder<F = Bb>> Air<AB> for MembershipAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let l = main.current_slice();
        let n = main.next_slice();
        let pv: Vec<AB::PublicVar> = b.public_values().to_vec();
        let d = self.depth;
        let ns = self.nsel();

        let lp: &P2Cols<AB::Var> = l[..P2W].borrow();
        let np: &P2Cols<AB::Var> = n[..P2W].borrow();
        eval_perm::<AB>(self, b, lp);

        let sel = |row: &[AB::Var], i: usize| -> AB::Expr { row[C_SEL + i].into() };
        let one = AB::Expr::ONE;

        // --- selector FSM -------------------------------------------------
        let mut sum = AB::Expr::ZERO;
        for i in 0..ns {
            let s = sel(l, i);
            b.assert_zero(s.clone() * (s.clone() - one.clone()));
            sum += s;
        }
        b.assert_eq(sum, one.clone());
        b.assert_zero(l[C_BIT].into() * (AB::Expr::from(l[C_BIT]) - one.clone()));
        b.when_first_row().assert_one(sel(l, 0));
        // Last row must be in {last Merkle level, pad}: FSM completed.
        b.when_last_row()
            .assert_one(sel(l, self.s_merkle(d - 1)) + sel(l, self.s_pad()));
        {
            let mut t = b.when_transition();
            t.assert_zero(sel(n, 0));
            for i in 0..ns - 2 {
                t.assert_eq(sel(n, i + 1), sel(l, i));
            }
            t.assert_eq(sel(n, self.s_pad()), sel(l, self.s_pad() - 1) + sel(l, self.s_pad()));
        }

        // --- public values -> columns (first row) -------------------------
        {
            let mut f = b.when_first_row();
            f.assert_eq(l[C_PC], pv[PV_PROTO]);
            f.assert_eq(l[C_PC + 1], pv[PV_VG]);
            for i in 0..HASH_LIMBS {
                f.assert_eq(l[C_PC + 2 + i], pv[PV_SESSION + i]);
            }
        }
        // copies stay constant down the trace
        {
            let mut t = b.when_transition();
            for i in 0..NPC {
                t.assert_eq(n[C_PC + i], l[C_PC + i]);
            }
        }

        // --- leaf sponge --------------------------------------------------
        // Stream limb (8k+j) source.
        for k in 0..LEAF_BLOCKS {
            for j in 0..8 {
                let idx = 8 * k + j;
                let blk: AB::Expr = l[C_BLK + j].into();
                let s = sel(l, k);
                if idx == 0 {
                    b.assert_zero(s * (blk - AB::Expr::from(bb(LEAF_FORMAT_VERSION))));
                } else if (1..12).contains(&idx) {
                    b.assert_zero(s * (blk - pv[PV_G + idx - 1].into()));
                } else if (12..23).contains(&idx) {
                    b.assert_zero(s * (blk - pv[PV_COMM + idx - 12].into()));
                } else if (23..34).contains(&idx) {
                    b.assert_zero(s * (blk - pv[PV_META + idx - 23].into()));
                } else if (34..42).contains(&idx) {
                    // rho: private, unconstrained here (committed, hidden).
                } else {
                    b.assert_zero(s * blk);
                }
            }
        }
        // First leaf row: input = [blk | IV].
        {
            let s = sel(l, 0);
            let iv = leaf_iv();
            for j in 0..8 {
                b.assert_zero(s.clone() * (AB::Expr::from(lp.inputs[j]) - l[C_BLK + j].into()));
                b.assert_zero(s.clone() * (AB::Expr::from(lp.inputs[8 + j]) - AB::Expr::from(iv[j])));
            }
        }
        // Subsequent leaf rows: absorb into the rate.
        {
            let lo = out_of(lp);
            let mut t = b.when_transition();
            for k in 1..LEAF_BLOCKS {
                let s = sel(n, k);
                for j in 0..8 {
                    t.assert_zero(s.clone() * (AB::Expr::from(np.inputs[j]) - AB::Expr::from(lo[j]) - AB::Expr::from(n[C_BLK + j])));
                    t.assert_zero(s.clone() * (AB::Expr::from(np.inputs[8 + j]) - AB::Expr::from(lo[8 + j])));
                }
            }
        }

        // --- Merkle levels ------------------------------------------------
        {
            let lo = out_of(lp);
            let mut t = b.when_transition();
            for i in 0..d {
                let s = sel(n, self.s_merkle(i));
                let bit: AB::Expr = n[C_BIT].into();
                for j in 0..8 {
                    let cur: AB::Expr = lo[j].into();
                    let sib: AB::Expr = n[C_SIB + j].into();
                    // bit=0: [cur|sib]; bit=1: [sib|cur]
                    let left = cur.clone() + bit.clone() * (sib.clone() - cur.clone());
                    let right = sib.clone() + bit.clone() * (cur - sib);
                    t.assert_zero(s.clone() * (AB::Expr::from(np.inputs[j]) - left));
                    t.assert_zero(s.clone() * (AB::Expr::from(np.inputs[8 + j]) - right));
                }
            }
        }
        // Root check at the last level.
        {
            let s = sel(l, self.s_merkle(d - 1));
            let lo = out_of(lp);
            for j in 0..8 {
                b.assert_zero(s.clone() * (AB::Expr::from(lo[j]) - pv[PV_ROOT + j].into()));
            }
        }
    }
}

/// Inputs the prover needs to fill the trace.
pub struct TraceInputs<'a> {
    pub stream: &'a [Bb; LEAF_STREAM_LEN],
    pub siblings: &'a [Digest],
    pub bits: &'a [bool],
    pub pc: [Bb; NPC],
}

pub fn pc_from_pv(pv: &[Bb]) -> [Bb; NPC] {
    let mut pc = [Bb::ZERO; NPC];
    pc[0] = pv[PV_PROTO];
    pc[1] = pv[PV_VG];
    pc[2..].copy_from_slice(&pv[PV_SESSION..PV_SESSION + HASH_LIMBS]);
    pc
}

pub fn build_trace(air: &MembershipAir, ti: &TraceInputs, height: usize) -> RowMajorMatrix<Bb> {
    let d = air.depth;
    assert!(height.is_power_of_two() && height >= air.min_rows());
    assert_eq!(ti.siblings.len(), d);
    assert_eq!(ti.bits.len(), d);
    let p = perm();
    let mut inputs: Vec<[Bb; 16]> = Vec::with_capacity(height);
    let mut blk: Vec<[Bb; 8]> = vec![[Bb::ZERO; 8]; height];
    let mut bit = vec![false; height];
    let mut sib = vec![[Bb::ZERO; 8]; height];
    let mut selrow = vec![0usize; height];
    // leaf rows
    let st = leaf_sponge_states(ti.stream);
    for (k, (inp, _)) in st.iter().enumerate() {
        inputs.push(*inp);
        blk[k].copy_from_slice(&ti.stream[8 * k..8 * k + 8]);
        selrow[k] = k;
    }
    let mut cur: [Bb; 8] = core::array::from_fn(|i| st.last().unwrap().1[i]);
    for i in 0..d {
        let r = LEAF_BLOCKS + i;
        let s = ti.siblings[i].to_bb();
        let mut inp = [Bb::ZERO; 16];
        if ti.bits[i] {
            inp[..8].copy_from_slice(&s);
            inp[8..].copy_from_slice(&cur);
        } else {
            inp[..8].copy_from_slice(&cur);
            inp[8..].copy_from_slice(&s);
        }
        sib[r] = s;
        bit[r] = ti.bits[i];
        selrow[r] = air.s_merkle(i);
        let mut o = inp;
        p.permute_mut(&mut o);
        cur = core::array::from_fn(|j| o[j]);
        inputs.push(inp);
    }
    while inputs.len() < height {
        selrow[inputs.len()] = air.s_pad();
        inputs.push([Bb::ZERO; 16]);
    }
    let pm = generate_trace_rows::<Bb, Lin, W, SBOX, REGS, HALF, PARTIAL>(inputs, &air.constants, 0);
    let w = air.trace_width();
    let mut vals = vec![Bb::ZERO; height * w];
    for r in 0..height {
        let row = &mut vals[r * w..(r + 1) * w];
        row[..P2W].copy_from_slice(&pm.values[r * P2W..(r + 1) * P2W]);
        row[C_BLK..C_BLK + 8].copy_from_slice(&blk[r]);
        row[C_BIT] = Bb::from_bool(bit[r]);
        row[C_SIB..C_SIB + 8].copy_from_slice(&sib[r]);
        row[C_PC..C_PC + NPC].copy_from_slice(&ti.pc);
        row[C_SEL + selrow[r]] = Bb::ONE;
    }
    RowMajorMatrix::new(vals, w)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn air_permutation_equals_native_poseidon2() {
        // The proven permutation must be the SAME function as the native
        // hash used for the tree. Compare an AIR-generated trace output
        // against the native permutation on a non-trivial input.
        let air = MembershipAir::new(2);
        let mut inp = [Bb::ZERO; 16];
        for (i, x) in inp.iter_mut().enumerate() {
            *x = bb(1000 + 17 * i as u32);
        }
        let m = generate_trace_rows::<Bb, Lin, W, SBOX, REGS, HALF, PARTIAL>(
            vec![inp, inp], &air.constants, 0,
        );
        let cols: &P2Cols<Bb> = m.values[..P2W].borrow();
        let mut native = inp;
        perm().permute_mut(&mut native);
        assert_eq!(out_of(cols), native);
    }
}
