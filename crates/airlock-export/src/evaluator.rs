//! AuditEvaluator: ExprEvaluator-like recorder that keeps uncompressed LogUp entries.

use num_traits::{One, Zero};
use stwo::core::Fraction;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::expr::{BaseExpr, ColumnExpr, ExtExpr};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, INTERACTION_TRACE_IDX, ORIGINAL_TRACE_IDX, Relation, RelationEntry,
};

/// One uncompressed relation participation captured before challenge compression.
#[derive(Clone, Debug)]
pub struct RawRelationEntry {
    /// Relation name from [`Relation::get_name`].
    pub relation_name: String,
    /// Tuple element expressions (base field).
    pub values: Vec<BaseExpr>,
    /// Multiplicity expression (extension field).
    pub multiplicity: ExtExpr,
    /// Source tag for debugging.
    pub source: String,
}

struct FormalLogupAtRow {
    interaction: usize,
    fracs: Vec<Fraction<ExtExpr, ExtExpr>>,
    is_finalized: bool,
    cumsum_shift: ExtExpr,
}

impl FormalLogupAtRow {
    fn new(interaction: usize, log_size: u32) -> Self {
        let claimed_sum_name = "claimed_sum".to_string();
        let column_size = BaseField::from(2u32).pow(log_size.into());
        Self {
            interaction,
            fracs: vec![],
            is_finalized: true,
            cumsum_shift: ExtExpr::Param(claimed_sum_name)
                * BaseExpr::Inv(Box::new(BaseExpr::Const(column_size))),
        }
    }
}

/// Evaluator that records constraints **and** uncompressed relation entries.
pub struct AuditEvaluator {
    /// Next column index counter (per ExprEvaluator).
    pub cur_var_index: usize,
    /// Collected polynomial constraints.
    pub constraints: Vec<ExtExpr>,
    /// Uncompressed relation entries (the lossless LogUp view).
    pub relations: Vec<RawRelationEntry>,
    /// Preprocessed column ids in access order.
    pub preprocessed_columns: Vec<PreProcessedColumnId>,
    /// Whether finalize_logup was called.
    pub logup_finalized: bool,
    /// Structural problems that would otherwise panic Stwo's ExprEvaluator.
    /// Export fails closed on these instead of crashing the host process.
    pub structural_errors: Vec<String>,
    logup: FormalLogupAtRow,
}

impl AuditEvaluator {
    /// Create an empty auditor for a component with the given row-domain size.
    pub fn new(log_size: u32) -> Self {
        Self {
            cur_var_index: 0,
            constraints: Vec::new(),
            relations: Vec::new(),
            preprocessed_columns: Vec::new(),
            logup_finalized: false,
            structural_errors: Vec::new(),
            logup: FormalLogupAtRow::new(INTERACTION_TRACE_IDX, log_size),
        }
    }

    fn combine_formal<R: Relation<BaseExpr, ExtExpr>>(
        &mut self,
        relation: &R,
        values: &[BaseExpr],
    ) -> ExtExpr {
        const Z_SUFFIX: &str = "_z";
        const ALPHA_SUFFIX: &str = "_alpha";
        let z = ExtExpr::Param(relation.get_name().to_owned() + Z_SUFFIX);
        let alpha = ExtExpr::Param(relation.get_name().to_owned() + ALPHA_SUFFIX);
        if relation.get_size() != values.len() {
            self.structural_errors.push(format!(
                "relation `{}` arity mismatch: declared size {} but received {} values",
                relation.get_name(),
                relation.get_size(),
                values.len()
            ));
        }
        values
            .iter()
            .fold((ExtExpr::zero(), ExtExpr::one()), |(acc, power), value| {
                (acc + power.clone() * value.clone(), power * alpha.clone())
            })
            .0
            - z
    }
}

impl EvalAtRow for AuditEvaluator {
    type F = BaseExpr;
    type EF = ExtExpr;

    fn next_interaction_mask<const N: usize>(
        &mut self,
        interaction: usize,
        offsets: [isize; N],
    ) -> [Self::F; N] {
        let res = std::array::from_fn(|i| {
            let col = ColumnExpr::from((interaction, self.cur_var_index, offsets[i]));
            BaseExpr::Col(col)
        });
        self.cur_var_index += 1;
        res
    }

    fn add_constraint<G>(&mut self, constraint: G)
    where
        Self::EF: From<G>,
    {
        self.constraints.push(constraint.into());
    }

    fn combine_ef(values: [Self::F; 4]) -> Self::EF {
        ExtExpr::SecureCol([
            Box::new(values[0].clone()),
            Box::new(values[1].clone()),
            Box::new(values[2].clone()),
            Box::new(values[3].clone()),
        ])
    }

    fn add_to_relation<R: Relation<Self::F, Self::EF>>(
        &mut self,
        entry: RelationEntry<'_, Self::F, Self::EF, R>,
    ) {
        if self.logup_finalized {
            self.structural_errors.push(format!(
                "add_to_relation(`{}`) after LogUp was finalized",
                entry.relation().get_name()
            ));
        }
        self.relations.push(RawRelationEntry {
            relation_name: entry.relation().get_name().to_string(),
            values: entry.values().to_vec(),
            multiplicity: entry.multiplicity().clone(),
            source: format!("{}:add_to_relation", entry.relation().get_name()),
        });

        let combined = self.combine_formal(entry.relation(), entry.values());
        let frac = Fraction::new(entry.multiplicity().clone(), combined);
        self.write_logup_frac(frac);
    }

    fn get_preprocessed_column(&mut self, column: PreProcessedColumnId) -> Self::F {
        self.preprocessed_columns.push(column.clone());
        BaseExpr::Param(column.id)
    }

    fn next_trace_mask(&mut self) -> Self::F {
        let [mask_item] = self.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]);
        mask_item
    }

    fn write_logup_frac(&mut self, fraction: Fraction<Self::EF, Self::EF>) {
        if self.logup.fracs.is_empty() {
            self.logup.is_finalized = false;
        }
        self.logup.fracs.push(fraction);
    }

    fn finalize_logup_batched(&mut self, batch_size: usize) {
        if batch_size == 0 {
            self.structural_errors
                .push("finalize_logup_batched called with batch_size 0".into());
            return;
        }
        // Components with no relation entries may still call finalize. Treat that as
        // a no-op rather than panicking (Stwo's ExprEvaluator panics; AuditEvaluator
        // is an assurance tool and should fail closed without crashing the host).
        if self.logup.fracs.is_empty() {
            self.logup.is_finalized = true;
            self.logup_finalized = true;
            return;
        }
        if self.logup.is_finalized {
            self.structural_errors
                .push("LogupAtRow was already finalized".into());
            return;
        }

        let mut batched: Vec<Fraction<Self::EF, Self::EF>> = self
            .logup
            .fracs
            .chunks(batch_size)
            .map(|chunk| chunk.iter().cloned().sum())
            .collect();

        let Some(last_frac) = batched.pop() else {
            self.structural_errors
                .push("non-empty fracs produced no batched fractions".into());
            return;
        };
        let mut prev_col_cumsum = <Self::EF as num_traits::Zero>::zero();

        for cur_frac in batched {
            let [cur_cumsum] = self.next_extension_interaction_mask(self.logup.interaction, [0]);
            let diff = cur_cumsum.clone() - prev_col_cumsum.clone();
            prev_col_cumsum = cur_cumsum;
            self.add_constraint(diff * cur_frac.denominator - cur_frac.numerator);
        }

        let [prev_row_cumsum, cur_cumsum] =
            self.next_extension_interaction_mask(self.logup.interaction, [-1, 0]);
        let diff = cur_cumsum - prev_row_cumsum - prev_col_cumsum;
        let shifted_diff = diff + self.logup.cumsum_shift.clone();
        self.add_constraint(shifted_diff * last_frac.denominator - last_frac.numerator);
        self.logup.is_finalized = true;
        self.logup_finalized = true;
    }

    fn finalize_logup(&mut self) {
        self.finalize_logup_batched(1);
    }

    fn finalize_logup_in_pairs(&mut self) {
        self.finalize_logup_batched(2);
    }
}
