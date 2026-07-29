//! AuditEvaluator: ExprEvaluator-like recorder that keeps uncompressed LogUp entries.

use std::any::type_name;
use std::collections::BTreeMap;

use airlock_ir::M31_P;
use num_traits::{One, Zero};
use stwo::core::Fraction;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::expr::{BaseExpr, ColumnExpr, ExtExpr};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, INTERACTION_TRACE_IDX, ORIGINAL_TRACE_IDX, Relation, RelationEntry,
};

use crate::annotations::RelationCompression;

const MAX_RELATION_FINGERPRINT_TERMS: usize = 4096;
const MAX_RELATION_FINGERPRINT_DEPTH: usize = 128;

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
    column_index_per_interaction: BTreeMap<usize, usize>,
    mask_offsets_per_interaction: BTreeMap<usize, Vec<Vec<isize>>>,
    relation_compressions: BTreeMap<String, RelationCompression>,
    relation_types: BTreeMap<String, &'static str>,
    logup: FormalLogupAtRow,
}

impl AuditEvaluator {
    /// Create an empty auditor for a component with the given row-domain size.
    pub fn new(log_size: u32) -> Self {
        Self::with_relation_compressions(log_size, BTreeMap::new())
    }

    pub(crate) fn with_relation_compressions(
        log_size: u32,
        relation_compressions: BTreeMap<String, RelationCompression>,
    ) -> Self {
        Self {
            constraints: Vec::new(),
            relations: Vec::new(),
            preprocessed_columns: Vec::new(),
            logup_finalized: false,
            structural_errors: Vec::new(),
            column_index_per_interaction: BTreeMap::new(),
            mask_offsets_per_interaction: BTreeMap::new(),
            relation_compressions,
            relation_types: BTreeMap::new(),
            logup: FormalLogupAtRow::new(INTERACTION_TRACE_IDX, log_size),
        }
    }

    pub(crate) fn mask_offsets_per_interaction(&self) -> &BTreeMap<usize, Vec<Vec<isize>>> {
        &self.mask_offsets_per_interaction
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
        match self.relation_compressions.get(relation.get_name()).copied() {
            Some(RelationCompression::StwoLookupElements { z, alpha }) => {
                if let Err(error) = verify_stwo_lookup_shape(relation, values.len(), z, alpha) {
                    self.structural_errors.push(format!(
                        "relation `{}` does not match its declared StwoLookupElements compression: {error}",
                        relation.get_name()
                    ));
                }
            }
            None => self.structural_errors.push(format!(
                "relation `{}` has no declared compression contract",
                relation.get_name()
            )),
        }
        let current_type = type_name::<R>();
        if let Some(previous_type) = self
            .relation_types
            .insert(relation.get_name().to_owned(), current_type)
            && previous_type != current_type
        {
            self.structural_errors.push(format!(
                "relation name `{}` is shared by distinct Rust types `{previous_type}` and `{current_type}`",
                relation.get_name()
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

    fn push_relation_fraction(&mut self, fraction: Fraction<ExtExpr, ExtExpr>) {
        if self.logup.fracs.is_empty() {
            self.logup.is_finalized = false;
        }
        self.logup.fracs.push(fraction);
    }
}

type Monomial = Vec<u16>;
type BasePolynomial = BTreeMap<Monomial, BaseField>;
type ExtPolynomial = BTreeMap<Monomial, SecureField>;

fn verify_stwo_lookup_shape<R: Relation<BaseExpr, ExtExpr>>(
    relation: &R,
    arity: usize,
    z_limbs: [u32; 4],
    alpha_limbs: [u32; 4],
) -> Result<(), String> {
    if arity == 0 {
        return Err("zero-arity relations are unsupported".into());
    }
    let z = secure_from_reference("z", z_limbs)?;
    let alpha = secure_from_reference("alpha", alpha_limbs)?;
    let variable_names: Vec<String> = (0..arity)
        .map(|index| format!("__airlock_relation_value_{index}"))
        .collect();
    let values: Vec<BaseExpr> = variable_names
        .iter()
        .map(|name| BaseExpr::Param(name.clone()))
        .collect();
    let polynomial = normalize_ext_polynomial(
        &relation.combine(&values),
        &variable_names,
        MAX_RELATION_FINGERPRINT_TERMS,
    )?;
    let constant_monomial = vec![0; arity];
    let mut allowed = BTreeMap::new();
    allowed.insert(constant_monomial.clone(), ());

    let constant = polynomial
        .get(&constant_monomial)
        .copied()
        .unwrap_or_else(SecureField::zero);
    let expected_constant = -z;
    if constant != expected_constant {
        return Err(format!(
            "the constant coefficient is {constant:?}, expected -z = {expected_constant:?}"
        ));
    }

    let coefficients: Vec<SecureField> = (0..arity)
        .map(|index| {
            let mut monomial = vec![0; arity];
            monomial[index] = 1;
            allowed.insert(monomial.clone(), ());
            polynomial
                .get(&monomial)
                .copied()
                .unwrap_or_else(SecureField::zero)
        })
        .collect();
    for (index, coefficient) in coefficients.iter().enumerate() {
        let expected = alpha.pow(index as u128);
        if *coefficient != expected {
            return Err(format!(
                "tuple coefficient {index} is {coefficient:?}, expected alpha^{index} = {expected:?}"
            ));
        }
    }
    if let Some((monomial, _)) = polynomial
        .iter()
        .find(|(monomial, coefficient)| !coefficient.is_zero() && !allowed.contains_key(*monomial))
    {
        return Err(format!(
            "compression contains a non-affine or cross-term monomial {monomial:?}"
        ));
    }
    Ok(())
}

fn secure_from_reference(label: &str, limbs: [u32; 4]) -> Result<SecureField, String> {
    if let Some(value) = limbs.iter().find(|value| **value >= M31_P) {
        return Err(format!(
            "{label} reference contains noncanonical M31 limb {value}"
        ));
    }
    Ok(SecureField::from_m31_array(limbs.map(BaseField::from)))
}

fn normalize_base_polynomial_bounded(
    expression: &BaseExpr,
    variable_names: &[String],
    term_limit: usize,
    depth_remaining: usize,
) -> Result<BasePolynomial, String> {
    let child_depth = fingerprint_child_depth(depth_remaining)?;
    match expression {
        BaseExpr::Const(value) => Ok(base_constant(*value, variable_names.len())),
        BaseExpr::Param(name) => {
            let Some(index) = variable_names
                .iter()
                .position(|candidate| candidate == name)
            else {
                return Err(format!("unexpected base parameter `{name}`"));
            };
            let mut monomial = vec![0; variable_names.len()];
            monomial[index] = 1;
            Ok(BTreeMap::from([(monomial, BaseField::one())]))
        }
        BaseExpr::Add(left, right) => {
            let left =
                normalize_base_polynomial_bounded(left, variable_names, term_limit, child_depth)?;
            let right =
                normalize_base_polynomial_bounded(right, variable_names, term_limit, child_depth)?;
            add_base_polynomials(left, right, false, term_limit)
        }
        BaseExpr::Sub(left, right) => {
            let left =
                normalize_base_polynomial_bounded(left, variable_names, term_limit, child_depth)?;
            let right =
                normalize_base_polynomial_bounded(right, variable_names, term_limit, child_depth)?;
            add_base_polynomials(left, right, true, term_limit)
        }
        BaseExpr::Mul(left, right) => {
            let left =
                normalize_base_polynomial_bounded(left, variable_names, term_limit, child_depth)?;
            let right =
                normalize_base_polynomial_bounded(right, variable_names, term_limit, child_depth)?;
            multiply_base_polynomials(&left, &right, term_limit)
        }
        BaseExpr::Neg(inner) => {
            let mut polynomial =
                normalize_base_polynomial_bounded(inner, variable_names, term_limit, child_depth)?;
            for coefficient in polynomial.values_mut() {
                *coefficient = -*coefficient;
            }
            Ok(polynomial)
        }
        BaseExpr::Inv(_) => Err("base-field inverse is unsupported in relation compression".into()),
        BaseExpr::Col(_) => Err("trace-column read is unsupported in relation compression".into()),
    }
}

fn normalize_ext_polynomial(
    expression: &ExtExpr,
    variable_names: &[String],
    term_limit: usize,
) -> Result<ExtPolynomial, String> {
    normalize_ext_polynomial_bounded(
        expression,
        variable_names,
        term_limit,
        MAX_RELATION_FINGERPRINT_DEPTH,
    )
}

fn normalize_ext_polynomial_bounded(
    expression: &ExtExpr,
    variable_names: &[String],
    term_limit: usize,
    depth_remaining: usize,
) -> Result<ExtPolynomial, String> {
    let child_depth = fingerprint_child_depth(depth_remaining)?;
    match expression {
        ExtExpr::SecureCol(coordinates) => {
            let coordinate_polynomials = coordinates
                .iter()
                .map(|coordinate| {
                    normalize_base_polynomial_bounded(
                        coordinate,
                        variable_names,
                        term_limit,
                        child_depth,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut polynomial = ExtPolynomial::new();
            for coordinate_polynomial in &coordinate_polynomials {
                for monomial in coordinate_polynomial.keys() {
                    polynomial.entry(monomial.clone()).or_default();
                    enforce_term_limit(polynomial.len(), term_limit)?;
                }
            }
            for (monomial, coefficient) in &mut polynomial {
                let coordinates = std::array::from_fn(|index| {
                    coordinate_polynomials[index]
                        .get(monomial)
                        .copied()
                        .unwrap_or_else(BaseField::zero)
                });
                *coefficient = SecureField::from_m31_array(coordinates);
            }
            polynomial.retain(|_, coefficient| !coefficient.is_zero());
            Ok(polynomial)
        }
        ExtExpr::Const(value) => Ok(ext_constant(*value, variable_names.len())),
        ExtExpr::Param(name) => Err(format!("unexpected extension parameter `{name}`")),
        ExtExpr::Add(left, right) => {
            let left =
                normalize_ext_polynomial_bounded(left, variable_names, term_limit, child_depth)?;
            let right =
                normalize_ext_polynomial_bounded(right, variable_names, term_limit, child_depth)?;
            add_ext_polynomials(left, right, false, term_limit)
        }
        ExtExpr::Sub(left, right) => {
            let left =
                normalize_ext_polynomial_bounded(left, variable_names, term_limit, child_depth)?;
            let right =
                normalize_ext_polynomial_bounded(right, variable_names, term_limit, child_depth)?;
            add_ext_polynomials(left, right, true, term_limit)
        }
        ExtExpr::Mul(left, right) => {
            let left =
                normalize_ext_polynomial_bounded(left, variable_names, term_limit, child_depth)?;
            let right =
                normalize_ext_polynomial_bounded(right, variable_names, term_limit, child_depth)?;
            multiply_ext_polynomials(&left, &right, term_limit)
        }
        ExtExpr::Neg(inner) => {
            let mut polynomial =
                normalize_ext_polynomial_bounded(inner, variable_names, term_limit, child_depth)?;
            for coefficient in polynomial.values_mut() {
                *coefficient = -*coefficient;
            }
            Ok(polynomial)
        }
    }
}

fn base_constant(value: BaseField, variable_count: usize) -> BasePolynomial {
    if value.is_zero() {
        BasePolynomial::new()
    } else {
        BTreeMap::from([(vec![0; variable_count], value)])
    }
}

fn ext_constant(value: SecureField, variable_count: usize) -> ExtPolynomial {
    if value.is_zero() {
        ExtPolynomial::new()
    } else {
        BTreeMap::from([(vec![0; variable_count], value)])
    }
}

fn add_base_polynomials(
    mut left: BasePolynomial,
    right: BasePolynomial,
    subtract: bool,
    term_limit: usize,
) -> Result<BasePolynomial, String> {
    for (monomial, coefficient) in right {
        let coefficient = if subtract { -coefficient } else { coefficient };
        *left.entry(monomial).or_default() += coefficient;
        enforce_term_limit(left.len(), term_limit)?;
    }
    left.retain(|_, coefficient| !coefficient.is_zero());
    Ok(left)
}

fn add_ext_polynomials(
    mut left: ExtPolynomial,
    right: ExtPolynomial,
    subtract: bool,
    term_limit: usize,
) -> Result<ExtPolynomial, String> {
    for (monomial, coefficient) in right {
        let coefficient = if subtract { -coefficient } else { coefficient };
        *left.entry(monomial).or_default() += coefficient;
        enforce_term_limit(left.len(), term_limit)?;
    }
    left.retain(|_, coefficient| !coefficient.is_zero());
    Ok(left)
}

fn multiply_base_polynomials(
    left: &BasePolynomial,
    right: &BasePolynomial,
    term_limit: usize,
) -> Result<BasePolynomial, String> {
    let mut product = BasePolynomial::new();
    for (left_monomial, left_coefficient) in left {
        for (right_monomial, right_coefficient) in right {
            let monomial = multiply_monomials(left_monomial, right_monomial)?;
            *product.entry(monomial).or_default() += *left_coefficient * *right_coefficient;
            enforce_term_limit(product.len(), term_limit)?;
        }
    }
    product.retain(|_, coefficient| !coefficient.is_zero());
    Ok(product)
}

fn multiply_ext_polynomials(
    left: &ExtPolynomial,
    right: &ExtPolynomial,
    term_limit: usize,
) -> Result<ExtPolynomial, String> {
    let mut product = ExtPolynomial::new();
    for (left_monomial, left_coefficient) in left {
        for (right_monomial, right_coefficient) in right {
            let monomial = multiply_monomials(left_monomial, right_monomial)?;
            *product.entry(monomial).or_default() += *left_coefficient * *right_coefficient;
            enforce_term_limit(product.len(), term_limit)?;
        }
    }
    product.retain(|_, coefficient| !coefficient.is_zero());
    Ok(product)
}

fn enforce_term_limit(term_count: usize, term_limit: usize) -> Result<(), String> {
    if term_count > term_limit {
        return Err(format!(
            "relation fingerprint exceeded {term_limit} polynomial terms"
        ));
    }
    Ok(())
}

fn fingerprint_child_depth(depth_remaining: usize) -> Result<usize, String> {
    depth_remaining.checked_sub(1).ok_or_else(|| {
        format!(
            "relation fingerprint expression exceeded depth limit {MAX_RELATION_FINGERPRINT_DEPTH}"
        )
    })
}

fn multiply_monomials(left: &Monomial, right: &Monomial) -> Result<Monomial, String> {
    left.iter()
        .zip(right)
        .map(|(left, right)| {
            left.checked_add(*right)
                .ok_or_else(|| "relation fingerprint monomial degree overflow".into())
        })
        .collect()
}

impl EvalAtRow for AuditEvaluator {
    type F = BaseExpr;
    type EF = ExtExpr;

    fn next_interaction_mask<const N: usize>(
        &mut self,
        interaction: usize,
        offsets: [isize; N],
    ) -> [Self::F; N] {
        let column_index = self
            .column_index_per_interaction
            .entry(interaction)
            .or_default();
        let current_column = *column_index;
        *column_index += 1;
        self.mask_offsets_per_interaction
            .entry(interaction)
            .or_default()
            .push(offsets.to_vec());
        std::array::from_fn(|i| {
            let col = ColumnExpr::from((interaction, current_column, offsets[i]));
            BaseExpr::Col(col)
        })
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
            return;
        }
        self.relations.push(RawRelationEntry {
            relation_name: entry.relation().get_name().to_string(),
            values: entry.values().to_vec(),
            multiplicity: entry.multiplicity().clone(),
            source: format!("{}:add_to_relation", entry.relation().get_name()),
        });

        let combined = self.combine_formal(entry.relation(), entry.values());
        let frac = Fraction::new(entry.multiplicity().clone(), combined);
        self.push_relation_fraction(frac);
    }

    fn get_preprocessed_column(&mut self, column: PreProcessedColumnId) -> Self::F {
        self.preprocessed_columns.push(column.clone());
        BaseExpr::Param(column.id)
    }

    fn next_trace_mask(&mut self) -> Self::F {
        let [mask_item] = self.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]);
        mask_item
    }

    fn write_logup_frac(&mut self, _fraction: Fraction<Self::EF, Self::EF>) {
        if self.logup_finalized {
            self.structural_errors
                .push("write_logup_frac called after LogUp was finalized".into());
            return;
        }
        self.structural_errors.push(
            "direct write_logup_frac is unsupported because it bypasses uncompressed relation capture; use add_to_relation"
                .into(),
        );
    }

    fn finalize_logup_batched(&mut self, batch_size: usize) {
        if batch_size == 0 {
            self.structural_errors
                .push("finalize_logup_batched called with batch_size 0".into());
            return;
        }
        if self.logup_finalized {
            self.structural_errors
                .push("LogUp finalization was called more than once".into());
            return;
        }
        self.logup_finalized = true;
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
    }

    fn finalize_logup(&mut self) {
        self.finalize_logup_batched(1);
    }

    fn finalize_logup_in_pairs(&mut self) {
        self.finalize_logup_batched(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn additive_polynomial_merges_enforce_the_term_limit() {
        let left_base = BTreeMap::from([
            (vec![1, 0, 0], BaseField::one()),
            (vec![0, 1, 0], BaseField::one()),
        ]);
        let right_base = BTreeMap::from([(vec![0, 0, 1], BaseField::one())]);
        assert_eq!(
            add_base_polynomials(left_base, right_base, false, 2).unwrap_err(),
            "relation fingerprint exceeded 2 polynomial terms"
        );

        let left_ext = BTreeMap::from([
            (vec![1, 0, 0], SecureField::one()),
            (vec![0, 1, 0], SecureField::one()),
        ]);
        let right_ext = BTreeMap::from([(vec![0, 0, 1], SecureField::one())]);
        assert_eq!(
            add_ext_polynomials(left_ext, right_ext, false, 2).unwrap_err(),
            "relation fingerprint exceeded 2 polynomial terms"
        );
    }

    #[test]
    fn secure_column_union_enforces_the_term_limit() {
        let expression = ExtExpr::SecureCol([
            Box::new(BaseExpr::Param("x".into())),
            Box::new(BaseExpr::Param("y".into())),
            Box::new(BaseExpr::Param("z".into())),
            Box::new(BaseExpr::zero()),
        ]);
        let variables = vec!["x".into(), "y".into(), "z".into()];
        assert_eq!(
            normalize_ext_polynomial(&expression, &variables, 2).unwrap_err(),
            "relation fingerprint exceeded 2 polynomial terms"
        );
    }

    #[test]
    fn polynomial_normalization_enforces_the_depth_limit() {
        let mut expression = BaseExpr::Param("x".into());
        for _ in 0..MAX_RELATION_FINGERPRINT_DEPTH {
            expression = BaseExpr::Neg(Box::new(expression));
        }
        assert_eq!(
            normalize_base_polynomial_bounded(
                &expression,
                &["x".into()],
                MAX_RELATION_FINGERPRINT_TERMS,
                MAX_RELATION_FINGERPRINT_DEPTH,
            )
            .unwrap_err(),
            "relation fingerprint expression exceeded depth limit 128"
        );
    }
}
