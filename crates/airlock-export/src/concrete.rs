//! Concrete AuditIR evaluation for exporter-faithfulness checks.

use std::collections::{BTreeMap, BTreeSet};

use airlock_ir::{
    BaseExpr, ColumnKind, ComponentManifest, ExtExpr, FieldSort, M31_P, RelationRole, RowSupport,
    STWO_MAX_CIRCLE_DOMAIN_LOG_SIZE, STWO_MIN_CIRCLE_DOMAIN_LOG_SIZE, hash_u32_values,
};
use num_traits::Zero;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::utils::{
    bit_reverse_index, circle_domain_index_to_coset_index, coset_index_to_circle_domain_index,
};

/// Canonical concrete values supplied for one exported component.
///
/// Preprocessed values are deliberately absent: they come from the component
/// manifest and cannot be overridden by this assignment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConcreteAssignment {
    /// Prover or interaction columns keyed by AuditIR column id.
    pub columns: BTreeMap<String, Vec<u32>>,
    /// M31 formal parameters.
    pub base_parameters: BTreeMap<String, u32>,
    /// QM31 formal parameters in Stwo's four-coordinate representation.
    pub extension_parameters: BTreeMap<String, [u32; 4]>,
}

/// One concretely evaluated exported constraint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluatedConstraint {
    /// Constraint identity from the manifest.
    pub id: String,
    /// Bit-reversed Circle-domain row.
    pub row: usize,
    /// Canonical QM31 coordinates.
    pub value: [u32; 4],
}

/// One concretely evaluated uncompressed relation entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluatedRelation {
    /// Relation identity.
    pub relation: String,
    /// Table or query role.
    pub role: RelationRole,
    /// Bit-reversed Circle-domain row.
    pub row: usize,
    /// Canonical tuple values.
    pub tuple: Vec<u32>,
    /// Canonical M31 multiplicity.
    pub multiplicity: u32,
}

/// Evaluate every exported constraint on every row in its declared support.
pub fn evaluate_constraints(
    component: &ComponentManifest,
    assignment: &ConcreteAssignment,
) -> Result<Vec<EvaluatedConstraint>, ConcreteEvaluationError> {
    validate_assignment(component, assignment)?;
    let mut evaluated = Vec::new();
    for constraint in &component.constraints {
        for row in supported_rows(&constraint.row_support, component.domain_size)? {
            let value = eval_ext(component, assignment, &constraint.expression, row)?;
            evaluated.push(EvaluatedConstraint {
                id: constraint.id.clone(),
                row,
                value: secure_limbs(value),
            });
        }
    }
    Ok(evaluated)
}

/// Whether every concretely evaluated exported constraint is zero.
pub fn constraints_hold(
    component: &ComponentManifest,
    assignment: &ConcreteAssignment,
) -> Result<bool, ConcreteEvaluationError> {
    Ok(evaluate_constraints(component, assignment)?
        .iter()
        .all(|constraint| constraint.value == [0; 4]))
}

/// Evaluate every uncompressed relation entry on every physical row.
///
/// Relation row support is an obligation on multiplicity, not permission to
/// omit physical rows from exporter-faithfulness comparison.
pub fn evaluate_relations(
    component: &ComponentManifest,
    assignment: &ConcreteAssignment,
) -> Result<Vec<EvaluatedRelation>, ConcreteEvaluationError> {
    validate_assignment(component, assignment)?;
    let domain_size = domain_size(component)?;
    let mut evaluated = Vec::new();
    for relation in &component.relations {
        let support = supported_rows(&relation.row_support, component.domain_size)?;
        for row in 0..domain_size {
            let mut tuple = Vec::with_capacity(relation.tuple.len());
            for value in &relation.tuple {
                tuple.push(eval_base(component, assignment, value, row)?.0);
            }
            let multiplicity = eval_base(component, assignment, &relation.multiplicity, row)?;
            if !support.contains(&row) && !multiplicity.is_zero() {
                return Err(
                    ConcreteEvaluationError::RelationMultiplicityOutsideSupport {
                        relation: relation.relation.clone(),
                        row,
                        multiplicity: multiplicity.0,
                    },
                );
            }
            evaluated.push(EvaluatedRelation {
                relation: relation.relation.clone(),
                role: relation.role,
                row,
                tuple,
                multiplicity: multiplicity.0,
            });
        }
    }
    Ok(evaluated)
}

fn validate_assignment(
    component: &ComponentManifest,
    assignment: &ConcreteAssignment,
) -> Result<(), ConcreteEvaluationError> {
    let domain_size = domain_size(component)?;
    let mut declared_columns = BTreeSet::new();
    for column in &component.columns {
        if !declared_columns.insert(column.id.as_str()) {
            return Err(ConcreteEvaluationError::DuplicateColumn(column.id.clone()));
        }
    }
    let preprocessed_columns: BTreeSet<&str> = component
        .columns
        .iter()
        .filter(|column| column.kind == ColumnKind::Preprocessed)
        .map(|column| column.id.as_str())
        .collect();

    for id in assignment.columns.keys() {
        if !declared_columns.contains(id.as_str()) {
            return Err(ConcreteEvaluationError::UnknownColumn(id.clone()));
        }
        if preprocessed_columns.contains(id.as_str()) {
            return Err(ConcreteEvaluationError::PreprocessedOverride(id.clone()));
        }
    }

    let mut observed_preprocessed = BTreeSet::new();
    for preprocessed in &component.preprocessed {
        if !observed_preprocessed.insert(preprocessed.id.as_str()) {
            return Err(ConcreteEvaluationError::DuplicatePreprocessed(
                preprocessed.id.clone(),
            ));
        }
        let column = component
            .columns
            .iter()
            .find(|column| column.id == preprocessed.id)
            .ok_or_else(|| {
                ConcreteEvaluationError::UnexpectedPreprocessed(preprocessed.id.clone())
            })?;
        if column.kind != ColumnKind::Preprocessed {
            return Err(ConcreteEvaluationError::UnexpectedPreprocessed(
                preprocessed.id.clone(),
            ));
        }
        if preprocessed.physical_length != component.domain_size
            || preprocessed.semantic_length > preprocessed.physical_length
        {
            return Err(ConcreteEvaluationError::InvalidPreprocessedShape(
                preprocessed.id.clone(),
            ));
        }
        if let Some(values) = &preprocessed.values {
            let expected_hash = preprocessed.values_hash.as_ref().ok_or_else(|| {
                ConcreteEvaluationError::MissingPreprocessedHash(preprocessed.id.clone())
            })?;
            if &hash_u32_values(values) != expected_hash {
                return Err(ConcreteEvaluationError::PreprocessedHashMismatch(
                    preprocessed.id.clone(),
                ));
            }
        }
    }

    for column in &component.columns {
        match column.kind {
            ColumnKind::Preprocessed => {
                let values = component
                    .preprocessed
                    .iter()
                    .find(|preprocessed| preprocessed.id == column.id)
                    .and_then(|preprocessed| preprocessed.values.as_ref())
                    .ok_or_else(|| {
                        ConcreteEvaluationError::MissingPreprocessedValues(column.id.clone())
                    })?;
                validate_column_values(&column.id, values, domain_size)?;
            }
            ColumnKind::Witness | ColumnKind::Interaction => {
                let values = assignment
                    .columns
                    .get(&column.id)
                    .ok_or_else(|| ConcreteEvaluationError::MissingColumn(column.id.clone()))?;
                validate_column_values(&column.id, values, domain_size)?;
            }
        }
    }

    let mut declared_base = BTreeSet::new();
    let mut declared_extension = BTreeSet::new();
    let mut declared_parameters = BTreeSet::new();
    for parameter in &component.parameters {
        if !declared_parameters.insert(parameter.name.as_str()) {
            return Err(ConcreteEvaluationError::DuplicateParameter(
                parameter.name.clone(),
            ));
        }
        match parameter.field {
            FieldSort::M31 => {
                declared_base.insert(parameter.name.as_str());
                if assignment
                    .extension_parameters
                    .contains_key(&parameter.name)
                {
                    return Err(ConcreteEvaluationError::ParameterSortMismatch(
                        parameter.name.clone(),
                    ));
                }
                let value = assignment
                    .base_parameters
                    .get(&parameter.name)
                    .ok_or_else(|| {
                        ConcreteEvaluationError::MissingBaseParameter(parameter.name.clone())
                    })?;
                validate_canonical(&parameter.name, *value)?;
            }
            FieldSort::Qm31 => {
                declared_extension.insert(parameter.name.as_str());
                if assignment.base_parameters.contains_key(&parameter.name) {
                    return Err(ConcreteEvaluationError::ParameterSortMismatch(
                        parameter.name.clone(),
                    ));
                }
                let limbs = assignment
                    .extension_parameters
                    .get(&parameter.name)
                    .ok_or_else(|| {
                        ConcreteEvaluationError::MissingExtensionParameter(parameter.name.clone())
                    })?;
                for value in limbs {
                    validate_canonical(&parameter.name, *value)?;
                }
            }
        }
    }
    for name in assignment.base_parameters.keys() {
        if !declared_base.contains(name.as_str()) {
            return Err(ConcreteEvaluationError::UnknownBaseParameter(name.clone()));
        }
    }
    for name in assignment.extension_parameters.keys() {
        if !declared_extension.contains(name.as_str()) {
            return Err(ConcreteEvaluationError::UnknownExtensionParameter(
                name.clone(),
            ));
        }
    }
    Ok(())
}

fn validate_column_values(
    id: &str,
    values: &[u32],
    domain_size: usize,
) -> Result<(), ConcreteEvaluationError> {
    if values.len() != domain_size {
        return Err(ConcreteEvaluationError::ColumnLength {
            id: id.to_owned(),
            expected: domain_size,
            actual: values.len(),
        });
    }
    for value in values {
        validate_canonical(id, *value)?;
    }
    Ok(())
}

fn validate_canonical(label: &str, value: u32) -> Result<(), ConcreteEvaluationError> {
    if value >= M31_P {
        return Err(ConcreteEvaluationError::NoncanonicalM31 {
            label: label.to_owned(),
            value,
        });
    }
    Ok(())
}

fn domain_size(component: &ComponentManifest) -> Result<usize, ConcreteEvaluationError> {
    if !(STWO_MIN_CIRCLE_DOMAIN_LOG_SIZE..=STWO_MAX_CIRCLE_DOMAIN_LOG_SIZE)
        .contains(&component.log_size)
    {
        return Err(ConcreteEvaluationError::InvalidDomain {
            log_size: component.log_size,
            domain_size: component.domain_size,
        });
    }
    let expected =
        1u64.checked_shl(component.log_size)
            .ok_or(ConcreteEvaluationError::InvalidDomain {
                log_size: component.log_size,
                domain_size: component.domain_size,
            })?;
    if component.domain_size != expected {
        return Err(ConcreteEvaluationError::InvalidDomain {
            log_size: component.log_size,
            domain_size: component.domain_size,
        });
    }
    usize::try_from(expected).map_err(|_| ConcreteEvaluationError::InvalidDomain {
        log_size: component.log_size,
        domain_size: component.domain_size,
    })
}

fn supported_rows(
    support: &RowSupport,
    physical_size: u64,
) -> Result<std::ops::Range<usize>, ConcreteEvaluationError> {
    match support {
        RowSupport::All => Ok(0..usize::try_from(physical_size)
            .map_err(|_| ConcreteEvaluationError::InvalidRowSupport)?),
        RowSupport::Range { start, end } if start < end && *end <= physical_size => {
            let start =
                usize::try_from(*start).map_err(|_| ConcreteEvaluationError::InvalidRowSupport)?;
            let end =
                usize::try_from(*end).map_err(|_| ConcreteEvaluationError::InvalidRowSupport)?;
            Ok(start..end)
        }
        RowSupport::Range { .. } => Err(ConcreteEvaluationError::InvalidRowSupport),
        RowSupport::Classes { .. } => Err(ConcreteEvaluationError::UnsupportedRowClasses),
    }
}

fn eval_base(
    component: &ComponentManifest,
    assignment: &ConcreteAssignment,
    expression: &BaseExpr,
    row: usize,
) -> Result<BaseField, ConcreteEvaluationError> {
    match expression {
        BaseExpr::Param { name } => assignment
            .base_parameters
            .get(name)
            .copied()
            .map(BaseField::from)
            .ok_or_else(|| ConcreteEvaluationError::MissingBaseParameter(name.clone())),
        BaseExpr::Const { value } => {
            validate_canonical("constant", *value)?;
            Ok(BaseField::from(*value))
        }
        BaseExpr::Column { id, offset } => {
            let values = resolved_column(component, assignment, id)?;
            let index = offset_row(row, component.log_size, *offset);
            values
                .get(index)
                .copied()
                .map(BaseField::from)
                .ok_or_else(|| ConcreteEvaluationError::ColumnIndex {
                    id: id.clone(),
                    index,
                    len: values.len(),
                })
        }
        BaseExpr::Add { lhs, rhs } => Ok(eval_base(component, assignment, lhs, row)?
            + eval_base(component, assignment, rhs, row)?),
        BaseExpr::Mul { lhs, rhs } => Ok(eval_base(component, assignment, lhs, row)?
            * eval_base(component, assignment, rhs, row)?),
        BaseExpr::Neg { inner } => Ok(-eval_base(component, assignment, inner, row)?),
        BaseExpr::Inv { inner } => {
            let value = eval_base(component, assignment, inner, row)?;
            if value.is_zero() {
                return Err(ConcreteEvaluationError::UndefinedInverse);
            }
            Ok(value.inverse())
        }
    }
}

fn eval_ext(
    component: &ComponentManifest,
    assignment: &ConcreteAssignment,
    expression: &ExtExpr,
    row: usize,
) -> Result<SecureField, ConcreteEvaluationError> {
    match expression {
        ExtExpr::Param { name } => assignment
            .extension_parameters
            .get(name)
            .copied()
            .map(secure_from_limbs)
            .ok_or_else(|| ConcreteEvaluationError::MissingExtensionParameter(name.clone())),
        ExtExpr::Const { limbs } => {
            for value in limbs {
                validate_canonical("extension constant", *value)?;
            }
            Ok(secure_from_limbs(*limbs))
        }
        ExtExpr::SecureCol { parts } => {
            let mut values = [BaseField::zero(); 4];
            for (index, part) in parts.iter().enumerate() {
                values[index] = eval_base(component, assignment, part, row)?;
            }
            Ok(SecureField::from_m31_array(values))
        }
        ExtExpr::FromBase { inner } => Ok(eval_base(component, assignment, inner, row)?.into()),
        ExtExpr::Add { lhs, rhs } => {
            Ok(eval_ext(component, assignment, lhs, row)?
                + eval_ext(component, assignment, rhs, row)?)
        }
        ExtExpr::Mul { lhs, rhs } => {
            Ok(eval_ext(component, assignment, lhs, row)?
                * eval_ext(component, assignment, rhs, row)?)
        }
        ExtExpr::Neg { inner } => Ok(-eval_ext(component, assignment, inner, row)?),
    }
}

fn resolved_column<'a>(
    component: &'a ComponentManifest,
    assignment: &'a ConcreteAssignment,
    id: &str,
) -> Result<&'a [u32], ConcreteEvaluationError> {
    if let Some(column) = component.columns.iter().find(|column| column.id == id)
        && column.kind == ColumnKind::Preprocessed
    {
        return component
            .preprocessed
            .iter()
            .find(|preprocessed| preprocessed.id == id)
            .and_then(|preprocessed| preprocessed.values.as_deref())
            .ok_or_else(|| ConcreteEvaluationError::MissingPreprocessedValues(id.to_owned()));
    }
    assignment
        .columns
        .get(id)
        .map(Vec::as_slice)
        .ok_or_else(|| ConcreteEvaluationError::MissingColumn(id.to_owned()))
}

fn offset_row(row: usize, log_size: u32, offset: i32) -> usize {
    if offset == 0 {
        return row;
    }
    let domain_size = 1usize << log_size;
    let coset_index =
        circle_domain_index_to_coset_index(bit_reverse_index(row, log_size), log_size);
    let shifted =
        (coset_index as isize + offset as isize).rem_euclid(domain_size as isize) as usize;
    bit_reverse_index(
        coset_index_to_circle_domain_index(shifted, log_size),
        log_size,
    )
}

fn secure_from_limbs(limbs: [u32; 4]) -> SecureField {
    SecureField::from_m31_array(limbs.map(BaseField::from))
}

fn secure_limbs(value: SecureField) -> [u32; 4] {
    value.to_m31_array().map(|limb| limb.0)
}

/// Concrete assignment or expression evaluation failure.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConcreteEvaluationError {
    /// Component log size and physical size disagree.
    #[error("invalid component domain: log_size={log_size}, domain_size={domain_size}")]
    InvalidDomain {
        /// Declared log size.
        log_size: u32,
        /// Declared physical size.
        domain_size: u64,
    },
    /// A component declares one column id more than once.
    #[error("duplicate component column `{0}`")]
    DuplicateColumn(String),
    /// A component declares one formal parameter more than once.
    #[error("duplicate component parameter `{0}`")]
    DuplicateParameter(String),
    /// A component declares one preprocessed record more than once.
    #[error("duplicate preprocessed record `{0}`")]
    DuplicatePreprocessed(String),
    /// A preprocessed record does not resolve to a preprocessed column.
    #[error("unexpected preprocessed record `{0}`")]
    UnexpectedPreprocessed(String),
    /// Preprocessed semantic and physical lengths are inconsistent.
    #[error("invalid preprocessed shape for `{0}`")]
    InvalidPreprocessedShape(String),
    /// Concrete preprocessed values lack their required content hash.
    #[error("preprocessed column `{0}` has values without a content hash")]
    MissingPreprocessedHash(String),
    /// Concrete preprocessed values do not match their content hash.
    #[error("preprocessed column `{0}` values do not match its content hash")]
    PreprocessedHashMismatch(String),
    /// A supplied column is absent from the manifest.
    #[error("unknown concrete column `{0}`")]
    UnknownColumn(String),
    /// A required witness or interaction column is absent.
    #[error("missing concrete column `{0}`")]
    MissingColumn(String),
    /// Preprocessed values must come from the manifest.
    #[error("concrete assignment cannot override preprocessed column `{0}`")]
    PreprocessedOverride(String),
    /// A preprocessed column has no concrete values.
    #[error("preprocessed column `{0}` has no concrete values")]
    MissingPreprocessedValues(String),
    /// A concrete column length differs from the component domain.
    #[error("column `{id}` has length {actual}; expected {expected}")]
    ColumnLength {
        /// Column identity.
        id: String,
        /// Required physical length.
        expected: usize,
        /// Supplied length.
        actual: usize,
    },
    /// A row lookup escaped its validated column.
    #[error("column `{id}` index {index} is out of bounds for length {len}")]
    ColumnIndex {
        /// Column identity.
        id: String,
        /// Requested row index.
        index: usize,
        /// Physical column length.
        len: usize,
    },
    /// A field value is not a canonical M31 representative.
    #[error("noncanonical M31 value {value} for `{label}`")]
    NoncanonicalM31 {
        /// Value owner.
        label: String,
        /// Invalid representative.
        value: u32,
    },
    /// A required M31 parameter is absent.
    #[error("missing M31 parameter `{0}`")]
    MissingBaseParameter(String),
    /// A required QM31 parameter is absent.
    #[error("missing QM31 parameter `{0}`")]
    MissingExtensionParameter(String),
    /// A supplied M31 parameter is undeclared.
    #[error("unknown M31 parameter `{0}`")]
    UnknownBaseParameter(String),
    /// A supplied QM31 parameter is undeclared.
    #[error("unknown QM31 parameter `{0}`")]
    UnknownExtensionParameter(String),
    /// One parameter was supplied in the wrong field.
    #[error("parameter `{0}` was supplied in conflicting field maps")]
    ParameterSortMismatch(String),
    /// Inversion of zero is undefined.
    #[error("concrete AuditIR evaluation attempted to invert zero")]
    UndefinedInverse,
    /// A range support is malformed.
    #[error("invalid concrete row support")]
    InvalidRowSupport,
    /// Named row classes need a separately supplied row partition.
    #[error("named row classes are unsupported by concrete evaluation")]
    UnsupportedRowClasses,
    /// A relation's multiplicity is nonzero outside its declared row support.
    #[error(
        "relation `{relation}` has nonzero multiplicity {multiplicity} outside support at row {row}"
    )]
    RelationMultiplicityOutsideSupport {
        /// Relation identity.
        relation: String,
        /// Physical row.
        row: usize,
        /// Canonical M31 multiplicity.
        multiplicity: u32,
    },
}
