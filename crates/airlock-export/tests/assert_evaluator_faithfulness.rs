//! Differential exporter-faithfulness checks against Stwo's concrete evaluators.

use std::panic::{AssertUnwindSafe, catch_unwind};

use airlock_export::{
    ConcreteAssignment, ConcreteEvaluationError, ExportAnnotations, RelationAnnotation,
    RelationCompression, constraints_hold, evaluate_relations, export_component,
};
use airlock_ir::{
    ColumnKind, CommitmentPhase, FieldSort, M31_P, RelationRole, RowSupport, SemanticContract,
};
use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::TreeVec;
use stwo::core::utils::{
    bit_reverse_index, circle_domain_index_to_coset_index, coset_index_to_circle_domain_index,
};
use stwo::prover::backend::Column;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo_constraint_framework::logup::LookupElements;
use stwo_constraint_framework::relation_tracker::RelationTrackerEvaluator;
use stwo_constraint_framework::{
    AssertEvaluator, EvalAtRow, FrameworkEval, INTERACTION_TRACE_IDX, LogupTraceGenerator,
    ORIGINAL_TRACE_IDX, Relation, RelationEFTraitBound, RelationEntry, relation,
};

const LOG_SIZE: u32 = 4;
const DOMAIN_SIZE: usize = 1 << LOG_SIZE;

relation!(AuditPair, 2);

#[derive(Clone, Copy)]
struct CrossInteractionAir;

impl FrameworkEval for CrossInteractionAir {
    fn log_size(&self) -> u32 {
        LOG_SIZE
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        LOG_SIZE + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let [previous, current, next] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [-1, 0, 1]);
        let previous_copy = eval.next_trace_mask();
        let [interaction_value] = eval.next_extension_interaction_mask(INTERACTION_TRACE_IDX, [0]);

        eval.add_constraint(previous.clone() - previous_copy);
        let expected = E::combine_ef([current, previous, next, E::F::zero()]);
        eval.add_constraint(interaction_value - expected);
        eval
    }
}

#[derive(Clone, Copy)]
struct RelationAir;

impl FrameworkEval for RelationAir {
    fn log_size(&self) -> u32 {
        LOG_SIZE
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        LOG_SIZE + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let [previous, current] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [-1, 0]);
        let multiplicity = eval.next_trace_mask();
        eval.add_to_relation(RelationEntry::new(
            &AuditPair::dummy(),
            E::EF::from(multiplicity),
            &[previous, current],
        ));
        eval.finalize_logup();
        eval
    }
}

#[derive(Clone, Copy)]
struct NonGeometricRelation;

impl<F: Clone, EF: RelationEFTraitBound<F>> Relation<F, EF> for NonGeometricRelation {
    fn combine(&self, values: &[F]) -> EF {
        EF::from(values[0].clone()) + EF::from(values[0].clone()) * values[1].clone()
    }

    fn get_name(&self) -> &str {
        "NonGeometric"
    }

    fn get_size(&self) -> usize {
        2
    }
}

#[derive(Clone, Copy)]
struct NonGeometricRelationAir;

impl FrameworkEval for NonGeometricRelationAir {
    fn log_size(&self) -> u32 {
        LOG_SIZE
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        LOG_SIZE + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let [left, right] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 0]);
        eval.add_to_relation(RelationEntry::new(
            &NonGeometricRelation,
            E::EF::one(),
            &[left, right],
        ));
        eval.finalize_logup();
        eval
    }
}

#[derive(Clone)]
struct ConcreteTrace {
    trees: Vec<Vec<Vec<BaseField>>>,
}

impl ConcreteTrace {
    fn refs(&self) -> TreeVec<Vec<&Vec<BaseField>>> {
        TreeVec::new(
            self.trees
                .iter()
                .map(|tree| tree.iter().collect())
                .collect(),
        )
    }

    fn mutate(&mut self, interaction: usize, column: usize, row: usize, delta: u32) {
        let value = self.trees[interaction][column][row].0 as u64;
        self.trees[interaction][column][row] =
            BaseField::from(((value + u64::from(delta)) % u64::from(M31_P)) as u32);
    }
}

fn shift(values: &[BaseField], row: usize, offset: isize) -> BaseField {
    let coset_index =
        circle_domain_index_to_coset_index(bit_reverse_index(row, LOG_SIZE), LOG_SIZE);
    let shifted = (coset_index as isize + offset).rem_euclid(DOMAIN_SIZE as isize) as usize;
    let shifted_row = bit_reverse_index(
        coset_index_to_circle_domain_index(shifted, LOG_SIZE),
        LOG_SIZE,
    );
    values[shifted_row]
}

fn cross_interaction_trace() -> ConcreteTrace {
    let original = (0..DOMAIN_SIZE)
        .map(|row| BaseField::from((row as u32 * 17 + 3) % M31_P))
        .collect::<Vec<_>>();
    let previous = (0..DOMAIN_SIZE)
        .map(|row| shift(&original, row, -1))
        .collect::<Vec<_>>();
    let next = (0..DOMAIN_SIZE)
        .map(|row| shift(&original, row, 1))
        .collect::<Vec<_>>();
    ConcreteTrace {
        trees: vec![
            vec![],
            vec![original.clone(), previous.clone()],
            vec![
                original,
                previous,
                next,
                vec![BaseField::zero(); DOMAIN_SIZE],
            ],
        ],
    }
}

fn relation_trace() -> (ConcreteTrace, SecureField, LookupElements<2>) {
    let values = (0..DOMAIN_SIZE)
        .map(|row| BaseField::from((row as u32 * 29 + 11) % M31_P))
        .collect::<Vec<_>>();
    let previous = (0..DOMAIN_SIZE)
        .map(|row| shift(&values, row, -1))
        .collect::<Vec<_>>();
    let multiplicities = (0..DOMAIN_SIZE)
        .map(|row| BaseField::from((row as u32 * 7 + 1) % M31_P))
        .collect::<Vec<_>>();
    let lookup = LookupElements::<2>::dummy();

    let packed_values = BaseColumn::from_cpu(&values);
    let packed_previous = BaseColumn::from_cpu(&previous);
    let packed_multiplicities = BaseColumn::from_cpu(&multiplicities);
    let numerator = PackedSecureField::from(packed_multiplicities.data[0]);
    let denominator: PackedSecureField =
        lookup.combine(&[packed_previous.data[0], packed_values.data[0]]);
    assert!(!denominator.is_zero(), "test denominator");
    let mut generator = LogupTraceGenerator::new(LOG_SIZE);
    let mut column = generator.new_col();
    column.write_frac(0, numerator, denominator);
    column.finalize_col();
    let (interaction_evaluations, claimed_sum) = generator.finalize_last();
    let interaction = interaction_evaluations
        .into_iter()
        .map(|evaluation| evaluation.values.to_cpu())
        .collect();

    (
        ConcreteTrace {
            trees: vec![vec![], vec![values, multiplicities], interaction],
        },
        claimed_sum,
        lookup,
    )
}

fn default_annotations(name: &str) -> ExportAnnotations {
    ExportAnnotations {
        component_name: name.into(),
        contract: SemanticContract::default(),
        relations: indexmap::IndexMap::new(),
        preprocessed: indexmap::IndexMap::new(),
        column_semantics: indexmap::IndexMap::new(),
        parameters: indexmap::IndexMap::new(),
        witness_phase: CommitmentPhase::Phase1Original,
    }
}

fn assignment_from_trace(
    component: &airlock_ir::ComponentManifest,
    trace: &ConcreteTrace,
) -> ConcreteAssignment {
    let mut assignment = ConcreteAssignment::default();
    for column in &component.columns {
        if column.kind == ColumnKind::Preprocessed {
            continue;
        }
        let (interaction, column_index) =
            parse_trace_column(&column.id).expect("exported trace column id");
        assignment.columns.insert(
            column.id.clone(),
            trace.trees[interaction][column_index]
                .iter()
                .map(|value| value.0)
                .collect(),
        );
    }
    for parameter in &component.parameters {
        match parameter.field {
            FieldSort::M31 => {
                assignment.base_parameters.insert(parameter.name.clone(), 0);
            }
            FieldSort::Qm31 => {
                assignment
                    .extension_parameters
                    .insert(parameter.name.clone(), [0; 4]);
            }
        }
    }
    assignment
}

fn parse_trace_column(id: &str) -> Option<(usize, usize)> {
    let rest = id.strip_prefix("trace_")?;
    let (interaction, column) = rest.split_once("_column_")?;
    Some((interaction.parse().ok()?, column.parse().ok()?))
}

fn native_constraints_hold(air: CrossInteractionAir, trace: &ConcreteTrace) -> bool {
    let refs = trace.refs();
    catch_unwind(AssertUnwindSafe(|| {
        for row in 0..DOMAIN_SIZE {
            air.evaluate(AssertEvaluator::new(
                &refs,
                row,
                LOG_SIZE,
                SecureField::zero(),
            ));
        }
    }))
    .is_ok()
}

fn assert_native_relation_constraints_hold(
    air: RelationAir,
    trace: &ConcreteTrace,
    claimed_sum: SecureField,
) {
    let refs = trace.refs();
    for row in 0..DOMAIN_SIZE {
        air.evaluate(AssertEvaluator::new(&refs, row, LOG_SIZE, claimed_sum));
    }
}

fn bind_logup_parameters(
    assignment: &mut ConcreteAssignment,
    claimed_sum: SecureField,
    lookup: &LookupElements<2>,
) {
    assignment.extension_parameters.insert(
        "claimed_sum".into(),
        claimed_sum.to_m31_array().map(|value| value.0),
    );
    assignment.extension_parameters.insert(
        "AuditPair_z".into(),
        lookup.z.to_m31_array().map(|value| value.0),
    );
    assignment.extension_parameters.insert(
        "AuditPair_alpha".into(),
        lookup.alpha.to_m31_array().map(|value| value.0),
    );
}

#[test]
fn audit_ir_matches_assert_evaluator_on_honest_and_malicious_assignments() {
    let air = CrossInteractionAir;
    let manifest =
        export_component(&air, default_annotations("cross-interaction")).expect("export");
    let component = &manifest.components[0];
    let ids = component
        .columns
        .iter()
        .map(|column| column.id.as_str())
        .collect::<Vec<_>>();
    for expected in [
        "trace_1_column_0",
        "trace_1_column_1",
        "trace_2_column_0",
        "trace_2_column_1",
        "trace_2_column_2",
        "trace_2_column_3",
    ] {
        assert!(ids.contains(&expected), "missing local trace id {expected}");
    }
    assert!(!ids.contains(&"trace_2_column_4"));

    let honest = cross_interaction_trace();
    let honest_assignment = assignment_from_trace(component, &honest);
    assert!(native_constraints_hold(air, &honest));
    assert!(constraints_hold(component, &honest_assignment).expect("concrete evaluation"));

    let mut case = 0;
    for (interaction, column_count) in [(1, 2), (2, 4)] {
        for column in 0..column_count {
            for row in 0..DOMAIN_SIZE {
                let delta = 1 + (case as u32 * 65_537 % 1_000_003);
                let mut mutated = honest.clone();
                mutated.mutate(interaction, column, row, delta);
                let assignment = assignment_from_trace(component, &mutated);
                let native = native_constraints_hold(air, &mutated);
                let exported =
                    constraints_hold(component, &assignment).expect("concrete evaluation");
                assert_eq!(
                    exported, native,
                    "differential mismatch in mutation {case}: tree={interaction} column={column} row={row}"
                );
                assert!(
                    !native,
                    "mutation {case} unexpectedly preserved the relation"
                );
                case += 1;
            }
        }
    }
    assert_eq!(case, 96);
}

#[test]
fn exported_relations_match_relation_tracker_row_for_row() {
    let air = RelationAir;
    let mut annotations = default_annotations("relation-tracker");
    annotations.relations.insert(
        "AuditPair".into(),
        RelationAnnotation {
            compression: RelationCompression::StwoLookupElements,
            role: RelationRole::Query,
            row_support: RowSupport::All,
            challenge_phase: CommitmentPhase::Phase2Interaction,
        },
    );
    let manifest = export_component(&air, annotations).expect("export");
    let component = &manifest.components[0];

    let (trace, claimed_sum, lookup) = relation_trace();
    let mut assignment = assignment_from_trace(component, &trace);
    bind_logup_parameters(&mut assignment, claimed_sum, &lookup);
    let exported = evaluate_relations(component, &assignment).expect("relation evaluation");

    let refs = trace.refs();
    let mut native = Vec::new();
    for row in 0..DOMAIN_SIZE {
        native.extend(
            air.evaluate(RelationTrackerEvaluator::new(&refs, row, LOG_SIZE))
                .entries()
                .into_iter()
                .map(|entry| {
                    (
                        row,
                        entry.relation,
                        entry
                            .values
                            .into_iter()
                            .map(|value| value.0)
                            .collect::<Vec<_>>(),
                        entry.mult.0,
                    )
                }),
        );
    }

    assert_eq!(exported.len(), native.len());
    for (exported, (row, relation, tuple, multiplicity)) in exported.iter().zip(native) {
        assert_eq!(exported.row, row);
        assert_eq!(exported.relation, relation);
        assert_eq!(exported.role, RelationRole::Query);
        assert_eq!(exported.tuple, tuple);
        assert_eq!(exported.multiplicity, multiplicity);
    }
}

#[test]
fn exporter_rejects_custom_relation_compression_mislabeled_as_lookup_elements() {
    let mut annotations = default_annotations("non-geometric-relation");
    annotations.relations.insert(
        "NonGeometric".into(),
        RelationAnnotation {
            compression: RelationCompression::StwoLookupElements,
            role: RelationRole::Query,
            row_support: RowSupport::All,
            challenge_phase: CommitmentPhase::Phase2Interaction,
        },
    );

    let error = export_component(&NonGeometricRelationAir, annotations)
        .expect_err("custom relation compression must fail closed");
    assert!(
        error.to_string().contains(
            "does not match its declared StwoLookupElements compression: compression contains a non-affine or cross-term monomial"
        ),
        "{error}"
    );
}

#[test]
fn audit_ir_logup_lowering_accepts_native_trace_and_rejects_every_cell_mutation() {
    let air = RelationAir;
    let mut annotations = default_annotations("logup-lowering");
    annotations.relations.insert(
        "AuditPair".into(),
        RelationAnnotation {
            compression: RelationCompression::StwoLookupElements,
            role: RelationRole::Query,
            row_support: RowSupport::All,
            challenge_phase: CommitmentPhase::Phase2Interaction,
        },
    );
    let manifest = export_component(&air, annotations).expect("export");
    let component = &manifest.components[0];
    let (honest, claimed_sum, lookup) = relation_trace();
    let mut honest_assignment = assignment_from_trace(component, &honest);
    bind_logup_parameters(&mut honest_assignment, claimed_sum, &lookup);

    assert_native_relation_constraints_hold(air, &honest, claimed_sum);
    assert!(constraints_hold(component, &honest_assignment).expect("concrete evaluation"));

    let mut case = 0;
    for (interaction, column_count) in [(1, 2), (2, 4)] {
        for column in 0..column_count {
            for row in 0..DOMAIN_SIZE {
                let delta = 1 + (case as u32 * 131_071 % 1_000_003);
                let mut mutated = honest.clone();
                mutated.mutate(interaction, column, row, delta);
                let mut assignment = assignment_from_trace(component, &mutated);
                bind_logup_parameters(&mut assignment, claimed_sum, &lookup);
                let exported =
                    constraints_hold(component, &assignment).expect("concrete evaluation");
                assert!(
                    !exported,
                    "LogUp mutation {case} unexpectedly preserved the exported relation: tree={interaction} column={column} row={row}"
                );
                case += 1;
            }
        }
    }
    assert_eq!(case, 96);
}

#[test]
fn concrete_assignment_validation_fails_closed() {
    let manifest = export_component(
        &CrossInteractionAir,
        default_annotations("assignment-validation"),
    )
    .expect("export");
    let component = &manifest.components[0];
    let trace = cross_interaction_trace();
    let assignment = assignment_from_trace(component, &trace);

    let mut missing = assignment.clone();
    missing.columns.remove("trace_2_column_3");
    assert!(matches!(
        constraints_hold(component, &missing),
        Err(ConcreteEvaluationError::MissingColumn(id)) if id == "trace_2_column_3"
    ));

    let mut unknown = assignment.clone();
    unknown
        .columns
        .insert("trace_9_column_0".into(), vec![0; DOMAIN_SIZE]);
    assert!(matches!(
        constraints_hold(component, &unknown),
        Err(ConcreteEvaluationError::UnknownColumn(id)) if id == "trace_9_column_0"
    ));

    let mut short = assignment.clone();
    short
        .columns
        .get_mut("trace_1_column_0")
        .expect("column")
        .pop();
    assert!(matches!(
        constraints_hold(component, &short),
        Err(ConcreteEvaluationError::ColumnLength { .. })
    ));

    let mut noncanonical = assignment;
    noncanonical
        .columns
        .get_mut("trace_1_column_0")
        .expect("column")[0] = M31_P;
    assert!(matches!(
        constraints_hold(component, &noncanonical),
        Err(ConcreteEvaluationError::NoncanonicalM31 { .. })
    ));

    let assignment = assignment_from_trace(component, &trace);
    let mut duplicate_column = component.clone();
    duplicate_column.columns.push(component.columns[0].clone());
    assert!(matches!(
        constraints_hold(&duplicate_column, &assignment),
        Err(ConcreteEvaluationError::DuplicateColumn(_))
    ));

    let mut preprocessed_component = component.clone();
    let preprocessed_id = "trace_1_column_0";
    preprocessed_component
        .columns
        .iter_mut()
        .find(|column| column.id == preprocessed_id)
        .expect("column")
        .kind = ColumnKind::Preprocessed;
    let preprocessed_values = assignment
        .columns
        .get(preprocessed_id)
        .expect("column")
        .clone();
    preprocessed_component
        .preprocessed
        .push(airlock_ir::PreprocessedColumn {
            id: preprocessed_id.into(),
            semantic_length: DOMAIN_SIZE as u64,
            physical_length: DOMAIN_SIZE as u64,
            values_hash: Some(airlock_ir::hash_u32_values(&preprocessed_values)),
            values: Some(preprocessed_values),
            generator_id: None,
        });
    let mut preprocessed_assignment = assignment.clone();
    preprocessed_assignment.columns.remove(preprocessed_id);
    assert!(
        constraints_hold(&preprocessed_component, &preprocessed_assignment)
            .expect("preprocessed evaluation")
    );
    preprocessed_component.preprocessed[0]
        .values
        .as_mut()
        .expect("values")[0] += 1;
    assert!(matches!(
        constraints_hold(&preprocessed_component, &preprocessed_assignment),
        Err(ConcreteEvaluationError::PreprocessedHashMismatch(id)) if id == preprocessed_id
    ));

    let mut invalid_domain = component.clone();
    invalid_domain.log_size = 0;
    invalid_domain.domain_size = 1;
    assert!(matches!(
        constraints_hold(&invalid_domain, &ConcreteAssignment::default()),
        Err(ConcreteEvaluationError::InvalidDomain { .. })
    ));
}

#[test]
fn relation_parameters_are_required_even_for_uncompressed_entry_evaluation() {
    let mut annotations = default_annotations("relation-parameters");
    annotations.relations.insert(
        "AuditPair".into(),
        RelationAnnotation {
            compression: RelationCompression::StwoLookupElements,
            role: RelationRole::Query,
            row_support: RowSupport::All,
            challenge_phase: CommitmentPhase::Phase2Interaction,
        },
    );
    let manifest = export_component(&RelationAir, annotations).expect("export");
    let component = &manifest.components[0];
    let (trace, claimed_sum, lookup) = relation_trace();
    let mut assignment = assignment_from_trace(component, &trace);
    bind_logup_parameters(&mut assignment, claimed_sum, &lookup);

    let mut duplicate_parameter = component.clone();
    duplicate_parameter
        .parameters
        .push(component.parameters[0].clone());
    assert!(matches!(
        evaluate_relations(&duplicate_parameter, &assignment),
        Err(ConcreteEvaluationError::DuplicateParameter(_))
    ));

    assignment.extension_parameters.remove("AuditPair_z");
    assert!(matches!(
        evaluate_relations(component, &assignment),
        Err(ConcreteEvaluationError::MissingExtensionParameter(name)) if name == "AuditPair_z"
    ));

    let mut restricted = component.clone();
    restricted.relations[0].row_support = RowSupport::Range { start: 0, end: 1 };
    bind_logup_parameters(&mut assignment, claimed_sum, &lookup);
    assert!(matches!(
        evaluate_relations(&restricted, &assignment),
        Err(ConcreteEvaluationError::RelationMultiplicityOutsideSupport {
            relation,
            row: 1,
            ..
        }) if relation == "AuditPair"
    ));
}
