//! Fail-closed structural checks for hand-authored and exported AuditIR.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use airlock_ir::{
    BaseExpr, ColumnKind, CommitmentPhase, ComponentManifest, ExtExpr, Finding, FindingCode,
    ParameterRole, RowSupport, STWO_MAX_CIRCLE_DOMAIN_LOG_SIZE, STWO_MIN_CIRCLE_DOMAIN_LOG_SIZE,
    SemanticType, Severity,
};

/// Reject inconsistent component domains, column reads, row supports, and
/// preprocessed-data declarations before semantic lints consume them.
pub fn lint_component_structure(component: &ComponentManifest) -> Vec<Finding> {
    let mut findings = Vec::new();

    if component.name.trim().is_empty() {
        findings.push(structure_finding(
            component,
            FindingCode::InvalidManifestStructure,
            "component name must not be empty",
            vec![],
        ));
    }
    let has_nontrivial_constraint = component.constraints.iter().any(|constraint| {
        matches!(
            eval_ext_constant(&constraint.expression),
            StaticEval::Dynamic
        )
    });
    let has_nontrivial_relation =
        component.relations.iter().any(|relation| {
            match eval_base_constant(&relation.multiplicity) {
                StaticEval::Dynamic => true,
                StaticEval::Value(value) => value != 0,
                StaticEval::Undefined => false,
            }
        });
    if !has_nontrivial_constraint && !has_nontrivial_relation {
        findings.push(structure_finding(
            component,
            FindingCode::InvalidManifestStructure,
            "component emits no syntactically nontrivial constraint or relation entry",
            vec![component.name.clone()],
        ));
    }

    match 1u64.checked_shl(component.log_size) {
        Some(expected) if expected == component.domain_size => {}
        Some(expected) => findings.push(structure_finding(
            component,
            FindingCode::InvalidManifestStructure,
            format!(
                "domain_size {} does not equal 1 << log_size ({expected})",
                component.domain_size
            ),
            vec![component.name.clone()],
        )),
        None => findings.push(structure_finding(
            component,
            FindingCode::InvalidManifestStructure,
            format!(
                "log_size {} cannot be represented by u64",
                component.log_size
            ),
            vec![component.name.clone()],
        )),
    }
    if !(STWO_MIN_CIRCLE_DOMAIN_LOG_SIZE..=STWO_MAX_CIRCLE_DOMAIN_LOG_SIZE)
        .contains(&component.log_size)
    {
        findings.push(structure_finding(
            component,
            FindingCode::InvalidManifestStructure,
            format!(
                "log_size {} is outside Stwo CircleDomain range [{STWO_MIN_CIRCLE_DOMAIN_LOG_SIZE}, {STWO_MAX_CIRCLE_DOMAIN_LOG_SIZE}]",
                component.log_size
            ),
            vec![component.name.clone()],
        ));
    }

    let mut columns = BTreeMap::new();
    for column in &component.columns {
        if column.id.trim().is_empty() {
            findings.push(structure_finding(
                component,
                FindingCode::InvalidColumnContract,
                "column id must not be empty",
                vec![],
            ));
            continue;
        }
        if columns.insert(column.id.as_str(), column).is_some() {
            findings.push(structure_finding(
                component,
                FindingCode::InvalidColumnContract,
                format!("column `{}` is declared more than once", column.id),
                vec![column.id.clone()],
            ));
        }

        let mut offsets = BTreeSet::new();
        if column.offsets.is_empty() {
            findings.push(structure_finding(
                component,
                FindingCode::InvalidColumnContract,
                format!("column `{}` declares no mask offsets", column.id),
                vec![column.id.clone()],
            ));
        }
        for offset in &column.offsets {
            if !offsets.insert(*offset) {
                findings.push(structure_finding(
                    component,
                    FindingCode::InvalidColumnContract,
                    format!("column `{}` repeats offset {offset}", column.id),
                    vec![column.id.clone()],
                ));
            }
        }
        if let Some((lo, hi)) = column.declared_range
            && lo > hi
        {
            findings.push(structure_finding(
                component,
                FindingCode::InvalidColumnContract,
                format!(
                    "column `{}` declares reversed range [{lo}, {hi}]",
                    column.id
                ),
                vec![column.id.clone()],
            ));
        }
        if let Some(support) = &column.declared_support {
            validate_support(
                component,
                support,
                &format!("column `{}`", column.id),
                &mut findings,
            );
        }

        let (expected_phase, expected_interaction) = match column.kind {
            ColumnKind::Preprocessed => (CommitmentPhase::Phase0Public, 0),
            ColumnKind::Witness => (CommitmentPhase::Phase1Original, 1),
            ColumnKind::Interaction => (CommitmentPhase::Phase2Interaction, 2),
        };
        if column.commitment_phase != expected_phase {
            findings.push(structure_finding(
                component,
                FindingCode::InvalidColumnContract,
                format!(
                    "column `{}` has kind {:?} but phase {:?}; expected {:?}",
                    column.id, column.kind, column.commitment_phase, expected_phase
                ),
                vec![column.id.clone()],
            ));
        }
        if let Some(interaction) = column.interaction
            && interaction != expected_interaction
        {
            findings.push(structure_finding(
                component,
                FindingCode::InvalidColumnContract,
                format!(
                    "column `{}` has kind {:?} but interaction {}; expected {}",
                    column.id, column.kind, interaction, expected_interaction
                ),
                vec![column.id.clone()],
            ));
        }
    }

    let mut constraint_ids = BTreeSet::new();
    let mut reads = BTreeMap::<String, BTreeSet<i32>>::new();
    for constraint in &component.constraints {
        if constraint.id.trim().is_empty() || !constraint_ids.insert(constraint.id.as_str()) {
            findings.push(structure_finding(
                component,
                FindingCode::InvalidManifestStructure,
                format!(
                    "constraint id `{}` must be nonempty and unique",
                    constraint.id
                ),
                vec![constraint.id.clone()],
            ));
        }
        validate_support(
            component,
            &constraint.row_support,
            &format!("constraint `{}`", constraint.id),
            &mut findings,
        );
        match eval_ext_constant(&constraint.expression) {
            StaticEval::Value(limbs) if limbs.iter().any(|limb| *limb != 0) => {
                findings.push(structure_finding(
                    component,
                    FindingCode::InvalidManifestStructure,
                    format!(
                        "constraint `{}` is a constant nonzero expression and cannot be satisfied",
                        constraint.id
                    ),
                    vec![constraint.id.clone()],
                ));
            }
            StaticEval::Undefined => findings.push(structure_finding(
                component,
                FindingCode::InvalidManifestStructure,
                format!(
                    "constraint `{}` contains an undefined constant-field operation",
                    constraint.id
                ),
                vec![constraint.id.clone()],
            )),
            StaticEval::Dynamic | StaticEval::Value(_) => {}
        }
        validate_ext_constants(
            component,
            &constraint.expression,
            &format!("constraint `{}`", constraint.id),
            &mut findings,
        );
        collect_ext_reads(&constraint.expression, &mut reads);
    }

    let mut relation_contracts = BTreeMap::<&str, (usize, CommitmentPhase)>::new();
    for (index, relation) in component.relations.iter().enumerate() {
        let mut relation_reads = BTreeMap::<String, BTreeSet<i32>>::new();
        if relation.relation.trim().is_empty() || relation.tuple.is_empty() {
            findings.push(structure_finding(
                component,
                FindingCode::InvalidManifestStructure,
                format!("relation entry {index} must have a nonempty name and tuple"),
                vec![relation.relation.clone()],
            ));
        }
        if !relation.relation.trim().is_empty() && !relation.tuple.is_empty() {
            let contract = (relation.tuple.len(), relation.challenge_phase);
            match relation_contracts.get(relation.relation.as_str()) {
                Some(previous) if *previous != contract => {
                    findings.push(structure_finding(
                        component,
                        FindingCode::InvalidManifestStructure,
                        format!(
                            "relation `{}` disagrees with its earlier identity contract: arity/phase {:?} vs {:?}",
                            relation.relation, previous, contract
                        ),
                        vec![relation.relation.clone()],
                    ));
                }
                Some(_) => {}
                None => {
                    relation_contracts.insert(relation.relation.as_str(), contract);
                }
            }
        }
        if !matches!(
            relation.challenge_phase,
            CommitmentPhase::Phase2Interaction | CommitmentPhase::Phase3Reduction
        ) {
            findings.push(structure_finding(
                component,
                FindingCode::InvalidManifestStructure,
                format!(
                    "relation `{}` challenge phase {:?} occurs before the original trace commitment",
                    relation.relation, relation.challenge_phase
                ),
                vec![relation.relation.clone()],
            ));
        }
        validate_support(
            component,
            &relation.row_support,
            &format!("relation `{}`", relation.relation),
            &mut findings,
        );
        for value in &relation.tuple {
            if matches!(eval_base_constant(value), StaticEval::Undefined) {
                findings.push(structure_finding(
                    component,
                    FindingCode::InvalidManifestStructure,
                    format!(
                        "relation `{}` tuple contains an undefined constant-field operation",
                        relation.relation
                    ),
                    vec![relation.relation.clone()],
                ));
            }
            validate_base_constants(
                component,
                value,
                &format!("relation `{}` tuple", relation.relation),
                &mut findings,
            );
            collect_base_reads(value, &mut reads);
            collect_base_reads(value, &mut relation_reads);
        }
        validate_base_constants(
            component,
            &relation.multiplicity,
            &format!("relation `{}` multiplicity", relation.relation),
            &mut findings,
        );
        if matches!(
            eval_base_constant(&relation.multiplicity),
            StaticEval::Undefined
        ) {
            findings.push(structure_finding(
                component,
                FindingCode::InvalidManifestStructure,
                format!(
                    "relation `{}` multiplicity contains an undefined constant-field operation",
                    relation.relation
                ),
                vec![relation.relation.clone()],
            ));
        }
        collect_base_reads(&relation.multiplicity, &mut reads);
        collect_base_reads(&relation.multiplicity, &mut relation_reads);

        for id in relation_reads.keys() {
            let Some(column) = columns.get(id.as_str()) else {
                continue;
            };
            if !column
                .commitment_phase
                .strictly_precedes(relation.challenge_phase)
            {
                findings.push(structure_finding(
                    component,
                    FindingCode::InvalidColumnContract,
                    format!(
                        "relation `{}` uses column `{id}` from phase {:?}, which is not committed before its {:?} challenge",
                        relation.relation, column.commitment_phase, relation.challenge_phase
                    ),
                    vec![relation.relation.clone(), id.clone()],
                ));
            }
        }
    }

    for (id, offsets) in reads {
        let Some(column) = columns.get(id.as_str()) else {
            findings.push(structure_finding(
                component,
                FindingCode::InvalidColumnContract,
                format!("expressions read undeclared column `{id}`"),
                vec![id],
            ));
            continue;
        };
        for offset in offsets {
            if !column.offsets.contains(&offset) {
                findings.push(structure_finding(
                    component,
                    FindingCode::InvalidColumnContract,
                    format!(
                        "expressions read column `{id}` at offset {offset}, absent from its mask declaration"
                    ),
                    vec![id.clone()],
                ));
            }
        }
    }

    validate_semantic_contract(component, &mut findings);

    findings
}

fn validate_semantic_contract(component: &ComponentManifest, findings: &mut Vec<Finding>) {
    let public_inputs = validate_contract_names(
        component,
        "public input",
        &component.contract.public_inputs,
        findings,
    );
    let public_outputs = validate_contract_names(
        component,
        "public output",
        &component.contract.public_outputs,
        findings,
    );

    for name in public_inputs.intersection(&public_outputs) {
        findings.push(structure_finding(
            component,
            FindingCode::InvalidManifestStructure,
            format!("public value `{name}` is declared as both an input and an output"),
            vec![name.to_string()],
        ));
    }

    for name in &public_inputs {
        let matching_parameters = component
            .parameters
            .iter()
            .filter(|parameter| {
                parameter.name == *name && parameter.role == ParameterRole::PublicInput
            })
            .count();
        let matching_columns = component
            .columns
            .iter()
            .filter(|column| {
                column.id == *name
                    && column.semantic_type == SemanticType::PublicInput
                    && column.commitment_phase == CommitmentPhase::Phase0Public
            })
            .count();
        if matching_parameters + matching_columns != 1 {
            findings.push(structure_finding(
                component,
                FindingCode::InvalidManifestStructure,
                format!(
                    "public input `{name}` must resolve to exactly one PublicInput parameter or Phase0Public column"
                ),
                vec![name.to_string()],
            ));
        }
    }

    for name in &public_outputs {
        let matching_columns = component
            .columns
            .iter()
            .filter(|column| {
                column.id == *name && column.semantic_type == SemanticType::PublicOutput
            })
            .count();
        if matching_columns != 1 {
            findings.push(structure_finding(
                component,
                FindingCode::InvalidManifestStructure,
                format!("public output `{name}` must resolve to exactly one PublicOutput column"),
                vec![name.to_string()],
            ));
        }
    }

    for parameter in &component.parameters {
        if parameter.role == ParameterRole::PublicInput
            && !public_inputs.contains(parameter.name.as_str())
        {
            findings.push(structure_finding(
                component,
                FindingCode::InvalidManifestStructure,
                format!(
                    "PublicInput parameter `{}` is omitted from the semantic contract",
                    parameter.name
                ),
                vec![parameter.name.clone()],
            ));
        }
    }
    for column in &component.columns {
        let (contract_names, label) = match column.semantic_type {
            SemanticType::PublicInput => (&public_inputs, "PublicInput"),
            SemanticType::PublicOutput => (&public_outputs, "PublicOutput"),
            _ => continue,
        };
        if !contract_names.contains(column.id.as_str()) {
            findings.push(structure_finding(
                component,
                FindingCode::InvalidManifestStructure,
                format!(
                    "{label} column `{}` is omitted from the semantic contract",
                    column.id
                ),
                vec![column.id.clone()],
            ));
        }
    }
}

fn validate_contract_names<'a>(
    component: &ComponentManifest,
    kind: &str,
    names: &'a [String],
    findings: &mut Vec<Finding>,
) -> BTreeSet<&'a str> {
    let mut unique = BTreeSet::new();
    for name in names {
        if name.trim().is_empty() {
            findings.push(structure_finding(
                component,
                FindingCode::InvalidManifestStructure,
                format!("{kind} names must not be empty"),
                vec![],
            ));
            continue;
        }
        if !unique.insert(name.as_str()) {
            findings.push(structure_finding(
                component,
                FindingCode::InvalidManifestStructure,
                format!("{kind} `{name}` appears more than once in the semantic contract"),
                vec![name.clone()],
            ));
        }
    }
    unique
}

fn validate_support(
    component: &ComponentManifest,
    support: &RowSupport,
    owner: &str,
    findings: &mut Vec<Finding>,
) {
    match support {
        RowSupport::All => {}
        RowSupport::Range { start, end } if *start < *end && *end <= component.domain_size => {}
        RowSupport::Range { start, end } => findings.push(structure_finding(
            component,
            FindingCode::InvalidRowSupport,
            format!(
                "{owner} has invalid support [{start}, {end}) for domain {}",
                component.domain_size
            ),
            vec![owner.to_string()],
        )),
        RowSupport::Classes { classes } => {
            let unique: HashSet<_> = classes.iter().collect();
            if classes.is_empty() || unique.len() != classes.len() {
                findings.push(structure_finding(
                    component,
                    FindingCode::InvalidRowSupport,
                    format!("{owner} row classes must be nonempty and unique"),
                    vec![owner.to_string()],
                ));
            }
        }
    }
}

fn collect_base_reads(expression: &BaseExpr, reads: &mut BTreeMap<String, BTreeSet<i32>>) {
    match expression {
        BaseExpr::Column { id, offset } => {
            reads.entry(id.clone()).or_default().insert(*offset);
        }
        BaseExpr::Add { lhs, rhs } | BaseExpr::Mul { lhs, rhs } => {
            collect_base_reads(lhs, reads);
            collect_base_reads(rhs, reads);
        }
        BaseExpr::Neg { inner } | BaseExpr::Inv { inner } => collect_base_reads(inner, reads),
        BaseExpr::Param { .. } | BaseExpr::Const { .. } => {}
    }
}

fn collect_ext_reads(expression: &ExtExpr, reads: &mut BTreeMap<String, BTreeSet<i32>>) {
    match expression {
        ExtExpr::SecureCol { parts } => {
            for part in parts {
                collect_base_reads(part, reads);
            }
        }
        ExtExpr::FromBase { inner } => collect_base_reads(inner, reads),
        ExtExpr::Add { lhs, rhs } | ExtExpr::Mul { lhs, rhs } => {
            collect_ext_reads(lhs, reads);
            collect_ext_reads(rhs, reads);
        }
        ExtExpr::Neg { inner } => collect_ext_reads(inner, reads),
        ExtExpr::Param { .. } | ExtExpr::Const { .. } => {}
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StaticEval<T> {
    Dynamic,
    Value(T),
    Undefined,
}

fn eval_base_constant(expression: &BaseExpr) -> StaticEval<u32> {
    match expression {
        BaseExpr::Param { .. } | BaseExpr::Column { .. } => StaticEval::Dynamic,
        BaseExpr::Const { value } => StaticEval::Value(*value % airlock_ir::M31_P),
        BaseExpr::Add { lhs, rhs } => match (eval_base_constant(lhs), eval_base_constant(rhs)) {
            (StaticEval::Undefined, _) | (_, StaticEval::Undefined) => StaticEval::Undefined,
            (StaticEval::Value(lhs), StaticEval::Value(rhs)) => {
                StaticEval::Value(m31_add(lhs, rhs))
            }
            _ => StaticEval::Dynamic,
        },
        BaseExpr::Mul { lhs, rhs } => match (eval_base_constant(lhs), eval_base_constant(rhs)) {
            (StaticEval::Undefined, _) | (_, StaticEval::Undefined) => StaticEval::Undefined,
            (StaticEval::Value(0), _) | (_, StaticEval::Value(0)) => StaticEval::Value(0),
            (StaticEval::Value(lhs), StaticEval::Value(rhs)) => {
                StaticEval::Value(m31_mul(lhs, rhs))
            }
            _ => StaticEval::Dynamic,
        },
        BaseExpr::Neg { inner } => match eval_base_constant(inner) {
            StaticEval::Value(value) => StaticEval::Value(m31_neg(value)),
            other => other,
        },
        BaseExpr::Inv { inner } => match eval_base_constant(inner) {
            StaticEval::Value(0) | StaticEval::Undefined => StaticEval::Undefined,
            StaticEval::Value(value) => {
                StaticEval::Value(m31_pow(value, u64::from(airlock_ir::M31_P) - 2))
            }
            StaticEval::Dynamic => StaticEval::Dynamic,
        },
    }
}

fn eval_ext_constant(expression: &ExtExpr) -> StaticEval<[u32; 4]> {
    match expression {
        ExtExpr::Param { .. } => StaticEval::Dynamic,
        ExtExpr::Const { limbs } => StaticEval::Value(limbs.map(|limb| limb % airlock_ir::M31_P)),
        ExtExpr::SecureCol { parts } => {
            let mut limbs = [0; 4];
            for (index, part) in parts.iter().enumerate() {
                match eval_base_constant(part) {
                    StaticEval::Value(value) => limbs[index] = value,
                    StaticEval::Dynamic => return StaticEval::Dynamic,
                    StaticEval::Undefined => return StaticEval::Undefined,
                }
            }
            StaticEval::Value(limbs)
        }
        ExtExpr::FromBase { inner } => match eval_base_constant(inner) {
            StaticEval::Value(value) => StaticEval::Value([value, 0, 0, 0]),
            StaticEval::Dynamic => StaticEval::Dynamic,
            StaticEval::Undefined => StaticEval::Undefined,
        },
        ExtExpr::Add { lhs, rhs } => match (eval_ext_constant(lhs), eval_ext_constant(rhs)) {
            (StaticEval::Undefined, _) | (_, StaticEval::Undefined) => StaticEval::Undefined,
            (StaticEval::Value(lhs), StaticEval::Value(rhs)) => {
                StaticEval::Value(qm31_add(lhs, rhs))
            }
            _ => StaticEval::Dynamic,
        },
        ExtExpr::Mul { lhs, rhs } => match (eval_ext_constant(lhs), eval_ext_constant(rhs)) {
            (StaticEval::Undefined, _) | (_, StaticEval::Undefined) => StaticEval::Undefined,
            (StaticEval::Value(lhs), _) if lhs == [0; 4] => StaticEval::Value([0; 4]),
            (_, StaticEval::Value(rhs)) if rhs == [0; 4] => StaticEval::Value([0; 4]),
            (StaticEval::Value(lhs), StaticEval::Value(rhs)) => {
                StaticEval::Value(qm31_mul(lhs, rhs))
            }
            _ => StaticEval::Dynamic,
        },
        ExtExpr::Neg { inner } => match eval_ext_constant(inner) {
            StaticEval::Value(value) => StaticEval::Value(value.map(m31_neg)),
            other => other,
        },
    }
}

fn m31_add(lhs: u32, rhs: u32) -> u32 {
    ((u64::from(lhs) + u64::from(rhs)) % u64::from(airlock_ir::M31_P)) as u32
}

fn m31_mul(lhs: u32, rhs: u32) -> u32 {
    ((u64::from(lhs) * u64::from(rhs)) % u64::from(airlock_ir::M31_P)) as u32
}

fn m31_neg(value: u32) -> u32 {
    if value == 0 {
        0
    } else {
        airlock_ir::M31_P - value
    }
}

fn m31_pow(mut base: u32, mut exponent: u64) -> u32 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = m31_mul(result, base);
        }
        base = m31_mul(base, base);
        exponent >>= 1;
    }
    result
}

fn cm31_add(lhs: (u32, u32), rhs: (u32, u32)) -> (u32, u32) {
    (m31_add(lhs.0, rhs.0), m31_add(lhs.1, rhs.1))
}

fn cm31_mul(lhs: (u32, u32), rhs: (u32, u32)) -> (u32, u32) {
    (
        m31_add(m31_mul(lhs.0, rhs.0), m31_neg(m31_mul(lhs.1, rhs.1))),
        m31_add(m31_mul(lhs.0, rhs.1), m31_mul(lhs.1, rhs.0)),
    )
}

fn qm31_add(lhs: [u32; 4], rhs: [u32; 4]) -> [u32; 4] {
    [
        m31_add(lhs[0], rhs[0]),
        m31_add(lhs[1], rhs[1]),
        m31_add(lhs[2], rhs[2]),
        m31_add(lhs[3], rhs[3]),
    ]
}

fn qm31_mul(lhs: [u32; 4], rhs: [u32; 4]) -> [u32; 4] {
    let lhs_0 = (lhs[0], lhs[1]);
    let lhs_1 = (lhs[2], lhs[3]);
    let rhs_0 = (rhs[0], rhs[1]);
    let rhs_1 = (rhs[2], rhs[3]);
    let out_0 = cm31_add(
        cm31_mul(lhs_0, rhs_0),
        cm31_mul((2, 1), cm31_mul(lhs_1, rhs_1)),
    );
    let out_1 = cm31_add(cm31_mul(lhs_0, rhs_1), cm31_mul(lhs_1, rhs_0));
    [out_0.0, out_0.1, out_1.0, out_1.1]
}

fn validate_base_constants(
    component: &ComponentManifest,
    expression: &BaseExpr,
    owner: &str,
    findings: &mut Vec<Finding>,
) {
    match expression {
        BaseExpr::Const { value } if *value >= airlock_ir::M31_P => {
            findings.push(structure_finding(
                component,
                FindingCode::InvalidManifestStructure,
                format!("{owner} contains noncanonical M31 constant {value}"),
                vec![owner.to_string()],
            ));
        }
        BaseExpr::Add { lhs, rhs } | BaseExpr::Mul { lhs, rhs } => {
            validate_base_constants(component, lhs, owner, findings);
            validate_base_constants(component, rhs, owner, findings);
        }
        BaseExpr::Neg { inner } | BaseExpr::Inv { inner } => {
            validate_base_constants(component, inner, owner, findings);
        }
        BaseExpr::Param { .. } | BaseExpr::Const { .. } | BaseExpr::Column { .. } => {}
    }
}

fn validate_ext_constants(
    component: &ComponentManifest,
    expression: &ExtExpr,
    owner: &str,
    findings: &mut Vec<Finding>,
) {
    match expression {
        ExtExpr::Const { limbs } if limbs.iter().any(|limb| *limb >= airlock_ir::M31_P) => {
            findings.push(structure_finding(
                component,
                FindingCode::InvalidManifestStructure,
                format!("{owner} contains a noncanonical QM31 constant limb"),
                vec![owner.to_string()],
            ));
        }
        ExtExpr::SecureCol { parts } => {
            for part in parts {
                validate_base_constants(component, part, owner, findings);
            }
        }
        ExtExpr::FromBase { inner } => {
            validate_base_constants(component, inner, owner, findings);
        }
        ExtExpr::Add { lhs, rhs } | ExtExpr::Mul { lhs, rhs } => {
            validate_ext_constants(component, lhs, owner, findings);
            validate_ext_constants(component, rhs, owner, findings);
        }
        ExtExpr::Neg { inner } => validate_ext_constants(component, inner, owner, findings),
        ExtExpr::Param { .. } | ExtExpr::Const { .. } => {}
    }
}

fn structure_finding(
    component: &ComponentManifest,
    code: FindingCode,
    message: impl Into<String>,
    related: Vec<String>,
) -> Finding {
    Finding {
        code,
        severity: Severity::High,
        component: Some(component.name.clone()),
        message: message.into(),
        related,
    }
}

#[cfg(test)]
mod tests {
    use super::{StaticEval, eval_base_constant, qm31_mul};
    use airlock_ir::BaseExpr;

    #[test]
    fn qm31_constant_arithmetic_matches_pinned_stwo_vector() {
        let p = airlock_ir::M31_P;
        assert_eq!(
            qm31_mul([1, 2, 3, 4], [4, 5, 6, 7]),
            [p - 71, 93, p - 16, 50]
        );
    }

    #[test]
    fn base_constant_inverse_is_exact_and_zero_is_undefined() {
        let inverse = BaseExpr::Inv {
            inner: Box::new(BaseExpr::constant(3)),
        };
        let StaticEval::Value(inverse) = eval_base_constant(&inverse) else {
            panic!("nonzero M31 constant must have an inverse");
        };
        assert_eq!(
            eval_base_constant(&BaseExpr::Mul {
                lhs: Box::new(BaseExpr::constant(3)),
                rhs: Box::new(BaseExpr::constant(inverse)),
            }),
            StaticEval::Value(1)
        );
        assert_eq!(
            eval_base_constant(&BaseExpr::Inv {
                inner: Box::new(BaseExpr::constant(0)),
            }),
            StaticEval::Undefined
        );
    }
}
