//! Formal-parameter closure checks for AuditIR expressions.

use std::collections::{BTreeMap, BTreeSet};

use airlock_ir::{BaseExpr, ComponentManifest, ExtExpr, FieldSort, Finding, FindingCode, Severity};

/// Reject manifests whose formal parameter declarations do not exactly close
/// every expression.
pub fn lint_parameter_contract(component: &ComponentManifest) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut declarations = BTreeMap::new();

    for declaration in &component.parameters {
        if declaration.name.is_empty() {
            findings.push(parameter_finding(
                component,
                "formal parameter names must not be empty",
                vec![],
            ));
            continue;
        }
        if declarations
            .insert(declaration.name.as_str(), declaration)
            .is_some()
        {
            findings.push(parameter_finding(
                component,
                format!(
                    "formal parameter `{}` is declared more than once",
                    declaration.name
                ),
                vec![declaration.name.clone()],
            ));
        }
    }

    let mut referenced = BTreeMap::new();
    let mut sort_conflicts = BTreeSet::new();
    for constraint in &component.constraints {
        collect_ext_parameters(&constraint.expression, &mut referenced, &mut sort_conflicts);
    }
    for relation in &component.relations {
        for value in &relation.tuple {
            collect_base_parameters(value, &mut referenced, &mut sort_conflicts);
        }
        collect_base_parameters(&relation.multiplicity, &mut referenced, &mut sort_conflicts);
    }

    for name in sort_conflicts {
        findings.push(parameter_finding(
            component,
            format!("formal parameter `{name}` is used as both M31 and QM31"),
            vec![name],
        ));
    }

    for (name, field) in &referenced {
        if is_generated_intermediate(name) {
            findings.push(parameter_finding(
                component,
                format!("generated intermediate `{name}` escaped into AuditIR"),
                vec![name.clone()],
            ));
        }

        match declarations.get(name.as_str()) {
            None => findings.push(parameter_finding(
                component,
                format!("formal parameter `{name}` has no declaration"),
                vec![name.clone()],
            )),
            Some(declaration) if declaration.field != *field => {
                findings.push(parameter_finding(
                    component,
                    format!(
                        "formal parameter `{name}` is used as {field:?} but declared as {:?}",
                        declaration.field
                    ),
                    vec![name.clone()],
                ));
            }
            Some(_) => {}
        }
    }

    for name in declarations.keys() {
        if !referenced.contains_key(*name) {
            findings.push(parameter_finding(
                component,
                format!("formal parameter `{name}` is declared but never referenced"),
                vec![(*name).to_string()],
            ));
        }
    }

    findings
}

fn is_generated_intermediate(name: &str) -> bool {
    name.strip_prefix("intermediate").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn collect_base_parameters(
    expression: &BaseExpr,
    referenced: &mut BTreeMap<String, FieldSort>,
    conflicts: &mut BTreeSet<String>,
) {
    match expression {
        BaseExpr::Param { name } => insert_reference(name, FieldSort::M31, referenced, conflicts),
        BaseExpr::Const { .. } | BaseExpr::Column { .. } => {}
        BaseExpr::Add { lhs, rhs } | BaseExpr::Mul { lhs, rhs } => {
            collect_base_parameters(lhs, referenced, conflicts);
            collect_base_parameters(rhs, referenced, conflicts);
        }
        BaseExpr::Neg { inner } | BaseExpr::Inv { inner } => {
            collect_base_parameters(inner, referenced, conflicts);
        }
    }
}

fn collect_ext_parameters(
    expression: &ExtExpr,
    referenced: &mut BTreeMap<String, FieldSort>,
    conflicts: &mut BTreeSet<String>,
) {
    match expression {
        ExtExpr::Param { name } => insert_reference(name, FieldSort::Qm31, referenced, conflicts),
        ExtExpr::Const { .. } => {}
        ExtExpr::SecureCol { parts } => {
            for part in parts {
                collect_base_parameters(part, referenced, conflicts);
            }
        }
        ExtExpr::FromBase { inner } => collect_base_parameters(inner, referenced, conflicts),
        ExtExpr::Add { lhs, rhs } | ExtExpr::Mul { lhs, rhs } => {
            collect_ext_parameters(lhs, referenced, conflicts);
            collect_ext_parameters(rhs, referenced, conflicts);
        }
        ExtExpr::Neg { inner } => collect_ext_parameters(inner, referenced, conflicts),
    }
}

fn insert_reference(
    name: &str,
    field: FieldSort,
    referenced: &mut BTreeMap<String, FieldSort>,
    conflicts: &mut BTreeSet<String>,
) {
    if let Some(existing) = referenced.insert(name.to_string(), field)
        && existing != field
    {
        conflicts.insert(name.to_string());
    }
}

fn parameter_finding(
    component: &ComponentManifest,
    message: impl Into<String>,
    related: Vec<String>,
) -> Finding {
    Finding {
        code: FindingCode::InvalidParameterContract,
        severity: Severity::High,
        component: Some(component.name.clone()),
        message: message.into(),
        related,
    }
}
