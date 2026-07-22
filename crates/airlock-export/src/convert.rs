//! Convert Stwo symbolic expressions into AuditIR expressions.

use airlock_ir::{BaseExpr as IrBase, ExtExpr as IrExt};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::expr::{BaseExpr as StwoBase, ExtExpr as StwoExt};

/// Convert a Stwo base expression into AuditIR.
pub fn convert_base(expr: &StwoBase) -> IrBase {
    match expr {
        StwoBase::Col(_) => {
            // ColumnExpr fields are crate-private; reuse Stwo's stable format_expr id.
            let id = expr.format_expr();
            IrBase::Column {
                offset: offset_from_formatted_id(&id),
                id,
            }
        }
        StwoBase::Const(value) => IrBase::Const {
            value: base_field_u32(*value),
        },
        StwoBase::Param(name) => IrBase::param(name.clone()),
        StwoBase::Add(lhs, rhs) => IrBase::Add {
            lhs: Box::new(convert_base(lhs)),
            rhs: Box::new(convert_base(rhs)),
        },
        StwoBase::Sub(lhs, rhs) => IrBase::Add {
            lhs: Box::new(convert_base(lhs)),
            rhs: Box::new(IrBase::Neg {
                inner: Box::new(convert_base(rhs)),
            }),
        },
        StwoBase::Mul(lhs, rhs) => IrBase::Mul {
            lhs: Box::new(convert_base(lhs)),
            rhs: Box::new(convert_base(rhs)),
        },
        StwoBase::Neg(inner) => IrBase::Neg {
            inner: Box::new(convert_base(inner)),
        },
        StwoBase::Inv(inner) => IrBase::Inv {
            inner: Box::new(convert_base(inner)),
        },
    }
}

/// Convert a Stwo extension expression into AuditIR (lossy for full QM31).
pub fn convert_ext(expr: &StwoExt) -> IrExt {
    match expr {
        StwoExt::Param(name) => IrExt::Param { name: name.clone() },
        StwoExt::Const(value) => IrExt::Param {
            name: format!("qm31_const_{value:?}"),
        },
        StwoExt::SecureCol(parts) => IrExt::FromBase {
            inner: convert_base(&parts[0]),
        },
        StwoExt::Add(lhs, rhs) => IrExt::Add {
            lhs: Box::new(convert_ext(lhs)),
            rhs: Box::new(convert_ext(rhs)),
        },
        StwoExt::Sub(lhs, rhs) => IrExt::Add {
            lhs: Box::new(convert_ext(lhs)),
            rhs: Box::new(IrExt::Neg {
                inner: Box::new(convert_ext(rhs)),
            }),
        },
        StwoExt::Mul(lhs, rhs) => IrExt::Mul {
            lhs: Box::new(convert_ext(lhs)),
            rhs: Box::new(convert_ext(rhs)),
        },
        StwoExt::Neg(inner) => IrExt::Neg {
            inner: Box::new(convert_ext(inner)),
        },
    }
}

/// Best-effort multiplicity as a base expression for AuditIR relation entries.
pub fn multiplicity_as_base(expr: &StwoExt) -> IrBase {
    match expr {
        StwoExt::SecureCol(parts) => convert_base(&parts[0]),
        StwoExt::Param(name) => IrBase::param(name.clone()),
        StwoExt::Neg(inner) => IrBase::Neg {
            inner: Box::new(multiplicity_as_base(inner)),
        },
        other => {
            // Fall back to Stwo's format string as a param name.
            IrBase::param(other.format_expr())
        }
    }
}

fn base_field_u32(value: BaseField) -> u32 {
    value.0
}

fn offset_from_formatted_id(id: &str) -> i32 {
    // trace_{i}_column_{j}_offset_{k|neg_k}
    let Some(offset_str) = id.split("_offset_").nth(1) else {
        return 0;
    };
    if let Some(rest) = offset_str.strip_prefix("neg_") {
        -rest.parse::<i32>().unwrap_or(0)
    } else {
        offset_str.parse::<i32>().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo_constraint_framework::expr::ColumnExpr;

    #[test]
    fn converts_column_and_param() {
        let col = ColumnExpr::from((1usize, 2usize, -1isize));
        let expr = StwoBase::Col(col);
        let ir = convert_base(&expr);
        match ir {
            IrBase::Column { id, offset } => {
                assert_eq!(id, "trace_1_column_2_offset_neg_1");
                assert_eq!(offset, -1);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            convert_base(&StwoBase::Param("table_code".into())),
            IrBase::param("table_code")
        );
    }
}
