//! Convert Stwo symbolic expressions into AuditIR expressions.

use std::collections::HashSet;

use airlock_ir::{BaseExpr as IrBase, ExtExpr as IrExt};
use num_traits::Zero;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::expr::{BaseExpr as StwoBase, ExtExpr as StwoExt};

/// Conversion failure (malformed ids, lossy multiplicity projection, etc.).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ConvertError(pub String);

/// Convert a Stwo base expression into AuditIR.
///
/// When `preprocessed_ids` contains a name, Stwo `Param(name)` (used for
/// preprocessed columns) is rewritten to `Column { id, offset: 0 }` so formal
/// parameters and preprocessed columns do not share a namespace in AuditIR.
pub fn convert_base(
    expr: &StwoBase,
    preprocessed_ids: &HashSet<String>,
) -> Result<IrBase, ConvertError> {
    match expr {
        StwoBase::Col(_) => {
            // ColumnExpr fields are crate-private; reuse Stwo's stable format_expr id.
            let formatted = expr.format_expr();
            let (id, offset) = split_column_id_and_offset(&formatted)?;
            Ok(IrBase::Column { offset, id })
        }
        StwoBase::Const(value) => Ok(IrBase::Const {
            value: base_field_u32(*value),
        }),
        StwoBase::Param(name) => {
            if preprocessed_ids.contains(name) {
                Ok(IrBase::Column {
                    id: name.clone(),
                    offset: 0,
                })
            } else {
                Ok(IrBase::param(name.clone()))
            }
        }
        StwoBase::Add(lhs, rhs) => Ok(IrBase::Add {
            lhs: Box::new(convert_base(lhs, preprocessed_ids)?),
            rhs: Box::new(convert_base(rhs, preprocessed_ids)?),
        }),
        StwoBase::Sub(lhs, rhs) => Ok(IrBase::Add {
            lhs: Box::new(convert_base(lhs, preprocessed_ids)?),
            rhs: Box::new(IrBase::Neg {
                inner: Box::new(convert_base(rhs, preprocessed_ids)?),
            }),
        }),
        StwoBase::Mul(lhs, rhs) => Ok(IrBase::Mul {
            lhs: Box::new(convert_base(lhs, preprocessed_ids)?),
            rhs: Box::new(convert_base(rhs, preprocessed_ids)?),
        }),
        StwoBase::Neg(inner) => Ok(IrBase::Neg {
            inner: Box::new(convert_base(inner, preprocessed_ids)?),
        }),
        StwoBase::Inv(inner) => Ok(IrBase::Inv {
            inner: Box::new(convert_base(inner, preprocessed_ids)?),
        }),
    }
}

/// Convert a Stwo extension expression into AuditIR.
pub fn convert_ext(
    expr: &StwoExt,
    preprocessed_ids: &HashSet<String>,
) -> Result<IrExt, ConvertError> {
    match expr {
        StwoExt::Param(name) => Ok(IrExt::Param { name: name.clone() }),
        StwoExt::Const(value) => Ok(IrExt::Const {
            limbs: secure_field_limbs(*value),
        }),
        StwoExt::SecureCol(parts) => Ok(IrExt::SecureCol {
            parts: [
                convert_base(&parts[0], preprocessed_ids)?,
                convert_base(&parts[1], preprocessed_ids)?,
                convert_base(&parts[2], preprocessed_ids)?,
                convert_base(&parts[3], preprocessed_ids)?,
            ],
        }),
        StwoExt::Add(lhs, rhs) => Ok(IrExt::Add {
            lhs: Box::new(convert_ext(lhs, preprocessed_ids)?),
            rhs: Box::new(convert_ext(rhs, preprocessed_ids)?),
        }),
        StwoExt::Sub(lhs, rhs) => Ok(IrExt::Add {
            lhs: Box::new(convert_ext(lhs, preprocessed_ids)?),
            rhs: Box::new(IrExt::Neg {
                inner: Box::new(convert_ext(rhs, preprocessed_ids)?),
            }),
        }),
        StwoExt::Mul(lhs, rhs) => Ok(IrExt::Mul {
            lhs: Box::new(convert_ext(lhs, preprocessed_ids)?),
            rhs: Box::new(convert_ext(rhs, preprocessed_ids)?),
        }),
        StwoExt::Neg(inner) => Ok(IrExt::Neg {
            inner: Box::new(convert_ext(inner, preprocessed_ids)?),
        }),
    }
}

/// Best-effort multiplicity as a base expression for AuditIR relation entries.
///
/// Stwo lifts base multiplicities to `SecureCol([m, 0, 0, 0])`. When higher
/// limbs are non-zero constants or non-trivial expressions, conversion fails
/// closed rather than silently dropping limbs.
pub fn multiplicity_as_base(
    expr: &StwoExt,
    preprocessed_ids: &HashSet<String>,
) -> Result<IrBase, ConvertError> {
    match expr {
        StwoExt::SecureCol(parts) => {
            ensure_secure_col_is_base_lift(parts)?;
            convert_base(&parts[0], preprocessed_ids)
        }
        StwoExt::Param(name) => Ok(IrBase::param(name.clone())),
        StwoExt::Neg(inner) => Ok(IrBase::Neg {
            inner: Box::new(multiplicity_as_base(inner, preprocessed_ids)?),
        }),
        StwoExt::Const(value) => {
            let limbs = secure_field_limbs(*value);
            if limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0 {
                Ok(IrBase::Const { value: limbs[0] })
            } else {
                Err(ConvertError(format!(
                    "multiplicity QM31 const has non-zero higher limbs {limbs:?}"
                )))
            }
        }
        other => Err(ConvertError(format!(
            "cannot project multiplicity expression `{}` to a base field value",
            other.format_expr()
        ))),
    }
}

fn ensure_secure_col_is_base_lift(parts: &[Box<StwoBase>; 4]) -> Result<(), ConvertError> {
    for (i, part) in parts.iter().enumerate().skip(1) {
        match part.as_ref() {
            StwoBase::Const(v) if v.is_zero() => {}
            other => {
                return Err(ConvertError(format!(
                    "multiplicity SecureCol limb {i} is `{}`, expected zero const",
                    other.format_expr()
                )));
            }
        }
    }
    Ok(())
}

fn base_field_u32(value: BaseField) -> u32 {
    value.0
}

fn secure_field_limbs(value: SecureField) -> [u32; 4] {
    let [a, b, c, d] = value.to_m31_array();
    [a.0, b.0, c.0, d.0]
}

/// Split Stwo `trace_{i}_column_{j}_offset_{k|neg_k}` into stable column id + offset.
fn split_column_id_and_offset(formatted: &str) -> Result<(String, i32), ConvertError> {
    let Some((id, offset_str)) = formatted.split_once("_offset_") else {
        return Err(ConvertError(format!(
            "column format id `{formatted}` missing `_offset_` segment"
        )));
    };
    if id.is_empty() {
        return Err(ConvertError(format!(
            "column format id `{formatted}` has empty id prefix"
        )));
    }
    let offset = if let Some(rest) = offset_str.strip_prefix("neg_") {
        -rest.parse::<i32>().map_err(|_| {
            ConvertError(format!(
                "column format id `{formatted}` has unparsable neg offset `{rest}`"
            ))
        })?
    } else {
        offset_str.parse::<i32>().map_err(|_| {
            ConvertError(format!(
                "column format id `{formatted}` has unparsable offset `{offset_str}`"
            ))
        })?
    };
    Ok((id.to_string(), offset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::Zero;
    use stwo_constraint_framework::expr::ColumnExpr;

    #[test]
    fn converts_column_id_without_offset_suffix() {
        let col = ColumnExpr::from((1usize, 2usize, -1isize));
        let expr = StwoBase::Col(col);
        let ir = convert_base(&expr, &HashSet::new()).unwrap();
        match ir {
            IrBase::Column { id, offset } => {
                assert_eq!(id, "trace_1_column_2");
                assert_eq!(offset, -1);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn rewrites_preprocessed_param_to_column() {
        let mut prep = HashSet::new();
        prep.insert("table_code".into());
        assert_eq!(
            convert_base(&StwoBase::Param("table_code".into()), &prep).unwrap(),
            IrBase::Column {
                id: "table_code".into(),
                offset: 0
            }
        );
        assert_eq!(
            convert_base(&StwoBase::Param("claimed_sum".into()), &prep).unwrap(),
            IrBase::param("claimed_sum")
        );
    }

    #[test]
    fn converts_secure_col_and_const_ext() {
        let parts = [
            Box::new(StwoBase::Param("a".into())),
            Box::new(StwoBase::Const(BaseField::zero())),
            Box::new(StwoBase::Const(BaseField::zero())),
            Box::new(StwoBase::Const(BaseField::zero())),
        ];
        let ir = convert_ext(&StwoExt::SecureCol(parts), &HashSet::new()).unwrap();
        match ir {
            IrExt::SecureCol { parts } => {
                assert_eq!(parts[0], IrBase::param("a"));
                assert_eq!(parts[1], IrBase::Const { value: 0 });
            }
            other => panic!("unexpected {other:?}"),
        }

        let const_ir = convert_ext(
            &StwoExt::Const(SecureField::from_u32_unchecked(1, 2, 3, 4)),
            &HashSet::new(),
        )
        .unwrap();
        assert_eq!(
            const_ir,
            IrExt::Const {
                limbs: [1, 2, 3, 4]
            }
        );
    }

    #[test]
    fn multiplicity_rejects_nonzero_higher_limbs() {
        let parts = [
            Box::new(StwoBase::Param("m".into())),
            Box::new(StwoBase::Const(BaseField::from(1u32))),
            Box::new(StwoBase::Const(BaseField::zero())),
            Box::new(StwoBase::Const(BaseField::zero())),
        ];
        let err = multiplicity_as_base(&StwoExt::SecureCol(parts), &HashSet::new()).unwrap_err();
        assert!(err.to_string().contains("limb 1"), "{err}");
    }

    #[test]
    fn offset_parse_fails_closed() {
        let err = split_column_id_and_offset("trace_1_column_2").unwrap_err();
        assert!(err.to_string().contains("_offset_"), "{err}");
        let err = split_column_id_and_offset("trace_1_column_2_offset_neg_x").unwrap_err();
        assert!(err.to_string().contains("unparsable"), "{err}");
    }
}
