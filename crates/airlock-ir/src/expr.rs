//! Expression trees retained by AuditIR (pre-solver lowering).

use serde::{Deserialize, Serialize};

/// Which field an expression lives in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldSort {
    /// M31 base field.
    M31,
    /// QM31 extension (four M31 coordinates). Never model as prime-order FF.
    Qm31,
}

/// Base-field expression (M31).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum BaseExpr {
    /// Named parameter / formal challenge / public.
    Param {
        /// Parameter name.
        name: String,
    },
    /// Constant in `[0, p)`.
    Const {
        /// Canonical representative.
        value: u32,
    },
    /// Trace or preprocessed column cell.
    Column {
        /// Column identifier.
        id: String,
        /// Row offset relative to the evaluation row.
        offset: i32,
    },
    /// Addition.
    Add {
        /// Left.
        lhs: Box<BaseExpr>,
        /// Right.
        rhs: Box<BaseExpr>,
    },
    /// Multiplication.
    Mul {
        /// Left.
        lhs: Box<BaseExpr>,
        /// Right.
        rhs: Box<BaseExpr>,
    },
    /// Negation.
    Neg {
        /// Inner.
        inner: Box<BaseExpr>,
    },
    /// Multiplicative inverse. Partial: zero has no inverse.
    Inv {
        /// Inner.
        inner: Box<BaseExpr>,
    },
}

/// Extension-field expression (QM31 coordinates treated symbolically).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ExtExpr {
    /// Named parameter.
    Param {
        /// Parameter name.
        name: String,
    },
    /// Lift a base expression.
    FromBase {
        /// Base expression.
        inner: BaseExpr,
    },
    /// Addition.
    Add {
        /// Left.
        lhs: Box<ExtExpr>,
        /// Right.
        rhs: Box<ExtExpr>,
    },
    /// Multiplication.
    Mul {
        /// Left.
        lhs: Box<ExtExpr>,
        /// Right.
        rhs: Box<ExtExpr>,
    },
    /// Negation.
    Neg {
        /// Inner.
        inner: Box<ExtExpr>,
    },
}

impl BaseExpr {
    /// Convenience: named parameter.
    pub fn param(name: impl Into<String>) -> Self {
        Self::Param { name: name.into() }
    }

    /// Convenience: column at offset 0.
    pub fn column(id: impl Into<String>) -> Self {
        Self::Column {
            id: id.into(),
            offset: 0,
        }
    }

    /// Convenience: constant.
    pub fn constant(value: u32) -> Self {
        Self::Const { value }
    }
}
