//! Component and audit manifests.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::expr::{BaseExpr, ExtExpr, FieldSort};
use crate::schema::{IR_SCHEMA_ID, IR_SCHEMA_VERSION};

/// Top-level AuditIR document for one analyzed surface (or package of surfaces).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditManifest {
    /// Schema id.
    pub schema: String,
    /// Schema version.
    pub schema_version: String,
    /// Application source commit when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_commit: Option<String>,
    /// Sibling Stwo commit when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stwo_commit: Option<String>,
    /// Tooling version that produced this document.
    pub airlock_version: String,
    /// Components included in this export.
    pub components: Vec<ComponentManifest>,
}

impl AuditManifest {
    /// Construct a manifest with current schema identity.
    pub fn new(airlock_version: impl Into<String>, components: Vec<ComponentManifest>) -> Self {
        Self {
            schema: IR_SCHEMA_ID.to_string(),
            schema_version: IR_SCHEMA_VERSION.to_string(),
            source_commit: None,
            stwo_commit: None,
            airlock_version: airlock_version.into(),
            components,
        }
    }
}

/// One FrameworkEval-style component after instantiation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentManifest {
    /// Stable component name.
    pub name: String,
    /// Log2 of the row domain size.
    pub log_size: u32,
    /// Physical domain length (`1 << log_size`).
    pub domain_size: u64,
    /// Columns.
    pub columns: Vec<ColumnDecl>,
    /// Formal public values and verifier challenges referenced by expressions.
    #[serde(default)]
    pub parameters: Vec<ParameterDecl>,
    /// Polynomial constraints (post-ExprEvaluator retention).
    pub constraints: Vec<ConstraintDecl>,
    /// Uncompressed LogUp / relation entries (before challenge compression).
    pub relations: Vec<RelationEntry>,
    /// Preprocessed columns with concrete values or generator identity.
    pub preprocessed: Vec<PreprocessedColumn>,
    /// Declared maximum constraint log-degree bound from the component.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_max_constraint_log_degree_bound: Option<u32>,
    /// Semantic contract for this component.
    pub contract: SemanticContract,
    /// Whether LogUp was finalized exactly once.
    pub logup_finalized: bool,
}

/// A formal non-column value referenced by the AIR relation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterDecl {
    /// Stable name used by expression `Param` nodes.
    pub name: String,
    /// Field containing the parameter.
    pub field: FieldSort,
    /// Verifier-visible semantic role.
    pub role: ParameterRole,
    /// Earliest phase after which the value is available.
    pub available_after: CommitmentPhase,
}

/// Source and ownership of a formal AIR parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParameterRole {
    /// Public input fixed by the statement.
    PublicInput,
    /// Public component claim, such as a LogUp claimed sum.
    PublicClaim,
    /// Challenge derived by the verifier transcript.
    FiatShamirChallenge,
    /// Explicitly reviewed role not covered by the standard categories.
    Other,
}

/// Witness / preprocessed / interaction column declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnDecl {
    /// Stable column id used in expressions.
    pub id: String,
    /// Human name.
    pub name: String,
    /// Interaction / trace tree index when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interaction: Option<u32>,
    /// Commitment phase ownership.
    pub commitment_phase: CommitmentPhase,
    /// Row offsets referenced by the AIR for this column.
    #[serde(default)]
    pub offsets: Vec<i32>,
    /// Storage kind.
    pub kind: ColumnKind,
    /// Semantic role annotation (required for COVERED surfaces).
    pub semantic_type: SemanticType,
    /// Declared integer range when applicable (`[lo, hi]` inclusive absolute or signed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_range: Option<(i128, i128)>,
    /// Declared row support when restricted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_support: Option<RowSupport>,
}

/// Column storage kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ColumnKind {
    /// Prover-controlled original witness.
    Witness,
    /// Verifier-reconstructible or pinned preprocessed.
    Preprocessed,
    /// Interaction / LogUp cumulative and related.
    Interaction,
}

/// When a value is committed relative to challenges.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentPhase {
    /// Public statement / preprocessed.
    Phase0Public,
    /// Original trace before lookup challenges.
    Phase1Original,
    /// After lookup challenges, before later RLCs.
    Phase2Interaction,
    /// Custom reduction / sumcheck messages.
    Phase3Reduction,
}

impl CommitmentPhase {
    /// Whether `self` is available strictly before `other` begins.
    pub const fn strictly_precedes(self, other: Self) -> bool {
        self.rank() < other.rank()
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Phase0Public => 0,
            Self::Phase1Original => 1,
            Self::Phase2Interaction => 2,
            Self::Phase3Reduction => 3,
        }
    }
}

/// Semantic annotation for columns and obligations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticType {
    /// Unannotated (blocks COVERED until reviewed).
    Unknown,
    /// Public output.
    PublicOutput,
    /// Public input.
    PublicInput,
    /// Selector / boolean.
    Selector,
    /// Carry limb.
    Carry,
    /// Remainder.
    Remainder,
    /// Bit decomposition cell.
    Bit,
    /// Lookup table-side multiplicity.
    TableMultiplicity,
    /// Lookup query-side multiplicity.
    QueryMultiplicity,
    /// Table key column.
    TableKey,
    /// Table value column.
    TableValue,
    /// Signed integer encoding cell.
    SignedInteger {
        /// Encoding convention.
        encoding: SignedEncoding,
    },
    /// Route / expert id.
    RouteId,
    /// Other named role.
    Other {
        /// Role label.
        label: String,
    },
}

/// Signed field encoding convention.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignedEncoding {
    /// Centered M31 representatives in `[-(p-1)/2, (p-1)/2]`.
    CenteredM31,
    /// Explicit single-M31 bias encoding: `value + bias` in `[0, 2^bits)`.
    /// Wider decomposed integers require a separate typed encoding.
    BiasedBits {
        /// Bias added before unsigned packing.
        bias: i128,
        /// Number of bits.
        bits: u32,
    },
}

/// Integer equality obligation attached to a constraint or contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegerEncoding {
    /// Obligation name.
    pub name: String,
    /// Encoding.
    pub encoding: SignedEncoding,
    /// Absolute bound required for unique integer lift (`|x| <= bound`).
    pub abs_bound: u128,
}

/// Row partition / support description.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RowSupport {
    /// All rows in the physical domain.
    All,
    /// Half-open index range `[start, end)`.
    Range {
        /// Inclusive start.
        start: u64,
        /// Exclusive end.
        end: u64,
    },
    /// Named row classes.
    Classes {
        /// Allowed classes.
        classes: Vec<RowClass>,
    },
}

/// Named row class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RowClass {
    /// Semantically active computation row.
    Active,
    /// Inactive / zeroed expert row.
    Inactive,
    /// First boundary.
    BoundaryFirst,
    /// Last boundary.
    BoundaryLast,
    /// Semantic lookup-table row.
    SemanticTable,
    /// Padding beyond semantic table / shape.
    Padding,
}

/// Polynomial constraint declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintDecl {
    /// Stable id.
    pub id: String,
    /// Expression that must be zero (extension field).
    pub expression: ExtExpr,
    /// Rows where the constraint is intended to apply.
    pub row_support: RowSupport,
    /// Optional source location hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_location: Option<String>,
    /// Optional semantic claim label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_claim: Option<String>,
}

/// Uncompressed relation / LogUp entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationEntry {
    /// Relation name (e.g. `SiLU`).
    pub relation: String,
    /// Query vs table side.
    pub role: RelationRole,
    /// Tuple element expressions (base field).
    pub tuple: Vec<BaseExpr>,
    /// Multiplicity expression.
    pub multiplicity: BaseExpr,
    /// Rows where this entry may be nonzero.
    pub row_support: RowSupport,
    /// Challenge phase after which interaction may depend on this relation.
    pub challenge_phase: CommitmentPhase,
    /// Optional source location.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_location: Option<String>,
}

/// Relation participation role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationRole {
    /// Query / consumed side.
    Query,
    /// Table / provided side.
    Table,
}

/// Preprocessed column with concrete domain values or a hashed generator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreprocessedColumn {
    /// Column id matching [`ColumnDecl::id`].
    pub id: String,
    /// Semantic length (rows that mean something).
    pub semantic_length: u64,
    /// Physical length (domain size).
    pub physical_length: u64,
    /// Optional BLAKE3 hash of canonical little-endian values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values_hash: Option<String>,
    /// Optional concrete values (base-field canonical reps). Required for table-support lints
    /// unless `generator_id` is present and values are recoverable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<u32>>,
    /// Optional symbolic generator identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generator_id: Option<String>,
}

/// Verifier-owned semantic contract for a component.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticContract {
    /// Public inputs by `ParameterDecl::name` or `ColumnDecl::id`.
    #[serde(default)]
    pub public_inputs: Vec<String>,
    /// Public claims by `ParameterDecl::name`.
    #[serde(default)]
    pub public_claims: Vec<String>,
    /// Public outputs by `ColumnDecl::id`.
    #[serde(default)]
    pub public_outputs: Vec<String>,
    /// Integer obligations.
    #[serde(default)]
    pub integer_obligations: Vec<IntegerEncoding>,
    /// Trusted assumptions outside the AIR (explicit).
    #[serde(default)]
    pub assumptions: Vec<String>,
    /// Independent reference semantics document / crate id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_semantics_id: Option<String>,
    /// Free-form metadata.
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub metadata: IndexMap<String, String>,
}

impl Default for SemanticContract {
    fn default() -> Self {
        Self {
            public_inputs: Vec::new(),
            public_claims: Vec::new(),
            public_outputs: Vec::new(),
            integer_obligations: Vec::new(),
            assumptions: Vec::new(),
            reference_semantics_id: None,
            metadata: IndexMap::new(),
        }
    }
}
