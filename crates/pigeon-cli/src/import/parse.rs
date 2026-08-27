//! Reading an import file into a provider-independent plan.
//!
//! Design: `M1-IMPORT.md` §3 and §4. This phase writes nothing and reaches
//! nothing outside the file, which is what lets the whole input be checked
//! before any of it is applied.
//!
//! # Why this is not a CSV crate
//!
//! The format is two columns and a header, deliberately. What matters here is
//! not parsing sophistication — it is that every row is checked and every
//! problem is reported with its line number, rather than the first one aborting
//! the run. A quoted field spanning newlines is the one thing worth handling
//! that a naive split does not, and it is handled below.

use std::collections::BTreeMap;
use std::fmt;

use pigeon_db::repo::Address;

/// What one row asks for, after normalisation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Lowercased local part, or `*` for the catch-all.
    pub pattern: String,
    pub reject: bool,
    /// Accumulated across every row naming this address.
    ///
    /// Sorted, so two files listing the same fan-out in different orders
    /// produce the same plan.
    pub destinations: Vec<Address>,
    /// Every input line this rule came from, for reporting.
    pub rows: Vec<usize>,
}

impl Rule {
    /// The catch-all is `*@domain`, which is not a wildcard alias.
    pub fn is_catchall(&self) -> bool {
        self.pattern == "*"
    }
}

/// Everything the file asks for, grouped by domain.
///
/// `BTreeMap` rather than `HashMap`: the plan is reported, previewed and
/// applied in a stated order, and an ordering that varies between runs makes a
/// diff of two dry runs meaningless.
#[derive(Debug, Clone, Default)]
pub struct Plan {
    pub domains: BTreeMap<String, BTreeMap<String, Rule>>,
    pub rows_read: usize,
}

impl Plan {
    pub fn rule_count(&self) -> usize {
        self.domains.values().map(BTreeMap::len).sum()
    }
}

/// Something wrong with the input, carrying where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    /// 1-based line number in the file, or 0 for whole-file problems.
    pub row: usize,
    pub address: String,
    pub kind: ConflictKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictKind {
    MissingHeader,
    UnknownColumn,
    WrongFieldCount,
    InvalidAddress,
    InvalidPattern,
    InvalidDestination,
    RejectWithDestination,
    ForwardWithoutDestination,
    UnknownKind,
    KindConflict,
    DuplicateRow,
    /// Found against the database rather than in the file.
    ExistingAliasDiffers,
    /// Found by the snapshot, inside the transaction.
    Unserveable,
    /// The configuration moved between the plan and the lock.
    StateChanged,
}

impl ConflictKind {
    /// The stable identifier in `--json`. Not the message.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingHeader => "missing_header",
            Self::UnknownColumn => "unknown_column",
            Self::WrongFieldCount => "wrong_field_count",
            Self::InvalidAddress => "invalid_address",
            Self::InvalidPattern => "invalid_pattern",
            Self::InvalidDestination => "invalid_destination",
            Self::RejectWithDestination => "reject_with_destination",
            Self::ForwardWithoutDestination => "forward_without_destination",
            Self::UnknownKind => "unknown_kind",
            Self::KindConflict => "kind_conflict",
            Self::DuplicateRow => "duplicate_row",
            Self::ExistingAliasDiffers => "existing_alias_differs",
            Self::Unserveable => "unserveable",
            Self::StateChanged => "state_changed",
        }
    }
}

impl fmt::Display for Conflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.row == 0 {
            write!(f, "{}", self.message)
        } else {
            write!(f, "row {}: {}", self.row, self.message)
        }
    }
}

/// Parse and normalise the whole input.
///
/// Returns the plan **and** every conflict found. A caller that sees conflicts
/// must not apply the plan; both are returned together so the report can be
/// complete rather than stopping at the first bad row.
pub fn parse(text: &str) -> (Plan, Vec<Conflict>) {
    let mut conflicts = Vec::new();
    let mut plan = Plan::default();

    let rows = split_rows(text);
    let Some((header_row, header)) = rows.first().cloned() else {
        conflicts.push(Conflict {
            row: 0,
            address: String::new(),
            kind: ConflictKind::MissingHeader,
            message: "the file is empty; a header row naming `address` and `destination` \
                      is required"
                .into(),
        });
        return (plan, conflicts);
    };

    let columns = match header_columns(&header) {
        Ok(c) => c,
        Err((kind, message)) => {
            conflicts.push(Conflict {
                row: header_row,
                address: String::new(),
                kind,
                message,
            });
            return (plan, conflicts);
        }
    };

    for (row, line) in rows.into_iter().skip(1) {
        if line.iter().all(|f| f.trim().is_empty()) {
            continue;
        }
        plan.rows_read += 1;
        if let Err(c) = apply_row(&mut plan, &columns, row, &line) {
            conflicts.push(c);
        }
    }

    // Destinations accumulate in arrival order; sorting makes the plan a
    // function of the file's content rather than its ordering.
    for rules in plan.domains.values_mut() {
        for rule in rules.values_mut() {
            rule.destinations.sort();
            rule.destinations.dedup();
        }
    }

    (plan, conflicts)
}

/// Which column holds what.
struct Columns {
    address: usize,
    destination: usize,
    kind: Option<usize>,
    width: usize,
}

/// Match columns by name (I-2).
///
/// Column order varies between exporters, and guessing which column is the
/// destination is how an import writes every alias backwards.
fn header_columns(header: &[String]) -> Result<Columns, (ConflictKind, String)> {
    let mut address = None;
    let mut destination = None;
    let mut kind = None;
    let mut unknown: Vec<&str> = Vec::new();

    for (i, name) in header.iter().enumerate() {
        match name.trim().to_ascii_lowercase().as_str() {
            "address" => address = Some(i),
            "destination" => destination = Some(i),
            "kind" => kind = Some(i),
            "" => {}
            _ => unknown.push(name.trim()),
        }
    }

    // Which failure this is decides which fix the message names, so the two are
    // distinguished rather than collapsed.
    //
    // Nothing recognised at all means the first row is data — the header was
    // forgotten, and reporting the first cell as an "unknown column" would be
    // accurate and useless. One recognised column beside an unrecognised one is
    // a typo in a header that exists.
    if address.is_none() && destination.is_none() {
        return Err((
            ConflictKind::MissingHeader,
            format!(
                "a header row naming `address` and `destination` is required, and this                  file's first row is {}. Columns are matched by name, so their order does                  not matter.",
                if unknown.is_empty() {
                    "empty".to_string()
                } else {
                    format!("{:?}", unknown.join(", "))
                }
            ),
        ));
    }

    if let Some(name) = unknown.first() {
        return Err((
            ConflictKind::UnknownColumn,
            format!(
                "unknown column {name:?}; expected `address`, `destination` and optionally `kind`"
            ),
        ));
    }

    match (address, destination) {
        (Some(address), Some(destination)) => Ok(Columns {
            address,
            destination,
            kind,
            width: header.len(),
        }),
        (None, _) => Err((
            ConflictKind::MissingHeader,
            "the header has no `address` column".into(),
        )),
        (_, None) => Err((
            ConflictKind::MissingHeader,
            "the header has no `destination` column".into(),
        )),
    }
}

fn apply_row(
    plan: &mut Plan,
    columns: &Columns,
    row: usize,
    fields: &[String],
) -> Result<(), Conflict> {
    let at = |i: usize| fields.get(i).map(|s| s.trim()).unwrap_or("");

    if fields.len() != columns.width {
        return Err(Conflict {
            row,
            address: at(columns.address).to_string(),
            kind: ConflictKind::WrongFieldCount,
            message: format!(
                "{} fields, expected {}. A destination containing a comma must be quoted.",
                fields.len(),
                columns.width
            ),
        });
    }

    let raw_address = at(columns.address);
    let raw_destination = at(columns.destination);
    let raw_kind = columns.kind.map(at).unwrap_or("forward");

    let reject = match raw_kind.to_ascii_lowercase().as_str() {
        "" | "forward" => false,
        "reject" => true,
        other => {
            return Err(Conflict {
                row,
                address: raw_address.to_string(),
                kind: ConflictKind::UnknownKind,
                message: format!("kind {other:?} is not `forward` or `reject`"),
            });
        }
    };

    let (pattern, domain) = split_pattern(raw_address).map_err(|message| Conflict {
        row,
        address: raw_address.to_string(),
        kind: ConflictKind::InvalidAddress,
        message,
    })?;

    // The pattern is checked against the same grammar the router uses, so a
    // file cannot introduce a rule the snapshot would later refuse.
    pigeon_route::pattern::parse(&pattern).map_err(|e| Conflict {
        row,
        address: raw_address.to_string(),
        kind: ConflictKind::InvalidPattern,
        message: format!("{e}"),
    })?;

    if reject && !raw_destination.is_empty() {
        return Err(Conflict {
            row,
            address: raw_address.to_string(),
            kind: ConflictKind::RejectWithDestination,
            message: "a reject rule refuses an address; it cannot also forward it".into(),
        });
    }
    if !reject && raw_destination.is_empty() {
        // Never read as inheritance. Inheriting is a real state, and a blank
        // cell is far more often a broken export than a deliberate one.
        return Err(Conflict {
            row,
            address: raw_address.to_string(),
            kind: ConflictKind::ForwardWithoutDestination,
            message: "no destination. Import never reads a blank cell as inheriting the \
                      domain default; set one explicitly, or use kind=reject."
                .into(),
        });
    }

    let destination = if reject {
        None
    } else {
        Some(Address::parse(raw_destination).map_err(|e| Conflict {
            row,
            address: raw_address.to_string(),
            kind: ConflictKind::InvalidDestination,
            message: format!("{e}"),
        })?)
    };

    let rules = plan.domains.entry(domain).or_default();
    match rules.get_mut(&pattern) {
        None => {
            rules.insert(
                pattern.clone(),
                Rule {
                    pattern,
                    reject,
                    destinations: destination.into_iter().collect(),
                    rows: vec![row],
                },
            );
        }
        Some(existing) => {
            // One row saying forward and one saying reject are two intentions,
            // and picking either would be a guess.
            if existing.reject != reject {
                return Err(Conflict {
                    row,
                    address: raw_address.to_string(),
                    kind: ConflictKind::KindConflict,
                    message: format!(
                        "already appears on row {} with a different kind",
                        existing.rows[0]
                    ),
                });
            }
            if let Some(d) = destination {
                if existing.destinations.contains(&d) {
                    return Err(Conflict {
                        row,
                        address: raw_address.to_string(),
                        kind: ConflictKind::DuplicateRow,
                        message: format!(
                            "{d} is already listed on row {}. Repeated addresses fan out; \
                             an exact repeat is more often a mangled export.",
                            existing.rows[0]
                        ),
                    });
                }
                existing.destinations.push(d);
            }
            existing.rows.push(row);
        }
    }
    Ok(())
}

/// Split `local@domain` into a folded pattern and a folded domain.
///
/// Not `Address::parse`: the left side may be `*` or contain one, which is a
/// pattern rather than an address.
fn split_pattern(raw: &str) -> Result<(String, String), String> {
    let (local, domain) = raw
        .rsplit_once('@')
        .ok_or_else(|| format!("{raw:?} has no '@'"))?;

    if local.is_empty() {
        return Err(format!("{raw:?} has no local part"));
    }
    let domain = domain.trim().to_ascii_lowercase();
    if domain.is_empty() {
        return Err(format!("{raw:?} has no domain"));
    }

    Ok((local.trim().to_ascii_lowercase(), domain))
}

/// Split CSV text into rows of fields, honouring quotes.
///
/// Returns the 1-based line each row started on, which is what a person reading
/// an error message counts to — a quoted field spanning newlines otherwise makes
/// every later row number wrong.
fn split_rows(text: &str) -> Vec<(usize, Vec<String>)> {
    let mut rows = Vec::new();
    let mut field = String::new();
    let mut row: Vec<String> = Vec::new();
    let mut in_quotes = false;
    let mut line = 1usize;
    let mut row_started_at = 1usize;
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                chars.next();
                field.push('"');
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                row.push(std::mem::take(&mut field));
            }
            '\r' if !in_quotes => {}
            '\n' if !in_quotes => {
                row.push(std::mem::take(&mut field));
                rows.push((row_started_at, std::mem::take(&mut row)));
                line += 1;
                row_started_at = line;
            }
            '\n' => {
                line += 1;
                field.push('\n');
            }
            c => field.push(c),
        }
    }

    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push((row_started_at, row));
    }
    rows
}
