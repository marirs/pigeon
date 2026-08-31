//! The routing snapshot: what it holds, how it answers, and what it refuses.
//!
//! Design: `M1-SNAPSHOT.md`. Every ordering decision here is §2 and §4, and the
//! validation in [`Snapshot::build`] is §6 and §7.

use std::collections::{HashMap, HashSet};

use pigeon_types::{Address, DomainGate, ForwardPolicy};

use crate::fold;
use crate::pattern::{PatternError, Wildcard};

/// Where a matched rule sends mail, or that it refuses it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    /// Refuse this address. `alias add … --reject`.
    Reject,
    /// Forward, to one or more mailboxes.
    ///
    /// Inheritance from the domain default is already resolved (§5), so this is
    /// never empty and lookup never consults the domain.
    Forward(Vec<Destination>),
}

/// A mailbox mail is forwarded to.
///
/// `local` keeps its case and `domain` is folded: Pigeon is a relay here, not
/// the authority, and RFC 5321 §2.4 reserves the local part to the destination
/// host. Folding it merges distinct recipients — finding 12.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Destination {
    pub local: String,
    pub domain: String,
}

impl std::fmt::Display for Destination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}

/// Which tier of the precedence chain produced an answer.
///
/// Returned rather than recomputed, because `pigeon route inbound` prints it
/// and a second code path deriving it would be a second implementation of §2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    ExactFull,
    ExactBase,
    Wildcard,
    CatchAll,
}

/// What the snapshot says about one recipient.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision<'a> {
    /// Accept and forward.
    Forward {
        tier: Tier,
        /// The rule as written, for diagnostics: `hello`, `shop-*`, `catch-all`.
        matched: &'a str,
        destinations: &'a [Destination],
    },
    /// A rule matched and refuses this address.
    Reject { tier: Tier, matched: &'a str },
    /// No rule matched.
    NoRoute,
    /// The domain is not carried here at all.
    UnknownDomain,
    /// The domain exists but is not accepting: gated by DNS, or switched off.
    DomainNotAccepting,
}

impl Decision<'_> {
    /// Whether mail for this recipient should be accepted at `RCPT TO`.
    pub fn accepts(&self) -> bool {
        matches!(self, Self::Forward { .. })
    }
}

#[derive(Debug, Clone)]
struct WildcardRule {
    pattern: Wildcard,
    rule: Rule,
}

#[derive(Debug, Clone)]
struct Domain {
    gate: DomainGate,
    plus_addressing: bool,
    forwarding: Forwarding,
    /// Keyed by folded local part.
    exact: HashMap<String, (String, Rule)>,
    /// Pre-sorted by §2 precedence, so the first match is the winner and the
    /// ordering cannot be applied inconsistently at two call sites.
    wildcards: Vec<WildcardRule>,
    catchall: Option<Rule>,
}

/// How a domain's mail is rewritten on the way out, and what signs it.
///
/// Read from the same transaction-pinned snapshot as the routing decision, for
/// the reason the snapshot exists at all: a message must be forwarded under the
/// policy that was in force when it was accepted. Reading the policy from the
/// database at delivery time would let a configuration change between the two
/// produce a message signed under one identity and routed under another.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Forwarding {
    pub policy: ForwardPolicy,
    /// The active key, if the domain has one. `None` means nothing here can
    /// sign — which `Preserve` does not need and `RewriteFrom` cannot do
    /// without.
    pub dkim: Option<DkimIdentity>,
}

/// The active DKIM key for a domain, as the database records it.
///
/// The private key is *not* here: this names where it lives, and loading it is
/// the daemon's job, against the configured key root. A snapshot that carried
/// key material would put it in every clone of the routing table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimIdentity {
    pub selector: String,
    /// As stored. Resolved against the configured `keys` root by the caller,
    /// which is where the containment rule lives (`M1-SCHEMA.md`).
    pub private_key_path: String,
    pub algorithm: String,
}

/// An immutable routing table.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    domains: HashMap<String, Domain>,
}

// ------------------------------------------------------------------ building

/// One domain's configuration, as read from the database.
#[derive(Debug, Clone)]
pub struct DomainInput {
    pub name: String,
    pub gate: DomainGate,
    pub plus_addressing: bool,
    pub forwarding: Forwarding,
    /// The default every inheriting alias resolves to.
    pub default_destination: Option<Destination>,
    pub aliases: Vec<AliasInput>,
    pub catchall: Option<CatchAllInput>,
}

#[derive(Debug, Clone)]
pub struct AliasInput {
    pub pattern: String,
    pub reject: bool,
    /// Empty means "inherit the domain default" (§5), which is why this is a
    /// `Vec` and not an `Option<Vec>`: the absence *is* the encoding.
    pub destinations: Vec<Destination>,
}

#[derive(Debug, Clone)]
pub struct CatchAllInput {
    /// `None` inherits the domain default.
    pub destination: Option<Vec<Destination>>,
}

/// Why a configuration cannot be published.
///
/// Blocking means the snapshot cannot answer correctly. Anything that answers
/// correctly but probably surprises the operator is a [`Report`] instead.
#[derive(Debug, Clone, PartialEq)]
pub enum BuildError {
    DomainNotAnALabel {
        domain: String,
    },
    BadPattern {
        domain: String,
        pattern: String,
        source: PatternError,
    },
    RejectWithDestinations {
        domain: String,
        pattern: String,
    },
    InheritsNothing {
        domain: String,
        pattern: String,
    },
    CatchAllInheritsNothing {
        domain: String,
    },
    BadDestination {
        domain: String,
        pattern: String,
        destination: String,
    },
    /// Two equal-precedence wildcards that overlap and route differently.
    ///
    /// Blocked rather than resolved: a deterministic tie-break makes an
    /// ambiguous configuration repeatable, not correct. One of the two rules
    /// would never apply and nothing would say so.
    AmbiguousWildcards {
        domain: String,
        a: String,
        b: String,
    },
    /// A cycle, named by the path around it.
    Loop {
        path: Vec<String>,
    },
    /// The walk visited more nodes than exist. Proves a bug here, not a bad
    /// configuration — see §6.
    TraversalOverran {
        nodes: usize,
    },
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DomainNotAnALabel { domain } => write!(
                f,
                "{domain:?} is not a usable domain name. Managed domains are stored as \
                 normalised A-labels, and one that is not cannot be compared against an \
                 incoming domain that always is."
            ),
            Self::BadPattern {
                domain,
                pattern,
                source,
            } => write!(f, "{domain}: alias {pattern:?}: {source}"),
            Self::RejectWithDestinations { domain, pattern } => write!(
                f,
                "{domain}: alias {pattern:?} is a reject rule and also has destinations. \
                 One rule cannot both refuse and forward."
            ),
            Self::InheritsNothing { domain, pattern } => write!(
                f,
                "{domain}: alias {pattern:?} inherits the domain default, and {domain} \
                 has none. Set one with `pigeon domain forward`, or give the alias its own."
            ),
            Self::CatchAllInheritsNothing { domain } => write!(
                f,
                "{domain}: catch-all is enabled and inherits the domain default, and \
                 {domain} has none. It would accept every address and route none of them."
            ),
            Self::BadDestination {
                domain,
                pattern,
                destination,
            } => write!(
                f,
                "{domain}: alias {pattern:?} forwards to {destination:?}, which is not a \
                 valid address"
            ),
            Self::AmbiguousWildcards { domain, a, b } => write!(
                f,
                "{domain}: wildcards {a:?} and {b:?} have equal precedence, match some of \
                 the same addresses, and route differently. Which one applies would be \
                 arbitrary, so neither is published. Make one more specific."
            ),
            Self::Loop { path } => {
                write!(f, "forwarding loop: {}", path.join(" -> "))
            }
            Self::TraversalOverran { nodes } => write!(
                f,
                "loop detection visited more than {nodes} nodes, which cannot happen with \
                 a correct path set. This is a bug in Pigeon, not in your configuration."
            ),
        }
    }
}

impl std::error::Error for BuildError {}

/// Something true about the configuration that is worth saying and is not an
/// error.
#[derive(Debug, Clone, PartialEq)]
pub enum Report {
    /// An alias that routes exactly where the catch-all already routes.
    RedundantAgainstCatchAll { domain: String, pattern: String },
    /// Equal-precedence overlapping wildcards that route *identically*. One of
    /// them never applies, and which is arbitrary, but nothing goes anywhere
    /// unexpected.
    RedundantWildcards {
        domain: String,
        a: String,
        b: String,
    },
    /// Validated and deliberate, and it looks like a fault.
    ActiveButDisabled { domain: String },
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RedundantAgainstCatchAll { domain, pattern } => write!(
                f,
                "{domain}: alias {pattern:?} forwards where the catch-all already does, so \
                 it does not change where mail goes. It becomes meaningful again if the \
                 catch-all destination changes."
            ),
            Self::RedundantWildcards { domain, a, b } => write!(
                f,
                "{domain}: wildcards {a:?} and {b:?} overlap at equal precedence but route \
                 identically, so one of them never applies."
            ),
            Self::ActiveButDisabled { domain } => write!(
                f,
                "{domain} passes every DNS check but is switched off, so it refuses mail. \
                 Enable it with `pigeon domain enable {domain}`."
            ),
        }
    }
}

/// A snapshot and everything worth telling the operator about it.
#[derive(Debug)]
pub struct Built {
    pub snapshot: Snapshot,
    pub reports: Vec<Report>,
}

impl Snapshot {
    /// Build and validate. Nothing is published unless this returns `Ok`.
    ///
    /// This is Milestone 1's enforcement boundary (`M1-SCHEMA.md` S-2). Every
    /// invariant SQLite cannot express is checked here, and it runs on every
    /// path into service — startup, reload, and inside a mutation's own
    /// transaction — so a row that violates one cannot go live merely because
    /// nobody ran a command.
    pub fn build(inputs: Vec<DomainInput>) -> Result<Built, BuildError> {
        let mut domains = HashMap::with_capacity(inputs.len());
        let mut reports = Vec::new();

        for input in inputs {
            let (name, domain, mut domain_reports) = Self::build_domain(input)?;
            reports.append(&mut domain_reports);
            domains.insert(name, domain);
        }

        let snapshot = Snapshot { domains };
        snapshot.check_for_loops()?;
        Ok(Built { snapshot, reports })
    }

    fn build_domain(input: DomainInput) -> Result<(String, Domain, Vec<Report>), BuildError> {
        let name = input.name.to_ascii_lowercase();
        if !is_a_label(&name) {
            return Err(BuildError::DomainNotAnALabel { domain: input.name });
        }

        let mut reports = Vec::new();
        let mut exact = HashMap::new();
        let mut wildcards: Vec<WildcardRule> = Vec::new();

        for alias in input.aliases {
            let rule = resolve(
                &name,
                &alias.pattern,
                alias.reject,
                alias.destinations,
                input.default_destination.as_ref(),
            )?;

            let folded = alias.pattern.to_ascii_lowercase();
            match crate::pattern::parse(&folded).map_err(|source| BuildError::BadPattern {
                domain: name.clone(),
                pattern: alias.pattern.clone(),
                source,
            })? {
                None => {
                    exact.insert(folded, (alias.pattern, rule));
                }
                Some(pattern) => wildcards.push(WildcardRule { pattern, rule }),
            }
        }

        // Sorted once, so the first match is the winner. Sorting at lookup, or
        // comparing candidates as they are found, is the same rule written in
        // two places.
        wildcards.sort_by(|a, b| a.pattern.precedence(&b.pattern));

        // Ambiguity is decided after sorting but has nothing to do with it:
        // equal precedence plus overlap is a property of the pair.
        check_wildcard_ambiguity(&name, &wildcards, &mut reports)?;

        let catchall = match input.catchall {
            None => None,
            Some(c) => Some(Rule::Forward(match c.destination {
                Some(d) => d,
                None => vec![input.default_destination.clone().ok_or_else(|| {
                    BuildError::CatchAllInheritsNothing {
                        domain: name.clone(),
                    }
                })?],
            })),
        };

        if let Some(Rule::Forward(catch_dests)) = &catchall {
            for (written, rule) in exact.values() {
                if let Rule::Forward(d) = rule
                    && same_destinations(d, catch_dests)
                {
                    reports.push(Report::RedundantAgainstCatchAll {
                        domain: name.clone(),
                        pattern: written.clone(),
                    });
                }
            }
        }

        if input.gate.status.is_validated() && !input.gate.inbound_enabled {
            reports.push(Report::ActiveButDisabled {
                domain: name.clone(),
            });
        }

        Ok((
            name,
            Domain {
                gate: input.gate,
                plus_addressing: input.plus_addressing,
                forwarding: input.forwarding,
                exact,
                wildcards,
                catchall,
            },
            reports,
        ))
    }

    // ----------------------------------------------------------------- lookup

    /// Resolve a recipient. Allocates nothing.
    ///
    /// The order is `M1-SNAPSHOT.md` §4, and every step of it is load-bearing:
    ///
    /// ```text
    /// 1. exact alias, FULL local part
    /// 2. exact alias, BASE local part        (only if a tag was stripped)
    /// 3. wildcards matching EITHER form, ranked once by §2 precedence
    /// 4. catch-all
    /// 5. reject unknown
    /// ```
    ///
    /// Both exact lookups precede every wildcard, so exact beats wildcard. Both
    /// forms reach the wildcard tier, so `hello+*` matches `hello+github` —
    /// which an earlier design could not, because the wildcard tier only ever
    /// saw the base. Catch-all waits until both forms have been tried
    /// everywhere else, so tagged mail on a catch-all domain still finds its
    /// alias.
    /// Every domain this table carries, folded.
    ///
    /// For startup work that has to touch each one — loading signing keys, for
    /// instance. Ordering is unspecified, because a `HashMap` has none and
    /// pretending otherwise invites a caller to depend on it.
    pub fn domains(&self) -> impl Iterator<Item = &str> {
        self.domains.keys().map(String::as_str)
    }

    /// How this domain's mail is rewritten and signed on the way out.
    ///
    /// `None` for a domain this table does not carry — the same answer
    /// [`Snapshot::resolve`] gives, so a caller cannot get a forwarding policy
    /// for an address it would have refused.
    pub fn forwarding(&self, domain: &str) -> Option<&Forwarding> {
        let folded = fold::domain(domain)?;
        self.domains.get(folded.as_str()).map(|d| &d.forwarding)
    }

    pub fn resolve(&self, address: &Address<'_>) -> Decision<'_> {
        let Some(folded_domain) = fold::domain(address.domain()) else {
            return Decision::UnknownDomain;
        };
        let Some(domain) = self.domains.get(folded_domain.as_str()) else {
            return Decision::UnknownDomain;
        };
        if !domain.gate.accepts_inbound() {
            return Decision::DomainNotAccepting;
        }

        let Some(full) = fold::local(address.local()) else {
            return Decision::NoRoute;
        };
        let full = full.as_str();

        // 1.
        if let Some((written, rule)) = domain.exact.get(full) {
            return decide(Tier::ExactFull, written, rule);
        }

        // 2. Only when a tag was actually stripped. `local_without_tag` returns
        // the local part unchanged when there is no tag, and when the base
        // would be empty — `+tag@` is a real local part, not an empty one.
        let base = if domain.plus_addressing {
            let base = address.local_without_tag();
            if base.len() == address.local().len() {
                None
            } else {
                fold::local(base)
            }
        } else {
            None
        };
        let base = base.as_ref().map(|b| b.as_str());

        if let Some(base) = base
            && let Some((written, rule)) = domain.exact.get(base)
        {
            return decide(Tier::ExactBase, written, rule);
        }

        // 3. One ranking over both forms. `wildcards` is pre-sorted, so the
        // first that matches either form is the winner — ranking the two forms
        // separately would make "the full form first" a hidden fourth
        // precedence rule.
        for w in &domain.wildcards {
            if w.pattern.matches(full) || base.is_some_and(|b| w.pattern.matches(b)) {
                return decide(Tier::Wildcard, w.pattern.as_str(), &w.rule);
            }
        }

        // 4.
        if let Some(rule) = &domain.catchall {
            return decide(Tier::CatchAll, "catch-all", rule);
        }

        // 5.
        Decision::NoRoute
    }

    /// Whether this domain is carried here at all.
    pub fn has_domain(&self, domain: &str) -> bool {
        fold::domain(domain).is_some_and(|d| self.domains.contains_key(d.as_str()))
    }

    /// How many rules the table holds, for the reload log line.
    ///
    /// A reload that says only "published" tells an operator nothing about
    /// what changed; the counts are the cheapest thing that does.
    pub fn rule_count(&self) -> usize {
        self.domains
            .values()
            .map(|d| d.exact.len() + d.wildcards.len() + usize::from(d.catchall.is_some()))
            .sum()
    }

    /// Domains in the snapshot, for diagnostics.
    pub fn domain_names(&self) -> impl Iterator<Item = &str> {
        self.domains.keys().map(String::as_str)
    }

    // --------------------------------------------------------- loop detection

    /// Depth-first, with a path-local set (§6).
    ///
    /// `on_path` detects cycles; `finished` only avoids repeated work. A single
    /// global visited set would refuse a diamond — `a → b`, `a → c`, `b → d`,
    /// `c → d` reaches `d` twice by different routes with no cycle anywhere —
    /// and fanning one alias out to several destinations is an advertised
    /// feature, so diamonds are ordinary rather than exotic.
    fn check_for_loops(&self) -> Result<(), BuildError> {
        let mut finished: HashSet<Destination> = HashSet::new();
        let mut budget = self.node_count();

        for domain in self.domains.values() {
            for rule in domain
                .exact
                .values()
                .map(|(_, r)| r)
                .chain(domain.wildcards.iter().map(|w| &w.rule))
                .chain(domain.catchall.iter())
            {
                if let Rule::Forward(dests) = rule {
                    for d in dests {
                        let mut on_path = Vec::new();
                        self.walk(d, &mut on_path, &mut finished, &mut budget)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn walk(
        &self,
        node: &Destination,
        on_path: &mut Vec<Destination>,
        finished: &mut HashSet<Destination>,
        budget: &mut usize,
    ) -> Result<(), BuildError> {
        if on_path.contains(node) {
            let mut path: Vec<String> = on_path.iter().map(|d| d.to_string()).collect();
            path.push(node.to_string());
            return Err(BuildError::Loop { path });
        }
        if finished.contains(node) {
            return Ok(());
        }

        // Derived, not fixed. With a correct `on_path` set no walk can visit
        // more nodes than exist without repeating one, so exhausting this
        // proves a bug here rather than a deep configuration.
        let Some(next) = budget.checked_sub(1) else {
            return Err(BuildError::TraversalOverran {
                nodes: self.node_count(),
            });
        };
        *budget = next;

        // Resolve this concrete address through the snapshot. Enablement is
        // ignored on purpose: a loop through a gated domain is still a loop,
        // and it starts looping the moment the domain returns — when nobody is
        // looking for a configuration change, because there was not one.
        let followed = self.follow_ignoring_gate(node);

        on_path.push(node.clone());
        for d in followed {
            self.walk(&d, on_path, finished, budget)?;
        }
        on_path.pop();

        finished.insert(node.clone());
        Ok(())
    }

    /// The destinations a concrete address resolves to, if it is managed here.
    fn follow_ignoring_gate(&self, node: &Destination) -> Vec<Destination> {
        let Some(folded) = fold::domain(&node.domain) else {
            return Vec::new();
        };
        let Some(domain) = self.domains.get(folded.as_str()) else {
            return Vec::new();
        };
        let joined = format!("{}@{}", node.local, node.domain);
        let Ok(address) = Address::parse(&joined) else {
            return Vec::new();
        };

        match resolve_within(domain, &address) {
            Some(Rule::Forward(d)) => d.clone(),
            _ => Vec::new(),
        }
    }

    fn node_count(&self) -> usize {
        self.domains
            .values()
            .map(|d| d.exact.len() + d.wildcards.len() + usize::from(d.catchall.is_some()))
            .sum::<usize>()
            .max(1)
            // Every rule can carry several destinations, and each is a node.
            .saturating_mul(MAX_DESTINATIONS_PER_RULE)
    }
}

/// Bound on how many mailboxes one rule may fan out to, for the traversal
/// budget only. Generous: this is a backstop, not a policy.
const MAX_DESTINATIONS_PER_RULE: usize = 64;

/// Resolve inside one domain, ignoring the gate. Shared by loop detection so
/// the walk follows exactly the same precedence the runtime does.
fn resolve_within(domain: &Domain, address: &Address<'_>) -> Option<Rule> {
    let full = fold::local(address.local())?;
    let full = full.as_str();

    if let Some((_, rule)) = domain.exact.get(full) {
        return Some(rule.clone());
    }

    let base = if domain.plus_addressing {
        let b = address.local_without_tag();
        if b.len() == address.local().len() {
            None
        } else {
            fold::local(b)
        }
    } else {
        None
    };
    let base = base.as_ref().map(|b| b.as_str());

    if let Some(base) = base
        && let Some((_, rule)) = domain.exact.get(base)
    {
        return Some(rule.clone());
    }

    for w in &domain.wildcards {
        if w.pattern.matches(full) || base.is_some_and(|b| w.pattern.matches(b)) {
            return Some(w.rule.clone());
        }
    }

    domain.catchall.clone()
}

fn decide<'a>(tier: Tier, matched: &'a str, rule: &'a Rule) -> Decision<'a> {
    match rule {
        Rule::Reject => Decision::Reject { tier, matched },
        Rule::Forward(destinations) => Decision::Forward {
            tier,
            matched,
            destinations,
        },
    }
}

/// Turn one stored alias into a rule, resolving inheritance (§5).
fn resolve(
    domain: &str,
    pattern: &str,
    reject: bool,
    destinations: Vec<Destination>,
    default: Option<&Destination>,
) -> Result<Rule, BuildError> {
    if reject {
        // SQLite cannot express this: a CHECK cannot reach another table.
        if !destinations.is_empty() {
            return Err(BuildError::RejectWithDestinations {
                domain: domain.to_string(),
                pattern: pattern.to_string(),
            });
        }
        return Ok(Rule::Reject);
    }

    for d in &destinations {
        if Address::parse(&format!("{}@{}", d.local, d.domain)).is_err() {
            return Err(BuildError::BadDestination {
                domain: domain.to_string(),
                pattern: pattern.to_string(),
                destination: d.to_string(),
            });
        }
    }

    if destinations.is_empty() {
        // The absence is the encoding: no rows means inherit.
        let d = default.ok_or_else(|| BuildError::InheritsNothing {
            domain: domain.to_string(),
            pattern: pattern.to_string(),
        })?;
        return Ok(Rule::Forward(vec![d.clone()]));
    }

    Ok(Rule::Forward(destinations))
}

/// Equal precedence plus overlap is either ambiguous or redundant (§2, §7).
fn check_wildcard_ambiguity(
    domain: &str,
    wildcards: &[WildcardRule],
    reports: &mut Vec<Report>,
) -> Result<(), BuildError> {
    for (i, a) in wildcards.iter().enumerate() {
        for b in &wildcards[i + 1..] {
            let equal_precedence = a.pattern.literals() == b.pattern.literals();
            if !equal_precedence || !a.pattern.overlaps(&b.pattern) {
                continue;
            }
            if a.rule == b.rule {
                reports.push(Report::RedundantWildcards {
                    domain: domain.to_string(),
                    a: a.pattern.as_str().to_string(),
                    b: b.pattern.as_str().to_string(),
                });
            } else {
                return Err(BuildError::AmbiguousWildcards {
                    domain: domain.to_string(),
                    a: a.pattern.as_str().to_string(),
                    b: b.pattern.as_str().to_string(),
                });
            }
        }
    }
    Ok(())
}

fn same_destinations(a: &[Destination], b: &[Destination]) -> bool {
    let mut a: Vec<_> = a.to_vec();
    let mut b: Vec<_> = b.to_vec();
    a.sort();
    b.sort();
    a == b
}

/// Whether a domain is a usable, normalised A-label.
///
/// The same rules `Address::parse` applies to the right-hand side, checked here
/// because a managed domain that an incoming address could never equal is a
/// domain that silently carries no mail.
fn is_a_label(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= fold::MAX_DOMAIN
        && domain.contains('.')
        && domain.is_ascii()
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
