//! The mapping from string identifiers to the slots a compiled program uses.
//!
//! A condition says `$a`; the bytecode says `StrMatch(0)`. This is the thing
//! that turns one into the other, and it is also what expands `them` and
//! `($a*)` into concrete slot lists.
//!
//! # Why identifiers are compared without their `$`
//!
//! The two halves of the language disagree about the sigil: a definition is
//! stored as `$a`, while a reference in a condition is stored as `a`. Both
//! forms reach the lookup — `$a` from a definition, `a` from `$a`, `#a`, `@a`
//! and `!a`, and either from a set, depending on how it was written. Comparing
//! on the stripped name means every one of those finds the same slot, instead
//! of each call site having to remember which half it came from.

use std::collections::BTreeMap;

use crate::ast::{StringDef, StringSet};

/// String identifiers of one rule, in definition order.
///
/// Definition order is the slot order, and it is what every set expansion
/// preserves. That matters for one thing only — reproducibility — but it
/// matters a lot there: the same rule source must produce byte-identical
/// bytecode every time, or the rule database cannot be verified by rebuild.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StringTable {
    /// Stripped identifier to slot.
    slots: BTreeMap<String, u32>,
    /// Slot to the identifier as defined, i.e. with its `$`.
    order: Vec<String>,
}

impl StringTable {
    /// Build from a rule's string definitions.
    ///
    /// The parser rejects a duplicate identifier, so the dedup here is
    /// belt-and-braces for tables built by hand or by the rule-set importer.
    /// It has to happen at all because a repeated identifier would otherwise
    /// give two slots the same name and make `them` count one string twice.
    pub fn from_defs(defs: &[StringDef]) -> Self {
        let mut table = StringTable::default();
        for def in defs {
            let key = strip(&def.id).to_string();
            if table.slots.contains_key(&key) {
                continue;
            }
            let slot = table.order.len() as u32;
            table.slots.insert(key, slot);
            table.order.push(def.id.clone());
        }
        table
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// The slot for `name`, accepting it with or without the leading `$`.
    pub fn resolve(&self, name: &str) -> Option<u32> {
        self.slots.get(strip(name)).copied()
    }

    /// The identifier as defined, for `$0` in a disassembly or a report.
    pub fn name_of(&self, slot: u32) -> Option<&str> {
        self.order.get(slot as usize).map(String::as_str)
    }

    /// Expand a set into slots, in definition order.
    ///
    /// Membership is tested by walking the definitions rather than the set, so
    /// a set that names the same string twice — `($a, $a*)` — yields one slot.
    /// Anything else would make `all of ($a, $a*)` impossible to satisfy and
    /// `2 of ($a, $a*)` satisfiable by a single match.
    ///
    /// Returns `(slots, rendered_set)`; the rendering is for the error a caller
    /// raises when the expansion comes out empty.
    pub fn expand(&self, set: &StringSet) -> (Vec<u32>, String) {
        match set {
            StringSet::All => ((0..self.order.len() as u32).collect(), "them".to_string()),
            StringSet::List { names, prefixes } => {
                let mut slots = Vec::new();
                let mut rendered = String::new();
                for (index, id) in self.order.iter().enumerate() {
                    let bare = strip(id);
                    let named = names.iter().any(|n| strip(n) == bare);
                    let prefixed = prefixes.iter().any(|p| bare.starts_with(strip(p)));
                    if named || prefixed {
                        slots.push(index as u32);
                    }
                }
                rendered.push('(');
                for (i, n) in names.iter().enumerate() {
                    if i > 0 {
                        rendered.push_str(", ");
                    }
                    rendered.push('$');
                    rendered.push_str(strip(n));
                }
                for (i, p) in prefixes.iter().enumerate() {
                    if i > 0 || !names.is_empty() {
                        rendered.push_str(", ");
                    }
                    rendered.push('$');
                    rendered.push_str(strip(p));
                    rendered.push('*');
                }
                rendered.push(')');
                (slots, rendered)
            }
        }
    }
}

fn strip(name: &str) -> &str {
    name.strip_prefix('$').unwrap_or(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Modifiers, Span, StringValue};

    fn defs(ids: &[&str]) -> Vec<StringDef> {
        ids.iter()
            .map(|id| StringDef {
                id: (*id).to_string(),
                value: StringValue::Text(b"x".to_vec()),
                modifiers: Modifiers::default(),
                span: Span::new(0, 0),
            })
            .collect()
    }

    fn list(names: &[&str], prefixes: &[&str]) -> StringSet {
        StringSet::List {
            names: names.iter().map(|s| (*s).to_string()).collect(),
            prefixes: prefixes.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn a_definition_and_a_reference_agree_on_the_slot() {
        let t = StringTable::from_defs(&defs(&["$a", "$b"]));
        // `$a` is how a set writes it; `a` is how `#a` writes it.
        assert_eq!(t.resolve("$a"), Some(0));
        assert_eq!(t.resolve("a"), Some(0));
        assert_eq!(t.resolve("$b"), Some(1));
        assert_eq!(t.resolve("b"), Some(1));
        assert_eq!(t.resolve("c"), None);
    }

    #[test]
    fn them_is_every_slot_in_definition_order() {
        let t = StringTable::from_defs(&defs(&["$a", "$b", "$c"]));
        let (slots, rendered) = t.expand(&StringSet::All);
        assert_eq!(slots, vec![0, 1, 2]);
        assert_eq!(rendered, "them");
    }

    #[test]
    fn a_prefix_expands_to_the_definitions_it_covers() {
        let t = StringTable::from_defs(&defs(&["$a1", "$a2", "$b1"]));
        let (slots, _) = t.expand(&list(&[], &["a"]));
        assert_eq!(slots, vec![0, 1]);
    }

    #[test]
    fn a_set_that_names_one_string_twice_yields_one_slot() {
        // The bug this prevents: `2 of ($a, $a*)` becoming satisfiable by `$a`
        // matching once.
        let t = StringTable::from_defs(&defs(&["$a", "$b"]));
        let (slots, _) = t.expand(&list(&["a"], &["a"]));
        assert_eq!(slots, vec![0]);
    }

    #[test]
    fn expansion_follows_definition_order_not_the_order_written() {
        // Sets are written in whatever order reads best; slots come out in
        // definition order so the bytecode is a function of the source alone.
        let t = StringTable::from_defs(&defs(&["$a", "$b", "$c"]));
        let (slots, _) = t.expand(&list(&["c", "a"], &[]));
        assert_eq!(slots, vec![0, 2]);
    }

    #[test]
    fn an_unmatched_prefix_expands_to_nothing_and_renders_for_the_error() {
        let t = StringTable::from_defs(&defs(&["$a"]));
        let (slots, rendered) = t.expand(&list(&[], &["zz"]));
        assert!(slots.is_empty());
        assert_eq!(rendered, "($zz*)");
    }

    #[test]
    fn an_anonymous_string_gets_a_stable_slot_like_any_other() {
        // `$ = "a" $ = "b"` — the parser synthesises `$anon1`, `$anon2`, and
        // `them` must still reach both.
        let t = StringTable::from_defs(&defs(&["$anon1", "$anon2"]));
        assert_eq!(t.len(), 2);
        assert_eq!(t.resolve("anon2"), Some(1));
        assert_eq!(t.name_of(1), Some("$anon2"));
    }

    #[test]
    fn a_repeated_definition_does_not_claim_two_slots() {
        let t = StringTable::from_defs(&defs(&["$a", "$a", "$b"]));
        assert_eq!(t.len(), 2);
        assert_eq!(t.resolve("b"), Some(1));
    }
}
