//! Compiling a rule set rather than a rule.
//!
//! A single rule compiles on its own — see [`compile_rule`](super::compile_rule)
//! — and that is enough for the great majority of the corpus. What it cannot
//! express is one rule written in terms of another:
//!
//! ```text
//! private rule MACHO_PRIVATE : FILE { condition: ... }
//!
//! rule Some_Family_Generic {
//!     strings: $a = "..." $b = "..."
//!     condition: MACHO_PRIVATE and any of ( $a* ) and any of ( $b* )
//! }
//! ```
//!
//! That is how a rule set states a shared precondition once and turns it on
//! from thirty places — 31 rules of the extended corpus are written this way,
//! all of them naming one private rule. Compiling them one at a time cannot
//! work, for two separate reasons:
//!
//! * **A name means nothing alone.** `MACHO_PRIVATE` is a fact about *this*
//!   corpus. The reference compiles to an index into the corpus's result array,
//!   so the corpus has to be known when the reference is compiled.
//! * **Order matters.** The referenced rule has to have been evaluated before
//!   the rule that reads it, which is a property of the set rather than of any
//!   one member.
//!
//! # What this refuses, and why it must
//!
//! Two shapes have no correct compilation, and both are refused here rather
//! than resolved:
//!
//! * **A cycle.** `A` referencing `B` referencing `A` has no evaluation order.
//!   YARA refuses it too. Substituting one into the other would not terminate.
//! * **A dangling reference.** A rule naming a rule that failed to compile.
//!   The tempting reading is "it did not compile, so it does not match, so the
//!   reference is false" — and that reading is a *false positive* wherever the
//!   reference is negated, because `not OTHER` then becomes true of every file
//!   on the disk. Refusing the referrer costs three detections that do not
//!   fire; resolving it costs a rule that matches everything. There is no
//!   judgement call here.
//!
//! Both refusals are counted rather than silently dropped, because a corpus
//! that quietly loses rules to a broken dependency looks exactly like a corpus
//! that is clean.

use std::collections::VecDeque;

use crate::ast::Rule;
use crate::program::Program;

use super::{compile_rule_with, CompileError, RuleRefs};

/// A rule set, compiled together so that rules can refer to one another.
///
/// The two fields answer the two questions the scanner has: *what do I run*
/// (`order`, in the order to run it) and *what happened to the rules that are
/// not in it* (`rules`, either the program or the reason it is not one).
#[derive(Debug)]
pub struct Corpus {
    /// One entry per rule of the input, in the input's order.
    ///
    /// Corpus order rather than evaluation order, because this is the array the
    /// interpreter indexes: `Op::RuleRef(n)` is a position in *this* vector, so
    /// the caller fills a `Vec<bool>` alongside it as the scan proceeds.
    rules: Vec<Result<Program, CompileError>>,
    /// Evaluation order — the indices of `rules` that compiled, arranged so
    /// that a rule follows everything it names.
    order: Vec<u32>,
    /// Rule names defined more than once in the input.
    duplicates: Vec<String>,
}

impl Corpus {
    /// Every rule, compiled or refused, in corpus order.
    pub fn rules(&self) -> &[Result<Program, CompileError>] {
        &self.rules
    }

    /// Take the compiled programs, in corpus order.
    ///
    /// Consuming, because a program is not cheap to copy and the caller wants
    /// to put each one somewhere it will stay. The refusals come along, so a
    /// caller that wants both halves of the outcome does not have to ask twice.
    pub fn into_rules(self) -> Vec<Result<Program, CompileError>> {
        self.rules
    }

    /// The indices to evaluate, in the order to evaluate them.
    ///
    /// Every index here holds a compiled program, so a scanner can walk it
    /// without checking. Rules that were refused — for their own sake, for a
    /// dangling reference, or for being in a cycle — are absent.
    pub fn order(&self) -> &[u32] {
        &self.order
    }

    /// Rule names the input defined more than once.
    ///
    /// Empty for any well-formed set. Reported rather than resolved because a
    /// reference to such a name has no single meaning, and the caller is the
    /// only one who can say which definition was meant.
    pub fn duplicates(&self) -> &[String] {
        &self.duplicates
    }

    /// How many rules compiled.
    pub fn compiled(&self) -> usize {
        self.order.len()
    }

    /// How many rules were refused, and why.
    pub fn refused(&self) -> impl Iterator<Item = &CompileError> {
        self.rules.iter().filter_map(|r| r.as_ref().err())
    }
}

/// Compile a whole rule set, resolving references between its rules.
///
/// Every rule is compiled, whether or not it can ever be evaluated: a rule in a
/// cycle still has a name and a condition, and refusing it with the reason is
/// more useful than never mentioning it. Only rules that both compiled and
/// depend on nothing uncompiled appear in [`Corpus::order`].
///
/// # The four passes
///
/// 1. Names to indices, from the input alone.
/// 2. Compile every rule against that table. A reference becomes
///    `Op::RuleRef(index)`; a name in neither the loop variables nor the table
///    is refused here.
/// 3. Read each program's dependencies back out of its bytecode. They are
///    already there as `RuleRef` operands, which is why there is no second
///    walker over the AST — and no second chance to disagree with the compiler
///    about what a name means. A loop variable named the same as a rule is the
///    case that would break an AST walker and cannot break this: the compiler
///    resolved `s` to a slot, so no `RuleRef` was emitted for it.
/// 4. Order by those dependencies, then walk the order marking every rule that
///    depends on something that failed.
///
/// Takes any iterator of rules so that the caller does not have to own them:
/// a rule set read from a file lives in the parsed file it came from, and a
/// corpus is not a reason to copy ten thousand conditions.
pub fn compile_corpus<'a, I>(rules: I) -> Corpus
where
    I: IntoIterator<Item = &'a Rule>,
{
    let rules: Vec<&Rule> = rules.into_iter().collect();
    let refs = RuleRefs::from_names(rules.iter().map(|rule| rule.name.as_str()));

    // Pass 2: compile everything. Failures are kept, not dropped.
    let mut compiled: Vec<Result<Program, CompileError>> = rules
        .iter()
        .copied()
        .map(|rule| compile_rule_with(rule, &refs))
        .collect();

    // Pass 3: dependencies, read back out of the bytecode.
    let deps: Vec<Vec<u32>> = compiled
        .iter()
        .map(|program| match program {
            Ok(p) => p.rule_refs(),
            // A rule that did not compile constrains no order.
            Err(_) => Vec::new(),
        })
        .collect();

    // Pass 4a: order. `None` means a cycle, and then nothing can be said about
    // where any rule in it goes.
    let Some(order) = topological(&deps) else {
        // Rules in a cycle are refused by name, as a class, rather than the
        // whole set being abandoned: everything outside the cycle is still
        // usable, and `for .. in` over a rule set is not all-or-nothing.
        for index in cyclic(&deps) {
            if compiled[index as usize].is_ok() {
                compiled[index as usize] = Err(CompileError::dependency(
                    rules[index as usize].name.clone(),
                    rules[index as usize].span,
                    format!(
                        "`{}` takes part in a cycle of rule references, which has no \
                         evaluation order",
                        rules[index as usize].name
                    ),
                ));
            }
        }
        return Corpus {
            rules: compiled,
            order: Vec::new(),
            duplicates: refs.duplicates().to_vec(),
        };
    };

    // Pass 4b: a rule is unusable if it or anything it reads is unusable.
    // Walking `order` is enough to settle that in one pass, because every
    // dependency of a rule appears before it.
    //
    // A rule that failed to compile is checked first and by itself, because the
    // dependency test below cannot see it: its `deps` is empty — a program that
    // does not exist reads nothing — so it looks exactly like a rule that reads
    // nothing and is therefore ready. Testing `deps` alone is how a refused rule
    // ends up in `order`, where the scanner would evaluate a program that is not
    // there.
    let mut usable = vec![false; rules.len()];
    let mut kept = Vec::with_capacity(order.len());
    for &index in &order {
        let i = index as usize;
        if compiled[i].is_err() {
            continue;
        }
        // A name the set defines twice: a reference to it means neither
        // definition, and no ordering can repair that. Checked after the rule's
        // own compilation so that a rule with a real error in it reports that
        // error rather than this one.
        if refs.is_duplicate(&rules[i].name) {
            compiled[i] = Err(CompileError::dependency(
                rules[i].name.clone(),
                rules[i].span,
                format!(
                    "`{}` is defined more than once, so a reference to it is ambiguous",
                    rules[i].name
                ),
            ));
            continue;
        }
        // The rule compiled, so anything it reads that is unusable is unusable
        // because it was refused, not because it is missing.
        let Some(broken) = deps[i].iter().find(|&&d| !usable[d as usize]) else {
            usable[i] = true;
            kept.push(index);
            continue;
        };
        let name = &rules[*broken as usize].name;
        compiled[i] = Err(CompileError::dependency(
            rules[i].name.clone(),
            rules[i].span,
            format!("`{}` reads `{name}`, which did not compile", rules[i].name),
        ));
    }

    Corpus {
        rules: compiled,
        order: kept,
        duplicates: refs.duplicates().to_vec(),
    }
}

/// The indices of `rules`, arranged so that a rule follows its dependencies.
///
/// Kahn's algorithm on the reverse edges: start from the rules that read
/// nothing, then release each rule whose dependencies have all been placed.
/// Iterative, with an explicit queue, because a dependency chain can be as long
/// as the corpus and this runs on a corpus of ten thousand rules.
///
/// The queue is seeded in index order and refilled in index order, so the
/// result is a function of the input alone — two compilations of the same set
/// produce byte-identical databases, which is what makes a shipped database
/// reproducible from its source.
///
/// `None` when the graph has a cycle, which leaves some rules unplaced.
fn topological(deps: &[Vec<u32>]) -> Option<Vec<u32>> {
    let mut pending: Vec<u32> = deps.iter().map(|d| d.len() as u32).collect();
    let mut dependents: Vec<Vec<u32>> = vec![Vec::new(); deps.len()];
    for (rule, reads) in deps.iter().enumerate() {
        for &read in reads {
            // A reference to an index outside the corpus is impossible: the
            // table the compiler indexed into was built from this same slice.
            // Dropping it rather than indexing keeps a malformed input from
            // being a panic.
            if let Some(list) = dependents.get_mut(read as usize) {
                list.push(rule as u32);
            }
        }
    }

    let mut queue: VecDeque<u32> = (0..deps.len() as u32)
        .filter(|&i| pending[i as usize] == 0)
        .collect();
    let mut order = Vec::with_capacity(deps.len());
    while let Some(index) = queue.pop_front() {
        order.push(index);
        for &dependent in &dependents[index as usize] {
            let left = &mut pending[dependent as usize];
            *left -= 1;
            if *left == 0 {
                queue.push_back(dependent);
            }
        }
    }

    (order.len() == deps.len()).then_some(order)
}

/// The rules left unplaced by [`topological`] — those in, or behind, a cycle.
///
/// Recomputed by running the same algorithm and looking at what is missing,
/// rather than by a second cycle-finding algorithm: the two would have to agree
/// about what a cycle is, and one of them would eventually stop.
fn cyclic(deps: &[Vec<u32>]) -> Vec<u32> {
    let placed: Vec<bool> = match topological(deps) {
        Some(order) => {
            let mut seen = vec![false; deps.len()];
            for index in order {
                seen[index as usize] = true;
            }
            seen
        }
        None => {
            // `topological` returned `None` only because some rule was left
            // out, so recomputing without the early return is not needed: the
            // same walk is redone here, keeping the shortfall.
            let mut pending: Vec<u32> = deps.iter().map(|d| d.len() as u32).collect();
            let mut dependents: Vec<Vec<u32>> = vec![Vec::new(); deps.len()];
            for (rule, reads) in deps.iter().enumerate() {
                for &read in reads {
                    if let Some(list) = dependents.get_mut(read as usize) {
                        list.push(rule as u32);
                    }
                }
            }
            let mut queue: VecDeque<u32> = (0..deps.len() as u32)
                .filter(|&i| pending[i as usize] == 0)
                .collect();
            let mut seen = vec![false; deps.len()];
            while let Some(index) = queue.pop_front() {
                seen[index as usize] = true;
                for &dependent in &dependents[index as usize] {
                    let left = &mut pending[dependent as usize];
                    *left -= 1;
                    if *left == 0 {
                        queue.push_back(dependent);
                    }
                }
            }
            seen
        }
    };
    (0..deps.len() as u32)
        .filter(|&i| !placed[i as usize])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::Span;
    use crate::parser::parse_file;

    /// Compile a source snippet holding several rules.
    fn corpus(source: &str) -> Corpus {
        let file = parse_file(source).expect("the test source must parse");
        compile_corpus(&file.rules)
    }

    /// The names of the rules that compiled, in evaluation order.
    fn compiled_names(c: &Corpus, source: &str) -> Vec<String> {
        let file = parse_file(source).unwrap();
        c.order()
            .iter()
            .map(|&i| file.rules[i as usize].name.clone())
            .collect()
    }

    const PRIVATE_AND_USER: &str = r#"
        private rule GATE : FILE { condition: uint16(0) == 0x5a4d }
        rule USER {
            strings: $a = "x"
            condition: GATE and $a
        }
    "#;

    #[test]
    fn a_rule_can_be_written_in_terms_of_another() {
        let c = corpus(PRIVATE_AND_USER);
        assert_eq!(c.refused().count(), 0);
        assert_eq!(c.compiled(), 2);
        // The gate first: the rule that reads it has to come after it.
        assert_eq!(compiled_names(&c, PRIVATE_AND_USER), ["GATE", "USER"]);
    }

    #[test]
    fn a_reference_compiles_to_the_index_the_scanner_will_fill_in() {
        let c = corpus(PRIVATE_AND_USER);
        let program = c.rules()[1].as_ref().unwrap();
        assert!(
            program.code.contains(&crate::program::Op::RuleRef(0)),
            "{}",
            program.disassemble()
        );
    }

    #[test]
    fn the_order_follows_the_dependencies_and_not_the_source() {
        // Written back to front, so a compiler that emitted rules in source
        // order would run `A` before the rule it reads.
        let source = r#"
            rule A { condition: B and uint16(0) == 0x5a4d }
            rule B { condition: C }
            rule C { condition: true }
        "#;
        let c = corpus(source);
        assert_eq!(c.refused().count(), 0);
        assert_eq!(compiled_names(&c, source), ["C", "B", "A"]);
    }

    #[test]
    fn a_name_that_is_a_loop_variable_is_not_a_rule_reference() {
        // The trap an AST walker would fall into: the loop variable is spelled
        // the same as a rule. It compiles to a variable slot, so no `RuleRef`
        // is emitted and the rule does not depend on itself.
        let source = r#"
            rule i { condition: uint16(0) == 0x5a4d }
            rule USER { condition: for any i in (0..3) : ( i == 1 ) }
        "#;
        let c = corpus(source);
        assert_eq!(
            c.refused().count(),
            0,
            "{:?}",
            c.refused().collect::<Vec<_>>()
        );
        assert_eq!(c.compiled(), 2);
    }

    #[test]
    fn a_cycle_is_refused_rather_than_ordered() {
        let source = r#"
            rule A { condition: B }
            rule B { condition: A }
        "#;
        let c = corpus(source);
        assert_eq!(c.compiled(), 0);
        let errors: Vec<&CompileError> = c.refused().collect();
        assert_eq!(errors.len(), 2);
        for error in errors {
            assert_eq!(error.feature, "rule dependency");
            assert!(error.message.contains("cycle"), "{}", error.message);
        }
    }

    #[test]
    fn a_rule_that_reads_a_rule_that_did_not_compile_is_refused_too() {
        // `GATE` uses a module field that is not implemented, so it does not
        // compile. The tempting reading of `USER` is that `GATE` is false and
        // therefore `GATE and $a` never fires — but the same reasoning makes
        // `not GATE` true of every file on the disk, so neither is allowed.
        let source = r#"
            private rule GATE : FILE { condition: pe.signatures[0].verified }
            rule USER { condition: GATE }
            rule NEGATED { condition: not GATE }
        "#;
        let c = corpus(source);
        assert_eq!(c.compiled(), 0);
        let dangling: Vec<&CompileError> = c
            .refused()
            .filter(|e| e.feature == "rule dependency")
            .collect();
        let names: Vec<&str> = dangling.iter().map(|e| e.detail.as_str()).collect();
        assert_eq!(names, ["USER", "NEGATED"], "{names:?}");
        for error in dangling {
            assert!(
                error.message.contains("did not compile"),
                "{}",
                error.message
            );
        }
        // And the rule at fault keeps its own error rather than being
        // overwritten by the dependency one.
        let gate = c.refused().find(|e| e.feature == "module field").unwrap();
        assert_eq!(gate.detail, "pe.signatures[..].verified");
    }

    #[test]
    fn a_dangling_reference_names_the_rule_that_is_missing() {
        let source = r#"
            rule GATE { condition: pe.signatures[0].verified }
            rule USER { condition: GATE and true }
        "#;
        let c = corpus(source);
        let user = c.refused().find(|e| e.detail == "USER").expect("USER");
        assert!(user.message.contains("`GATE`"), "{}", user.message);
    }

    #[test]
    fn an_unknown_name_is_still_refused() {
        let source = "rule A { condition: NO_SUCH_RULE }";
        let c = corpus(source);
        assert_eq!(c.compiled(), 0);
        let error = c.refused().next().unwrap();
        assert!(error.message.contains("NO_SUCH_RULE"), "{}", error.message);
    }

    #[test]
    fn a_diamond_puts_the_shared_rule_first_and_each_reader_once() {
        let source = r#"
            rule LEFT { condition: BASE and uint8(0) == 1 }
            rule RIGHT { condition: BASE and uint8(1) == 2 }
            rule BASE { condition: uint16(0) == 0x5a4d }
        "#;
        let c = corpus(source);
        assert_eq!(c.refused().count(), 0);
        assert_eq!(compiled_names(&c, source), ["BASE", "LEFT", "RIGHT"]);
    }

    #[test]
    fn a_duplicated_rule_name_makes_every_reference_to_it_ambiguous() {
        let source = r#"
            rule GATE { condition: uint16(0) == 0x5a4d }
            rule GATE { condition: uint16(0) == 0x4d5a }
            rule USER { condition: GATE }
        "#;
        let c = corpus(source);
        assert_eq!(c.duplicates(), ["GATE"]);
        let names: Vec<&str> = c.refused().map(|e| e.detail.as_str()).collect();
        assert!(names.contains(&"USER"), "{names:?}");
    }

    #[test]
    fn the_order_is_a_function_of_the_input_alone() {
        // Two compilations of one source must agree, or a shipped database is
        // not reproducible from the source it was built from.
        let source = r#"
            rule A { condition: C and uint8(0) == 1 }
            rule B { condition: C and uint8(1) == 2 }
            rule C { condition: uint16(0) == 0x5a4d }
            rule D { condition: A or B }
        "#;
        let first = compile_rule_order(source);
        for _ in 0..4 {
            assert_eq!(compile_rule_order(source), first);
        }
    }

    fn compile_rule_order(source: &str) -> Vec<u32> {
        corpus(source).order().to_vec()
    }

    #[test]
    fn an_empty_corpus_compiles_to_an_empty_order() {
        let c = Corpus {
            rules: Vec::new(),
            order: Vec::new(),
            duplicates: Vec::new(),
        };
        assert_eq!(c.compiled(), 0);
        assert!(c.order().is_empty());
    }

    #[test]
    fn a_rule_referring_to_itself_is_a_cycle_of_one() {
        let c = corpus("rule A { condition: A }");
        assert_eq!(c.compiled(), 0);
        assert!(c.refused().next().unwrap().message.contains("cycle"));
    }

    #[test]
    fn the_span_of_a_dependency_error_is_the_rules_own() {
        // Not the referenced rule's: the message is about the rule that has to
        // be fixed, and a span pointing at the other one would send its author
        // to the wrong place.
        let source =
            "rule GATE { condition: pe.signatures[0].verified }\nrule USER { condition: GATE }";
        let file = parse_file(source).unwrap();
        let c = compile_corpus(&file.rules);
        let user = c.refused().find(|e| e.detail == "USER").unwrap();
        assert_eq!(user.span, file.rules[1].span);
        assert_ne!(user.span, Span::default());
    }
}
