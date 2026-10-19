//! What can go wrong loading a rule file.

use thiserror::Error;

/// A rule file that will not do.
///
/// Both variants are compile-time mistakes rather than runtime ones — a rule
/// file is read once, at load, and a bad one is refused whole. That is
/// deliberate: a rule set loaded halfway is a product whose behaviour depends on
/// how far down a file it read before something was wrong.
#[derive(Debug, Error)]
pub enum LoadError {
    /// The text is not TOML, or not this schema.
    #[error("the rule file could not be read: {message}")]
    Syntax {
        /// The parser's own message, which names the line and column.
        message: String,
    },

    /// A rule that parses but could never work.
    #[error("rule {id} cannot work: {reason}")]
    Invalid {
        /// The rule's identifier, so a file with forty rules points at one.
        id: String,
        /// What is wrong with it.
        reason: String,
    },
}
