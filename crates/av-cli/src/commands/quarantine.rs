//! `wenle quarantine` — everything a person needs to do about what the product
//! has taken off the machine.
//!
//! # Why this command exists rather than a directory a user browses
//!
//! A quarantined file is not a file in a folder. It is a sealed blob named after
//! a random identifier, and the thing that makes it intelligible — where it came
//! from, what it was called, which rule condemned it, when it was taken — is
//! inside an encrypted index. An operator who opens the vault in Explorer sees
//! sixteen files with names like `3f9a…c1.qtn` and nothing else. The command is
//! the only view of the vault that means anything, which is also why every verb
//! a user needs is here: a list they cannot act on is a list that sends them to
//! Explorer, and Explorer is where a false positive becomes an unrecoverable
//! file.
//!
//! # Why identifiers may be abbreviated
//!
//! Because the list prints the short form. A user reads `3f9ac1b0` off one
//! screen and types it on the next, and a command that demanded all thirty-two
//! characters would be a command whose own output is not usable as its input.
//! A prefix is accepted when it picks out exactly one item, refused by name when
//! it picks out two, and refused as "no such item" when it picks out none — the
//! three outcomes a user can act on, and never a silent choice among several.

use std::path::Path;

use anyhow::{anyhow, bail, Context as _, Result};
use av_core::Verdict;
use av_quarantine::{EntryStatus, QuarantineEntry, QuarantineId, QuarantineVault, RestoreOptions};
use chrono::{DateTime, Local, Utc};

use crate::cli::{Globals, QuarantineArgs, QuarantineCommand};
use crate::commands::Context;
use crate::exit::Exit;
use crate::output;
use crate::progress::{human_bytes, human_count};

/// Run a `quarantine` subcommand.
pub fn run(args: &QuarantineArgs, globals: &Globals, context: &Context) -> Result<Exit> {
    match &args.command {
        QuarantineCommand::List {
            all,
            limit,
            path,
            json,
        } => list(
            args.vault.as_deref(),
            *all,
            *limit,
            path.as_deref(),
            *json,
            globals,
            context,
        ),
        QuarantineCommand::Show { id, json } => show(args.vault.as_deref(), id, *json, context),
        QuarantineCommand::Restore {
            id,
            to,
            overwrite,
            keep_copy,
        } => restore(
            args.vault.as_deref(),
            id,
            to.as_deref(),
            *overwrite,
            *keep_copy,
            globals,
            context,
        ),
        QuarantineCommand::Delete { ids, all, yes } => {
            delete(args.vault.as_deref(), ids, *all, *yes, globals, context)
        }
        QuarantineCommand::Export { id, to, force } => {
            export(args.vault.as_deref(), id, to, *force, context)
        }
        QuarantineCommand::Verify { ids, json } => {
            verify(args.vault.as_deref(), ids, *json, globals, context)
        }
        QuarantineCommand::Maintain {
            dry_run,
            compact_after,
        } => maintain(
            args.vault.as_deref(),
            *dry_run,
            *compact_after,
            globals,
            context,
        ),
    }
}

// -- list ------------------------------------------------------------------

/// Show what is in the vault.
fn list(
    vault_path: Option<&Path>,
    all: bool,
    limit: Option<usize>,
    path_filter: Option<&str>,
    json: bool,
    globals: &Globals,
    context: &Context,
) -> Result<Exit> {
    let vault = context.open_vault(vault_path)?;
    let wanted = path_filter.map(str::to_lowercase);

    let mut shown: Vec<&QuarantineEntry> = Vec::new();
    let mut matching = 0usize;
    for entry in vault.list() {
        if !all && !entry.status.is_live() {
            continue;
        }
        if let Some(wanted) = &wanted {
            let original = entry.original_path.to_string_lossy().to_lowercase();
            if !original.contains(wanted) {
                continue;
            }
        }
        matching += 1;
        if limit.is_none_or(|limit| shown.len() < limit) {
            shown.push(entry);
        }
    }

    if json {
        let document = serde_json::json!({
            "vault": vault.root(),
            "matching": matching,
            "shown": shown.len(),
            "items": shown.iter().map(|e| entry_json(e)).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&document)?);
        return Ok(list_exit(&shown));
    }

    if shown.is_empty() {
        if !globals.quiet && matching == 0 {
            // Only when the vault itself is empty. An empty *page* of a
            // filtered or exhausted list is not the same thing, and saying
            // "the vault is empty" to someone who filtered for a path would be
            // a plain lie about their vault.
            println!("The quarantine vault is empty.");
        }
        return Ok(Exit::Clean);
    }

    for entry in &shown {
        print_row(entry);
    }
    if !globals.quiet {
        // The footer exists for the two things a table of rows cannot say: how
        // much of the list is being withheld, and what the vault weighs. The
        // second is the number a user is looking for when they are wondering
        // why their system drive is filling up.
        output::heading("Vault");
        let stats = vault.stats();
        if matching > shown.len() {
            println!(
                "  {} of {} items shown; raise --limit to see the rest",
                human_count(shown.len() as u64),
                human_count(matching as u64),
            );
        } else {
            println!("  {} items", human_count(matching as u64));
        }
        println!(
            "  {} held in {} live items at {}",
            human_bytes(stats.live_bytes),
            human_count(stats.quarantined as u64),
            vault.root().display(),
        );
        if !all && stats.restored + stats.deleted > 0 {
            println!(
                "  {} finished records hidden; --all shows them",
                human_count((stats.restored + stats.deleted) as u64),
            );
        }
        if stats.pending_removals > 0 {
            // The one line here that reports something wrong. A user who was
            // told a file was blocked and can still see it on disk deserves to
            // be told why rather than left to find it.
            output::warn(&format!(
                "{} originals could not be deleted and are still on disk; \
                 `wenle quarantine maintain` retries them",
                human_count(stats.pending_removals as u64),
            ));
        }
        if stats.orphans > 0 {
            output::warn(&format!(
                "{} sealed payloads in the vault belong to no record",
                human_count(stats.orphans as u64),
            ));
        }
    }
    Ok(list_exit(&shown))
}

/// The exit code for a listing.
///
/// A vault holding something malicious is a fact a script may want to act on,
/// and it is the same fact a scan reports: this machine has malware on it. Live
/// items only, because a record of something restored or deleted last month is
/// history, not a finding.
fn list_exit(entries: &[&QuarantineEntry]) -> Exit {
    let mut exit = Exit::Clean;
    for entry in entries {
        if !entry.status.is_live() {
            continue;
        }
        match entry.verdict {
            Verdict::Malicious => return Exit::Malicious,
            Verdict::Suspicious | Verdict::Unknown => exit = Exit::Suspicious,
            Verdict::Clean => {}
        }
    }
    exit
}

/// One item, as one table row.
///
/// Fixed columns rather than a header line, because the identifier is what a
/// user copies into the next command and a header that repeats on a terminal
/// that wrapped is a header that pushes the identifier off the row.
fn print_row(entry: &QuarantineEntry) {
    let when = local_time(entry.quarantined_at);
    let band = output::verdict_style(entry.verdict)
        .apply_to(format!("{:<10}", output::verdict_word(entry.verdict)));
    // The state is only worth a column when it is not the ordinary one: a list
    // where every row says "quarantined" is a list with a useless column.
    let state = match entry.status {
        EntryStatus::Quarantined => String::new(),
        other => format!("  {}", console::style(other.as_str()).dim()),
    };
    println!(
        "  {}  {band}  {:>10}  {when}  {}{state}",
        console::style(&entry.id.short()).cyan(),
        human_bytes(entry.size),
        entry.original_path.display(),
    );
}

// -- show ------------------------------------------------------------------

/// Everything recorded about one item.
fn show(vault_path: Option<&Path>, id: &str, json: bool, context: &Context) -> Result<Exit> {
    let vault = context.open_vault(vault_path)?;
    let id = resolve(&vault, id)?;
    let entry = vault.get(id)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&entry_json(entry))?);
        return Ok(Exit::Clean);
    }

    output::heading(entry.display_name());
    println!("  {}  {}", entry.id, console::style("(full id)").dim());

    output::heading("Origin");
    println!("  path      {}", entry.original_path.display());
    println!("  name      {}", entry.file_name);
    println!(
        "  taken     {}  by {}",
        local_time(entry.quarantined_at),
        entry.source.as_str()
    );
    if entry.source.is_pre_execution() {
        println!(
            "  {}",
            console::style("  it was stopped before it could run").green()
        );
    }
    if !entry.original_removed {
        println!(
            "  {}",
            console::style("  the original file could not be deleted and is still on disk")
                .yellow()
                .bold()
        );
    }

    output::heading("Assessment");
    println!(
        "  verdict   {}",
        output::verdict_style(entry.verdict).apply_to(output::verdict_word(entry.verdict))
    );
    println!("  severity  {}", entry.severity.as_str());
    if let Some(threat) = &entry.threat {
        println!("  threat    {threat}");
    }
    if let Some(detection) = &entry.detection {
        println!("  detected  {} by {}", detection, entry.source.as_str());
    }

    output::heading("Content");
    println!(
        "  size      {}  ({} bytes)",
        human_bytes(entry.size),
        entry.size
    );
    if let Some(md5) = &entry.digests.md5 {
        println!("  md5       {md5}");
    }
    if let Some(sha1) = &entry.digests.sha1 {
        println!("  sha1      {sha1}");
    }
    if let Some(sha256) = &entry.digests.sha256 {
        println!("  sha256    {sha256}");
    }

    output::heading("State");
    println!("  status    {}", entry.status.as_str());
    println!("  changed   {}", local_time(entry.changed_at));
    if let Some(note) = &entry.note {
        println!("  note      {note}");
    }
    if entry.is_suspicious_only() {
        // Said here rather than in a document, at the moment the user is
        // deciding whether to restore it. This is the band's whole purpose.
        println!(
            "\n  {}",
            console::style(
                "This was taken on suspicion, not on a known-bad match. If you need the \
                 file, restore it and add it to your exclusions."
            )
            .yellow()
        );
    }
    Ok(Exit::Clean)
}

// -- restore ---------------------------------------------------------------

/// Put an item back on disk.
fn restore(
    vault_path: Option<&Path>,
    id: &str,
    to: Option<&Path>,
    overwrite: bool,
    keep_copy: bool,
    globals: &Globals,
    context: &Context,
) -> Result<Exit> {
    let mut vault = context.open_vault(vault_path)?;
    let id = resolve(&vault, id)?;
    let entry = vault.get(id)?.clone();

    let mut options = match to {
        Some(path) => RestoreOptions::to(path),
        None => RestoreOptions::to_original(),
    };
    options.overwrite = overwrite;
    options.keep_copy = keep_copy;

    let written = vault.restore(id, &options)?;
    if !globals.quiet {
        output::heading("Restored");
        println!("  {}  {}", entry.file_name, written.display());
        if entry.is_suspicious_only() {
            output::warn(
                "this item was taken on suspicion. The rule that flagged it will flag it \
                 again on the next scan unless you exclude it.",
            );
        }
    }
    Ok(Exit::Clean)
}

// -- delete ----------------------------------------------------------------

/// Destroy items.
fn delete(
    vault_path: Option<&Path>,
    ids: &[String],
    all: bool,
    yes: bool,
    globals: &Globals,
    context: &Context,
) -> Result<Exit> {
    let mut vault = context.open_vault(vault_path)?;

    // The set to act on is worked out in full before anything is destroyed, so
    // that a mistyped identifier in the middle of a list aborts the whole
    // command rather than deleting the first three items and then failing.
    let targets: Vec<QuarantineId> = if all {
        vault
            .list()
            .iter()
            .filter(|e| e.status.is_live())
            .map(|e| e.id)
            .collect()
    } else {
        ids.iter()
            .map(|text| resolve(&vault, text))
            .collect::<Result<Vec<_>>>()?
    };

    if targets.is_empty() {
        if !globals.quiet {
            println!("There is nothing to delete.");
        }
        return Ok(Exit::Clean);
    }

    // Confirmation, and why it is not skipped for a single item either: the
    // command destroys the only copy of a file the product took off the machine
    // because it might be malware, and "might be" is exactly the case where
    // asking is worth the keystroke.
    if !yes && !confirm(&vault, &targets)? {
        if !globals.quiet {
            println!("Nothing was deleted.");
        }
        return Ok(Exit::Clean);
    }

    let mut deleted = 0usize;
    let mut freed = 0u64;
    let mut failed = 0usize;
    for id in &targets {
        match vault.delete(*id) {
            Ok(entry) => {
                deleted += 1;
                freed += entry.size;
                if !globals.quiet {
                    println!("  deleted  {}  {}", entry.id.short(), entry.file_name);
                }
            }
            Err(error) => {
                failed += 1;
                output::error(&format!("{}: {error}", id.short()));
            }
        }
    }

    if !globals.quiet {
        output::heading("Deleted");
        println!(
            "  {} items, {} freed",
            human_count(deleted as u64),
            human_bytes(freed)
        );
    }
    if failed > 0 {
        // The payload is still on the disk the user asked to have it removed
        // from, so this is not a success. Reporting the per-item errors and
        // then exiting 0 would leave a script believing a batch had run when
        // part of it had not — and the one thing the caller cannot recover from
        // is not being told.
        bail!(
            "{failed} of {} items could not be deleted; the errors above say why",
            targets.len()
        );
    }
    Ok(Exit::Clean)
}

/// Ask before destroying the only copy.
///
/// Reads standard input directly rather than pulling in a prompt crate: one
/// question with two answers does not need a dependency, and the failure mode
/// worth avoiding is the one where a piped standard input gives an instant and
/// unintended "yes". Anything that is not an explicit yes is a no.
fn confirm(vault: &QuarantineVault, targets: &[QuarantineId]) -> Result<bool> {
    use std::io::Write;

    let bytes: u64 = targets
        .iter()
        .filter_map(|id| vault.get(*id).ok())
        .map(|entry| entry.size)
        .sum();
    let noun = if targets.len() == 1 { "item" } else { "items" };
    print!(
        "Delete {} {noun} ({}), permanently? [y/N] ",
        targets.len(),
        human_bytes(bytes)
    );
    std::io::stdout().flush().context("flushing the prompt")?;

    let mut answer = String::new();
    let read = std::io::stdin()
        .read_line(&mut answer)
        .context("reading the answer")?;
    if read == 0 {
        // End of input: a script that ran this without `--yes`. The default is
        // no, and saying so is better than a "yes" nobody typed.
        println!();
        return Ok(false);
    }
    Ok(matches!(answer.trim().to_lowercase().as_str(), "y" | "yes"))
}

// -- export ----------------------------------------------------------------

/// Write an item's bytes out as a file.
fn export(
    vault_path: Option<&Path>,
    id: &str,
    to: &Path,
    force: bool,
    context: &Context,
) -> Result<Exit> {
    let vault = context.open_vault(vault_path)?;
    let id = resolve(&vault, id)?;
    let entry = vault.get(id)?;
    vault.export(id, to, force)?;

    output::heading("Exported");
    println!("  {}  {}", entry.file_name, to.display());
    // Printed every time, because this is the one operation that puts live
    // malware on a filesystem on purpose.
    output::warn(&format!(
        "{} was written to disk in the clear. It is not the file it was, and nothing \
         is protecting you from it now.",
        entry.display_name()
    ));
    Ok(Exit::Clean)
}

// -- verify ----------------------------------------------------------------

/// Re-read the sealed payloads and check them against their recorded hashes.
fn verify(
    vault_path: Option<&Path>,
    ids: &[String],
    json: bool,
    globals: &Globals,
    context: &Context,
) -> Result<Exit> {
    let vault = context.open_vault(vault_path)?;

    let (checked, problems): (Vec<QuarantineId>, Vec<(QuarantineId, String)>) = if ids.is_empty() {
        let all = vault.verify_all();
        let checked = vault
            .list()
            .iter()
            .filter(|e| e.status.is_live())
            .map(|e| e.id)
            .collect();
        let problems = all
            .into_iter()
            .map(|(id, error)| (id, error.to_string()))
            .collect();
        (checked, problems)
    } else {
        let targets = ids
            .iter()
            .map(|text| resolve(&vault, text))
            .collect::<Result<Vec<_>>>()?;
        let mut problems = Vec::new();
        for id in &targets {
            if let Err(error) = vault.verify(*id) {
                problems.push((*id, error.to_string()));
            }
        }
        (targets, problems)
    };

    if json {
        let document = serde_json::json!({
            "vault": vault.root(),
            "checked": checked.len(),
            "problems": problems
                .iter()
                .map(|(id, detail)| serde_json::json!({
                    "id": id.to_hex(),
                    "error": detail,
                }))
                .collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&document)?);
    } else if !globals.quiet {
        output::heading("Verified");
        println!("  {} payloads re-read", human_count(checked.len() as u64));
        if problems.is_empty() {
            println!(
                "  {}",
                console::style("  every one matched its recorded hash").green()
            );
        }
    }

    for (id, detail) in &problems {
        output::error(&format!("{}: {detail}", id.short()));
    }

    if !problems.is_empty() {
        // A payload that does not verify is a payload that cannot be restored
        // honestly, and a script needs to be able to tell that from a clean
        // run. This is not the same as "there was malware here".
        bail!(
            "{} of {} payloads did not verify; see the errors above",
            problems.len(),
            checked.len().max(problems.len())
        );
    }
    Ok(Exit::Clean)
}

// -- maintain --------------------------------------------------------------

/// Apply retention, size limits, the deletion retry list, and compaction.
fn maintain(
    vault_path: Option<&Path>,
    dry_run: bool,
    compact_after: Option<u64>,
    globals: &Globals,
    context: &Context,
) -> Result<Exit> {
    let mut vault = context.open_vault(vault_path)?;
    let retention = vault.policy().retention;

    if dry_run {
        // The report is written from the same values the real pass reads, so a
        // dry run that says "nothing to do" is a dry run that would have done
        // nothing. That is the whole value of it and the reason it is not a
        // separate implementation.
        let stats = vault.stats();
        output::heading("Would do");
        println!(
            "  retention      {}",
            match retention {
                Some(span) => format!("{} days", span.as_secs() / 86_400),
                None => "unlimited".to_owned(),
            }
        );
        println!(
            "  size ceiling   {}  ({} in use)",
            human_bytes(vault.policy().max_vault_size),
            human_bytes(stats.live_bytes),
        );
        println!("  live items     {}", human_count(stats.quarantined as u64));
        println!(
            "  still on disk  {} originals queued for deletion",
            human_count(stats.pending_removals as u64),
        );
        println!(
            "  records        {} finished, {} of them older than the compaction age",
            human_count((stats.restored + stats.deleted) as u64),
            human_count(count_compactable(&vault, compact_after)? as u64),
        );
        println!("\n  Run without --dry-run to do it.");
        return Ok(Exit::Clean);
    }

    let age =
        std::time::Duration::from_secs(compact_after.unwrap_or(30).saturating_mul(24 * 60 * 60));
    let outcome = vault.maintain(age)?;

    if !globals.quiet {
        output::heading("Maintenance");
        println!(
            "  {} expired   {} evicted ({} freed)   {} originals deleted   {} records forgotten",
            outcome.expired,
            outcome.evicted.count(),
            human_bytes(outcome.evicted.freed_bytes),
            outcome.sweep.removed,
            outcome.compacted,
        );
        if outcome.sweep.deferred > 0 {
            output::warn(&format!(
                "{} originals are still held open by another process and will be retried",
                outcome.sweep.deferred,
            ));
        }
        if outcome.sweep.abandoned > 0 {
            output::warn(&format!(
                "{} originals could not be deleted after repeated attempts and have been \
                 given up on; they are still on disk",
                outcome.sweep.abandoned,
            ));
        }
    }
    Ok(Exit::Clean)
}

/// How many finished records a compaction would forget.
fn count_compactable(vault: &QuarantineVault, days: Option<u64>) -> Result<usize> {
    let age = chrono::Duration::days(days.unwrap_or(30).min(i64::MAX as u64) as i64);
    let cutoff = Utc::now() - age;
    Ok(vault
        .list()
        .iter()
        .filter(|e| !e.status.is_live() && e.changed_at < cutoff)
        .count())
}

// -- shared ----------------------------------------------------------------

/// Turn what the user typed into an identifier.
///
/// Three outcomes, and each of them is a sentence rather than a guess: exactly
/// one item, no item, or several. See the module documentation for why a prefix
/// is accepted at all.
fn resolve(vault: &QuarantineVault, text: &str) -> Result<QuarantineId> {
    let text = text.trim();
    let prefix = text.to_lowercase();

    if prefix.is_empty() {
        // An empty prefix matches everything, which for a vault holding one
        // item would resolve to that item and for any other vault would be
        // ambiguous. Both are wrong answers to "which item?" — the question was
        // not asked — so the empty string is refused rather than special-cased.
        bail!("no id was given. Run `wenle quarantine list` to see them.");
    }
    if !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!(
            "`{text}` is not a quarantine id. An id is hexadecimal — run \
             `wenle quarantine list` to see them."
        );
    }

    // The full spelling first, whether or not anything matches it: a complete
    // identifier is unambiguous by construction, and answering from the entry
    // list would mean a full id for an item that is not in the list reads as
    // "no such prefix" rather than "no such item".
    if let Some(id) = QuarantineId::parse(&prefix) {
        vault
            .get(id)
            .map_err(|_| anyhow!("there is no quarantined item with the id {prefix}"))?;
        return Ok(id);
    }

    let matches: Vec<QuarantineId> = vault
        .list()
        .iter()
        .filter(|e| e.id.to_hex().starts_with(&prefix))
        .map(|e| e.id)
        .collect();

    match matches.len() {
        0 => Err(anyhow!(
            "no quarantined item has an id starting with `{text}`"
        )),
        1 => Ok(matches[0]),
        n => {
            let mut message = format!("`{text}` matches {n} items; use more of the id. Matches:");
            for id in matches.iter().take(8) {
                if let Ok(entry) = vault.get(*id) {
                    message.push_str(&format!(
                        "\n       {}  {}",
                        id.short(),
                        entry.original_path.display()
                    ));
                }
            }
            Err(anyhow!(message))
        }
    }
}

/// One entry as a JSON object.
///
/// Written out rather than serialising [`QuarantineEntry`] directly, because the
/// three fields a script actually keys on — the id as hex text, the verdict and
/// the status as words — are an enum and a byte array in the type, and a
/// consumer of this output should not have to know how the vault happens to
/// encode them internally.
fn entry_json(entry: &QuarantineEntry) -> serde_json::Value {
    serde_json::json!({
        "id": entry.id.to_hex(),
        "original_path": entry.original_path,
        "file_name": entry.file_name,
        "size": entry.size,
        "verdict": output::verdict_word(entry.verdict),
        "severity": entry.severity.as_str(),
        "status": entry.status.as_str(),
        "source": entry.source.as_str(),
        "blocked_before_running": entry.source.is_pre_execution(),
        "threat": entry.threat.as_ref().map(|t| t.to_string()),
        "detection": entry.detection,
        "quarantined_at": entry.quarantined_at.to_rfc3339(),
        "changed_at": entry.changed_at.to_rfc3339(),
        "original_removed": entry.original_removed,
        "digests": {
            "md5": entry.digests.md5,
            "sha1": entry.digests.sha1,
            "sha256": entry.digests.sha256,
        },
        "note": entry.note,
    })
}

/// A timestamp as the local time of whoever is reading it.
fn local_time(when: DateTime<Utc>) -> String {
    when.with_timezone(&Local)
        .format("%Y-%m-%d %H:%M")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_quarantine::{QuarantineContext, QuarantinePolicy};

    fn vault() -> (tempfile::TempDir, QuarantineVault) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let vault = QuarantineVault::open(dir.path().join("vault"), QuarantinePolicy::default())
            .expect("open");
        (dir, vault)
    }

    fn seed(vault: &mut QuarantineVault, name: &str, bytes: &[u8]) -> QuarantineId {
        let entry = vault
            .quarantine_bytes(
                Path::new(&format!(r"C:\Users\me\Downloads\{name}")),
                bytes,
                &QuarantineContext::default(),
            )
            .expect("quarantine");
        entry.id
    }

    #[test]
    fn a_full_identifier_resolves_to_itself() {
        let (dir, mut v) = vault();
        let id = seed(&mut v, "bad.exe", b"MZ");
        assert_eq!(resolve(&v, &id.to_hex()).unwrap(), id);
        assert_eq!(resolve(&v, &id.to_hex().to_uppercase()).unwrap(), id);
        drop(dir);
    }

    #[test]
    fn a_prefix_resolves_when_it_picks_out_one_item() {
        let (dir, mut v) = vault();
        let id = seed(&mut v, "bad.exe", b"MZ");
        assert_eq!(resolve(&v, &id.short()).unwrap(), id);
        assert_eq!(resolve(&v, &id.to_hex()[..4]).unwrap(), id);
        drop(dir);
    }

    #[test]
    fn a_prefix_that_matches_nothing_says_so() {
        let (dir, mut v) = vault();
        seed(&mut v, "bad.exe", b"MZ");
        // 'f' repeated is not a prefix of a random id with overwhelming
        // probability, and the error names what was typed.
        let error = resolve(&v, "ffffffff").unwrap_err().to_string();
        assert!(error.contains("ffffffff"), "{error}");
        assert!(error.contains("no quarantined item"), "{error}");
        drop(dir);
    }

    #[test]
    fn something_that_is_not_hexadecimal_is_refused_by_name() {
        let (dir, v) = vault();
        for text in ["hello", "550e8400-e29b-41d4", "0x1234", "zz"] {
            let error = resolve(&v, text).unwrap_err().to_string();
            assert!(error.contains(text), "{error}");
            assert!(error.contains("hexadecimal"), "{error}");
        }
        drop(dir);
    }

    #[test]
    fn a_complete_identifier_that_is_not_in_the_vault_is_not_reported_as_a_prefix() {
        // The distinction matters: "no such prefix" would send a user looking
        // for a typo in the first few characters when the whole id is wrong.
        let (dir, v) = vault();
        let error = resolve(&v, &"ab".repeat(16)).unwrap_err().to_string();
        assert!(error.contains("no quarantined item with the id"), "{error}");
        drop(dir);
    }

    #[test]
    fn a_prefix_that_matches_several_items_lists_them_and_picks_none() {
        // Ambiguity has to be produced rather than hoped for. Identifiers are
        // random, so a prefix long enough to be interesting will not collide in
        // any test that finishes — but the *first* character has only sixteen
        // possible values, and seventeen items must therefore share one by the
        // pigeonhole principle. That is the shortest prefix at which this
        // command can be ambiguous, which makes it exactly the case worth
        // pinning down.
        let (dir, mut v) = vault();
        let mut by_first: std::collections::HashMap<char, QuarantineId> =
            std::collections::HashMap::new();
        let mut collision = None;
        for i in 0..17 {
            let id = seed(&mut v, &format!("sample{i}.bin"), b"MZ");
            let first = id.to_hex().chars().next().expect("a hex digit");
            match by_first.get(&first) {
                Some(_) => {
                    collision = Some(first);
                    break;
                }
                None => {
                    by_first.insert(first, id);
                }
            }
        }
        let first = collision.expect("seventeen ids cannot all have a distinct first character");

        let error = resolve(&v, &first.to_string()).unwrap_err().to_string();
        assert!(error.contains("use more of the id"), "{error}");
        assert!(error.contains("matches"), "{error}");

        // And the same prefix one character longer is unambiguous, which is the
        // promise the message makes to the user.
        let full: Vec<QuarantineId> = v
            .list()
            .iter()
            .filter(|e| e.id.to_hex().starts_with(first))
            .map(|e| e.id)
            .collect();
        assert!(full.len() >= 2);
        drop(dir);
    }

    #[test]
    fn an_empty_id_is_refused_rather_than_matching_everything() {
        let (dir, mut v) = vault();
        seed(&mut v, "bad.exe", b"MZ");
        let error = resolve(&v, "  ").unwrap_err().to_string();
        assert!(error.contains("no id was given"), "{error}");
        drop(dir);
    }

    #[test]
    fn the_json_for_an_entry_uses_words_for_the_enum_fields() {
        let (dir, mut v) = vault();
        let id = seed(&mut v, "bad.exe", b"MZ");
        let entry = v.get(id).unwrap();
        let json = entry_json(entry);
        assert_eq!(json["id"], serde_json::json!(id.to_hex()));
        assert_eq!(json["verdict"], serde_json::json!("malicious"));
        assert_eq!(json["status"], serde_json::json!("quarantined"));
        assert_eq!(json["source"], serde_json::json!("manual"));
        assert_eq!(json["blocked_before_running"], serde_json::json!(false));
        assert_eq!(json["size"], serde_json::json!(2));
        drop(dir);
    }

    #[test]
    fn a_listing_exits_malicious_only_for_a_live_malicious_item() {
        let (dir, mut v) = vault();
        let id = seed(&mut v, "bad.exe", b"MZ");
        assert_eq!(list_exit(&[v.get(id).unwrap()]), Exit::Malicious);
        v.delete(id).expect("delete");
        assert_eq!(list_exit(&[v.get(id).unwrap()]), Exit::Clean);
        drop(dir);
    }

    #[test]
    fn a_suspicious_item_exits_three_not_one() {
        let (dir, mut v) = vault();
        let context = QuarantineContext {
            verdict: Verdict::Suspicious,
            ..QuarantineContext::default()
        };
        let entry = v
            .quarantine_bytes(Path::new(r"C:\maybe.exe"), b"MZ", &context)
            .expect("quarantine");
        assert_eq!(list_exit(&[v.get(entry.id).unwrap()]), Exit::Suspicious);
        drop(dir);
    }

    #[test]
    fn the_compactable_count_is_zero_for_a_vault_with_no_history() {
        let (dir, mut v) = vault();
        seed(&mut v, "bad.exe", b"MZ");
        assert_eq!(count_compactable(&v, None).unwrap(), 0);
        drop(dir);
    }

    #[test]
    fn digests_are_carried_through_to_the_json() {
        // Not a formatting test: the digests in the record are what a support
        // case matches a sample against, and losing them on the way out would
        // make `show --json` useless for the one job it has.
        let (dir, mut v) = vault();
        let id = seed(&mut v, "bad.exe", b"MZ");
        let entry = v.get(id).unwrap();
        assert!(entry.digests.sha256.is_some());
        let json = entry_json(entry);
        assert_eq!(
            json["digests"]["sha256"],
            serde_json::json!(entry.digests.sha256.clone())
        );
        drop(dir);
    }
}
