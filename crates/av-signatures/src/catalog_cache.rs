//! The catalog index, remembered between runs.
//!
//! # The cost this removes
//!
//! Every scan starts by building [`CatalogIndex`] from the catalog store, and on
//! the machine this was measured on that is the single largest thing a scan does
//! before it looks at a file:
//!
//! ```text
//! catalog store: 7300 catalogs read (0 refused, 0 oversized), 214820 digests, 1.89s
//! ```
//!
//! 1.2 GB of `.cat` files read and DER-parsed, against a scan of *one five-byte
//! file* that takes 34 ms of actual work. The rule database is not the problem —
//! `db info` on the 25 MB `rules.avdb` takes 0.77 s — so the line above is
//! almost the whole of a short scan's startup, paid again on every invocation
//! and thrown away when the process exits.
//!
//! This module writes the result of that work to one file and reads it back.
//! Measured on this machine, over the installed store of 7,300 catalogs and
//! 214,820 digests, release build, by the measurement test at the bottom of this
//! file:
//!
//! ```text
//! store enumeration:      47.2ms     (the 7,300 stats that every run pays)
//! uncached (from_store):  6.24s      (the baseline, with the store off the page cache)
//! cold (build + write):   2.24s      (the same build, with the store in the page cache)
//! cache file:             10,954,012 bytes
//! warm (read the cache):  59.8ms
//! ```
//!
//! 60 ms against 1.65 s to 6.24 s, and the difference is reading and checksumming
//! 10.4 MB instead of reading and DER-parsing 1.2 GB. The page cache is worth
//! knowing about — the same build is 2.2 s with the store in memory and 6.2 s
//! without it — and it is the other thing the cache removes: a second run reads
//! one file whatever state the store is in.
//!
//! The floor is the enumeration. A valid cache still costs the 7,300 `stat`
//! calls that decide it is still valid, which is 47 ms warm and 200 ms on the
//! first run after a boot — so the cache pays for itself only while the store's
//! parse costs more than its own directory listing, which is the case here by a
//! factor of thirty. On a store small enough for that to stop being true, the
//! cache is a rounding error rather than a cost, because it is then a file of a
//! few kilobytes read after a directory listing that dominates both paths.
//!
//! # What the cache is trusted with, and what it is not
//!
//! A catalog index is trust material: it is how the product decides that a file
//! is one a known vendor shipped. A cache that a hostile local user can write is
//! therefore a way to make the product vouch for a file it should not, and that
//! possibility was measured rather than assumed.
//!
//! ## The ACL, measured
//!
//! `Get-Acl C:\ProgramData\WenleAV\cache` on this machine:
//!
//! ```text
//! NT AUTHORITY\SYSTEM     Allow  FullControl                 Inherited
//! BUILTIN\Administrators  Allow  FullControl                 Inherited
//! MSI\wensz               Allow  FullControl                 Inherited
//! CREATOR OWNER           Allow  FullControl  (inherit-only) Inherited
//! BUILTIN\Users           Allow  ReadAndExecute, Synchronize Inherited
//! BUILTIN\Users           Allow  Write   Inheritance=ContainerInherit
//! ```
//!
//! The second `BUILTIN\Users` entry is the one that matters and it is not the
//! one a reader would guess: it carries `ContainerInherit` and **no**
//! `ObjectInherit` and **no** `INHERIT_ONLY_ACE`, so it is effective on the
//! cache directory itself. `Write` on a directory is `FILE_ADD_FILE`: every
//! interactive user on this machine can create files here, and `CREATOR OWNER`
//! gives them full control of whatever they create. The directory is a
//! `ProgramData` subdirectory and this grant is the one `ProgramData` itself
//! carries, so it is the normal state of affairs rather than a mistake by an
//! installer.
//!
//! One qualification, because it is the difference between measuring and
//! assuming: this was read from the ACL rather than exercised. Proving it by
//! writing would need a second, non-administrative account, and this machine has
//! one local account whose token is not elevated. The ACE semantics above are
//! what `icacls`, `Get-Acl` and `AccessCheck` agree on, and they are the reason
//! the design below does not depend on the answer either way.
//!
//! ## No MAC is possible here, so the cache is not a trust claim
//!
//! A MAC over the cache would need a key the writer cannot read, and there is
//! nowhere for this process to keep one: a cache the CLI can write while running
//! as an ordinary user is a cache an ordinary user can also read, and a key
//! compiled into the binary is a key in the attacker's hands. Keying it on the
//! machine's identity would refuse to share a cache between two machines that
//! share a store, for a threat the ACL already excludes for administrators —
//! who can plant a `.cat` in the store itself, which is a strictly larger
//! capability than forging this file.
//!
//! So the cache is **not authenticated**, and instead it is not believed. What
//! it records is the expensive half of the index — the set of digests the store
//! lists, and *which catalog file* lists each — and no publisher at all. When a
//! digest matches, the catalog file the cache names is re-read from the store,
//! parsed, and checked to list that digest before its publisher is reported; see
//! [`crate::catalog::CatalogIndex::catalogs_listing`]. A forged cache can
//! therefore only:
//!
//! - name a catalog that does not list the file, which vouches for nothing
//!   because the catalog is asked and says no;
//! - name one that does list it, which is the fact the store already stated; or
//! - leave entries out, which makes catalogued files look uncatalogued.
//!
//! The last is the worst outcome available, and it is the direction the trust
//! policy is built to survive: a catalog match can only ever discount a score
//! and can never convict, so suppressing one costs a false positive on a
//! Microsoft binary rather than a false clean on a hostile one.
//!
//! # Invalidation
//!
//! The cache records the store directory and, for every `.cat` in it, the name,
//! the size and the modification time, in the order the index numbers them. Any
//! difference — a file added, removed, renamed, resized, touched, or the cache
//! pointed at a different directory — is a miss and a rebuild. Nothing here
//! *repairs* an index, because a partially-updated index is a trust decision
//! made on half the evidence.
//!
//! A file rewritten in place with content of exactly the same length inside the
//! same timestamp tick is the case this cannot see. That is the other reason
//! nothing here is a trust claim: a wrong *digest set* can only lose matches,
//! and the containment check above is what keeps a wrong *owner* harmless.
//!
//! # The file
//!
//! Little-endian, fixed order, every length checked against the bytes that
//! remain before anything is allocated:
//!
//! ```text
//! magic "WENLECAT"                     8 bytes
//! version                              1 byte
//! store directory                      u32 length + UTF-8
//! catalog count                        u32
//!   per catalog: name                  u32 length + UTF-8
//!                size                  u64
//!                has modification time 1 byte, then i64 seconds, u32 nanos
//! SHA-1 digests:   stride, key count, owner count, start count, keys, owners,
//!                  starts
//! SHA-256 digests: the same
//! counters: read, refused, oversized   u32 each
//! SHA-256 of everything above          32 bytes
//! ```
//!
//! The trailing digest is a checksum and not a signature — a forger computes it
//! as easily as this module does. It exists so that a file truncated by a power
//! loss or garbled by a failing disk is *detected* rather than read as a
//! plausible index, which is a different failure with a different response.
//!
//! # Writing
//!
//! Temp file in the same directory, then `rename` over the target, so a reader
//! that arrives mid-write sees either the whole previous cache or the whole new
//! one and never a half-written file. No `fsync`: the rename is where the atomic
//! property comes from, and a torn file that survives a power loss is caught by
//! the checksum, so an fsync would buy durability the checksum already provides
//! at the cost of a synchronous flush on the startup path of every scan that
//! changes the store.
//!
//! # Failure is never the user's problem
//!
//! Every failure in this module is a cache miss. A store that cannot be read is
//! still the caller's error — that is a fact about the machine — but a cache
//! that cannot be read, decoded, written, or that describes a different store is
//! rebuilt, reported at `info` or `warn`, and the scan proceeds with the index
//! it would have built anyway. Nothing here panics on a malformed file, and
//! nothing here allocates an amount a malformed file asks for.

use std::fs::{self, File};
use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};

use sha2::{Digest as _, Sha256};

use crate::catalog::{CatalogIndex, DigestSet};

/// The first eight bytes of a cache file.
///
/// Checked before anything else is believed about the file, so that a file which
/// is not a cache at all — a log someone dropped in the directory, a decoy —
/// produces "this is not a cache" rather than a checksum failure.
pub(crate) const MAGIC: &[u8; 8] = b"WENLECAT";

/// The name the cache is written under inside the product's cache directory.
pub(crate) const FILE_NAME: &str = "catalog-index.avcache";

/// The layout this module writes, and the only one it will read.
///
/// A byte rather than a comment, because the alternative to refusing an older
/// layout is misreading one: the digest arrays are addressed by offset, so a
/// version that added a field would shift every one of them and a reader would
/// parse nonsense out of a file that is structurally valid.
pub(crate) const VERSION: u8 = 1;

/// The largest cache file that will be read.
///
/// The store on this machine produces 10,954,012 bytes. This is 24× that: room
/// for a machine with several times the catalog store, and still small enough
/// that a file somebody put in the cache directory cannot make the scanner read
/// for minutes. Checked against the file's metadata before it is opened, so an
/// oversized file is never loaded into memory at all.
const MAX_BYTES: u64 = 256 * 1024 * 1024;

/// How long a temp file can sit in the cache directory before it is presumed
/// abandoned.
///
/// A process killed between creating its temp file and renaming it leaves one
/// behind. An hour is far longer than any write here takes — 8 MB — and far
/// shorter than the interval between two scans of the same machine, so a live
/// writer is never swept and a dead one is cleaned up by the next run.
const STALE_TEMP: Duration = Duration::from_secs(60 * 60);

/// Distinguishes the temp files one process writes.
///
/// With the process id this makes every temp name unique, so two scans writing
/// the cache at once cannot rename each other's half-written file into place.
static TEMP_SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// One catalog file, as the cache records it.
///
/// The name, the size and the modification time: the three facts that decide
/// whether the store is the store the index was built from. `modified` is `None`
/// when the filesystem would not give a time that can be represented, which is
/// recorded as its own case rather than as a wrong time — and which disables the
/// cache for the run that saw it, because a store whose changes cannot be
/// detected is a store a cache must not be used for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogStamp {
    /// The file's name, as the filesystem spells it.
    pub(crate) name: String,
    /// Its length in bytes.
    pub(crate) size: u64,
    /// When it was last written, seconds and nanoseconds since the epoch.
    pub(crate) modified: Option<(i64, u32)>,
}

impl CatalogStamp {
    /// The stamp of one catalog file, or `None` if it cannot be measured.
    ///
    /// The name is converted lossily rather than refused, and both sides of
    /// every comparison go through the same conversion, so two runs agree with
    /// each other even about a name that is not valid Unicode — which no name in
    /// a Windows catalog store is. The residual case is two *different* names
    /// converting to the same string, and for the cache to be reused from that
    /// store the two files would also have to be the same length with the same
    /// timestamp; even then the containment check would refuse to let the wrong
    /// catalog vouch for anything.
    pub(crate) fn of(entry: &fs::DirEntry) -> Option<Self> {
        let metadata = entry.metadata().ok()?;
        Some(Self {
            name: entry.file_name().to_string_lossy().into_owned(),
            size: metadata.len(),
            modified: modification_time(&metadata),
        })
    }
}

/// When a file was last written, as seconds and nanoseconds since the epoch.
///
/// `None` for a time before the epoch that cannot be negated into an `i64`, or a
/// filesystem that does not report one at all. Both are cases this cache refuses
/// to guess about.
fn modification_time(metadata: &fs::Metadata) -> Option<(i64, u32)> {
    let since = metadata
        .modified()
        .ok()?
        .duration_since(SystemTime::UNIX_EPOCH);
    match since {
        Ok(elapsed) => Some((
            i64::try_from(elapsed.as_secs()).ok()?,
            elapsed.subsec_nanos(),
        )),
        Err(before) => {
            let elapsed = before.duration();
            Some((
                i64::try_from(elapsed.as_secs()).ok()?.checked_neg()?,
                elapsed.subsec_nanos(),
            ))
        }
    }
}

/// The store a cache was built from, as the cache records it.
///
/// Compared for equality against the live store before anything in the cache is
/// believed. `files` is in the order the index numbers catalogs, which is the
/// sort order — so an element-by-element comparison is also a comparison of
/// which catalog each owner index refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoreState {
    /// The store directory, as a display string.
    pub(crate) dir: String,
    /// Every catalog in it, in index order.
    pub(crate) files: Vec<CatalogStamp>,
}

impl StoreState {
    /// The state of the store directory `dir`, holding `files` in index order.
    pub(crate) fn of(dir: &Path, files: Vec<CatalogStamp>) -> Self {
        Self {
            dir: dir.to_string_lossy().into_owned(),
            files,
        }
    }
}

/// Why a cache was not used.
///
/// Three cases rather than one, because they are three different things to a
/// reader of the log: nothing has been cached yet is ordinary, a store that has
/// changed is ordinary, and a file that does not decode is worth being told
/// about. None of them is an error, and telling them apart is how an operator
/// finds out that something is writing to the cache directory.
#[derive(Debug)]
pub(crate) enum CacheMiss {
    /// There is no cache file.
    Absent,
    /// The file describes a store that is not this one, or a layout from a
    /// different version of this code.
    Stale(String),
    /// The file could not be read as a cache at all.
    Corrupt(String),
}

impl std::fmt::Display for CacheMiss {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Absent => write!(f, "no index cache yet"),
            Self::Stale(reason) => write!(f, "the index cache is out of date: {reason}"),
            Self::Corrupt(reason) => write!(f, "the index cache could not be read: {reason}"),
        }
    }
}

/// What a decoded cache holds: the digest sets and the build's counters.
///
/// The counters are diagnostics, and a forged one misreports a log line. They
/// are allowed into the cache anyway because they are what explains a scan that
/// found nothing, and leaving them out would mean re-reading the store to
/// recompute a number that decides nothing.
#[derive(Debug)]
pub(crate) struct Loaded {
    /// The digests listed under SHA-1.
    pub(crate) sha1: DigestSet,
    /// The digests listed under SHA-256.
    pub(crate) sha256: DigestSet,
    /// How many catalogs the build read.
    pub(crate) read: usize,
    /// How many files it refused.
    pub(crate) refused: usize,
    /// How many it skipped as oversized.
    pub(crate) oversized: usize,
}

/// Read the cache at `cache`, if it describes `state`.
///
/// Every failure is a [`CacheMiss`], and every one of them means the same thing
/// to the caller: build the index from the store instead. Nothing here returns
/// an error for the *scan* to deal with.
pub(crate) fn load(cache: &Path, state: &StoreState) -> Result<Loaded, CacheMiss> {
    let metadata = match fs::metadata(cache) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(CacheMiss::Absent);
        }
        Err(error) => {
            return Err(CacheMiss::Corrupt(format!(
                "{} could not be read: {error}",
                cache.display()
            )));
        }
    };
    if metadata.len() > MAX_BYTES {
        return Err(CacheMiss::Corrupt(format!(
            "{} is {} bytes, past the {MAX_BYTES} byte limit",
            cache.display(),
            metadata.len()
        )));
    }
    let bytes = fs::read(cache).map_err(|error| {
        CacheMiss::Corrupt(format!("{} could not be read: {error}", cache.display()))
    })?;
    decode(&bytes, state)
}

/// Decode a cache file, refusing anything that does not match `state`.
fn decode(bytes: &[u8], state: &StoreState) -> Result<Loaded, CacheMiss> {
    let truncated = || CacheMiss::Corrupt("the file is truncated".into());

    // The checksum first, over everything but itself, so that a file the disk
    // lost bytes from is rejected as damaged rather than parsed as a shorter but
    // structurally valid index.
    let Some(payload_len) = bytes.len().checked_sub(Sha256::output_size()) else {
        return Err(truncated());
    };
    let Some((payload, claimed)) = bytes.split_at_checked(payload_len) else {
        return Err(truncated());
    };
    let computed = Sha256::digest(payload);
    // Not a constant-time comparison, and deliberately not: the digest is a
    // checksum over data the attacker supplied, not a MAC over data they did
    // not, so there is no secret for a timing difference to leak.
    if claimed != computed.as_slice() {
        return Err(CacheMiss::Corrupt(
            "the contents do not match the checksum".into(),
        ));
    }

    let mut at = Reader::new(payload);
    if at.take(MAGIC.len()) != Some(MAGIC.as_slice()) {
        return Err(CacheMiss::Corrupt("not a catalog index cache".into()));
    }
    let version = at.u8().ok_or_else(truncated)?;
    if version != VERSION {
        return Err(CacheMiss::Stale(format!(
            "it was written in layout {version} and this is layout {VERSION}"
        )));
    }

    let dir = at.text().ok_or_else(truncated)?;
    if dir != state.dir {
        return Err(CacheMiss::Stale(format!("it was built from `{dir}`")));
    }
    let count = at.u32().ok_or_else(truncated)?;
    if count as usize != state.files.len() {
        return Err(CacheMiss::Stale(format!(
            "it was built from {count} catalogs and the store holds {}",
            state.files.len()
        )));
    }
    for expected in &state.files {
        let name = at.text().ok_or_else(truncated)?;
        let size = at.u64().ok_or_else(truncated)?;
        let modified = match at.u8().ok_or_else(truncated)? {
            0 => None,
            1 => {
                let seconds = at.i64().ok_or_else(truncated)?;
                let nanos = at.u32().ok_or_else(truncated)?;
                Some((seconds, nanos))
            }
            other => {
                return Err(CacheMiss::Corrupt(format!(
                    "a catalog timestamp has the flag {other}"
                )));
            }
        };
        if name != expected.name || size != expected.size || modified != expected.modified {
            return Err(CacheMiss::Stale(format!(
                "`{name}` is not the file it was built from"
            )));
        }
    }

    let sha1 = read_set(&mut at)?;
    let sha256 = read_set(&mut at)?;
    let read = at.u32().ok_or_else(truncated)?;
    let refused = at.u32().ok_or_else(truncated)?;
    let oversized = at.u32().ok_or_else(truncated)?;

    Ok(Loaded {
        sha1,
        sha256,
        read: read as usize,
        refused: refused as usize,
        oversized: oversized as usize,
    })
}

/// One fixed-width digest set.
///
/// The counts are read out of the file and are therefore the file author's to
/// choose, so each is checked against the bytes that back it before anything is
/// allocated: a 60-byte file claiming four billion keys must be refused, not
/// allocated for.
fn read_set(at: &mut Reader<'_>) -> Result<DigestSet, CacheMiss> {
    let damaged = || CacheMiss::Corrupt("a digest set is truncated".into());
    let stride = at.u32().ok_or_else(damaged)? as usize;
    let key_count = at.u32().ok_or_else(damaged)? as usize;
    let owner_count = at.u32().ok_or_else(damaged)? as usize;
    let start_count = at.u32().ok_or_else(damaged)? as usize;

    let key_bytes = key_count
        .checked_mul(stride)
        .and_then(|bytes| at.take(bytes))
        .ok_or_else(damaged)?
        .to_vec();
    let owners = at.u32s(owner_count).ok_or_else(damaged)?;
    let starts = at.u32s(start_count).ok_or_else(damaged)?;

    DigestSet::from_parts(stride, key_bytes, owners, starts)
        .ok_or_else(|| CacheMiss::Corrupt("a digest set is not self-consistent".into()))
}

/// Encode a cache file, checksum included.
///
/// Takes the digest sets by reference rather than by value: they are the whole
/// of the index and 6.5 MB of it, and copying them to write them out would be
/// work for nothing on the one path that runs at startup.
pub(crate) fn encode(
    state: &StoreState,
    sets: (&DigestSet, &DigestSet),
    counters: (usize, usize, usize),
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    text(&mut out, &state.dir);
    out.extend_from_slice(&count(state.files.len()).to_le_bytes());
    for file in &state.files {
        text(&mut out, &file.name);
        out.extend_from_slice(&file.size.to_le_bytes());
        match file.modified {
            Some((seconds, nanos)) => {
                out.push(1);
                out.extend_from_slice(&seconds.to_le_bytes());
                out.extend_from_slice(&nanos.to_le_bytes());
            }
            None => out.push(0),
        }
    }
    write_set(&mut out, sets.0);
    write_set(&mut out, sets.1);
    for value in [counters.0, counters.1, counters.2] {
        out.extend_from_slice(&count(value).to_le_bytes());
    }
    let digest = Sha256::digest(&out);
    out.extend_from_slice(&digest);
    out
}

/// A count as the file writes it.
///
/// Saturating rather than panicking or failing: these are counts of things that
/// are already in memory, so a value past `u32::MAX` means the machine has
/// bigger problems than a cache file, and a saturated count is caught by the
/// receiver as a mismatch.
fn count(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// One `u32`-length-prefixed string.
fn text(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&count(value.len()).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
}

/// One fixed-width digest set, in the order [`read_set`] expects.
///
/// The key field is a *count* and not the byte length of the array beside it.
/// The two differ by a factor of the stride, which is the one thing a reader
/// cannot recover from the file alone, so writing the wrong one is a file that
/// no reader can decode — which is exactly what the first version of this did.
fn write_set(out: &mut Vec<u8>, set: &DigestSet) {
    let (stride, keys, owners, starts) = set.parts();
    // Zero for an empty set, whose stride is zero: the reader multiplies this by
    // the stride to size the key array, and 0 × 0 is the empty array that set
    // actually has.
    let key_count = keys.len().checked_div(stride).unwrap_or(0);
    for value in [stride, key_count, owners.len(), starts.len()] {
        out.extend_from_slice(&count(value).to_le_bytes());
    }
    out.extend_from_slice(keys);
    for owner in owners {
        out.extend_from_slice(&owner.to_le_bytes());
    }
    for start in starts {
        out.extend_from_slice(&start.to_le_bytes());
    }
}

/// Write the index to the cache file, atomically.
///
/// The caller has already built the index from the store, so a failure here
/// costs the next scan its startup and nothing else.
pub(crate) fn store(cache: &Path, state: &StoreState, index: &CatalogIndex) -> std::io::Result<()> {
    let (sha1, sha256) = index.digest_sets();
    let counters = (
        index.catalogs_read(),
        index.catalogs_refused(),
        index.catalogs_oversized(),
    );
    let bytes = encode(state, (sha1, sha256), counters);
    write_atomically(cache, &bytes)
}

/// Replace `cache` with `bytes`, or leave whatever was there alone.
///
/// Temp file in the same directory — a rename across filesystems is a copy, and
/// a copy is not atomic — then a rename over the target. A reader that arrives
/// mid-write sees the previous cache or the new one, never a mix of the two.
pub(crate) fn write_atomically(cache: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let directory = match cache.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    fs::create_dir_all(directory)?;
    sweep_abandoned(directory);

    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = directory.join(format!("{FILE_NAME}.tmp.{}.{sequence}", std::process::id()));
    let mut file = File::create(&temp)?;
    if let Err(error) = file.write_all(bytes) {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    // Closed before the rename. A rename over a file another handle is open on
    // succeeds on Windows, but leaving a live handle on a file this process no
    // longer owns is how a temp file becomes one nobody can delete.
    drop(file);
    if let Err(error) = fs::rename(&temp, cache) {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    Ok(())
}

/// Remove temp files left by a process that died before its rename.
///
/// Only files older than [`STALE_TEMP`], so a writer that is still working is
/// never swept — and on Windows a temp file another process still holds open
/// cannot be deleted at all, so the age test is a second line of defence rather
/// than the only one. Every failure is ignored: one stale file in a cache
/// directory is not a reason to refuse to write the cache.
///
/// It runs when the cache is written, which is the only time one of these can
/// appear — so a run whose store is unchanged leaves an abandoned temp file
/// where it is, and the next run that has something to write clears it. The
/// file that is *not* cleared is the cache itself, which this never touches.
fn sweep_abandoned(directory: &Path) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(FILE_NAME) || !name.contains(".tmp.") {
            continue;
        }
        let Ok(modified) = entry.metadata().and_then(|metadata| metadata.modified()) else {
            continue;
        };
        let Ok(age) = now.duration_since(modified) else {
            continue;
        };
        if age > STALE_TEMP {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// A bounds-checked cursor over the cache file.
///
/// Every read answers `None` past the end rather than panicking, and every count
/// taken from the file is checked against what is left before it is used as a
/// length. The two together are what make a hostile file cost nothing: nothing
/// here allocates on a number the file supplied without the bytes to back it up.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// How many bytes are left.
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.at)
    }

    /// The next `count` bytes.
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(count)?;
        let taken = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(taken)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    fn u32(&mut self) -> Option<u32> {
        let bytes: [u8; 4] = self.take(4)?.try_into().ok()?;
        Some(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Option<u64> {
        let bytes: [u8; 8] = self.take(8)?.try_into().ok()?;
        Some(u64::from_le_bytes(bytes))
    }

    fn i64(&mut self) -> Option<i64> {
        let bytes: [u8; 8] = self.take(8)?.try_into().ok()?;
        Some(i64::from_le_bytes(bytes))
    }

    /// `count` little-endian `u32`s, refused unless they are all present.
    fn u32s(&mut self, count: usize) -> Option<Vec<u32>> {
        let bytes = count.checked_mul(4)?;
        if bytes > self.remaining() {
            return None;
        }
        let taken = self.take(bytes)?;
        Some(
            taken
                .chunks_exact(4)
                .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                .collect(),
        )
    }

    /// A `u32`-length-prefixed UTF-8 string.
    fn text(&mut self) -> Option<String> {
        let len = self.u32()? as usize;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).ok()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::catalog::{file_digest, store_state, CatalogIndex, HashAlgorithm};
    use crate::testing::{catalog, catalog_signed_by, chain_link};
    use av_pe::PeFile;

    /// An empty directory of this module's own, named for the test using it.
    ///
    /// One name per test rather than a shared scratch directory, because these
    /// run in parallel and a test that cleaned up another test's store would
    /// fail in a way that has nothing to do with the code.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("wenle-catalog-cache-{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("the scratch directory is created");
        dir
    }

    /// A PE image and its SHA-1 digest.
    fn covered() -> (Vec<u8>, Vec<u8>) {
        let image = av_pe::testing::minimal_pe32();
        let pe = PeFile::parse(&image).expect("the fixture is a PE");
        let digest = file_digest(&pe, HashAlgorithm::Sha1).expect("a digest");
        (image, digest)
    }

    /// A *different* PE image and its SHA-1 digest.
    ///
    /// `minimal_pe32` returns the same bytes on every call, so a test that needs
    /// two distinct files cannot get them by calling it twice.
    fn covered_differently() -> (Vec<u8>, Vec<u8>) {
        let mut image = av_pe::testing::minimal_pe32();
        av_pe::testing::add_imports(&mut image, &[("OTHER.dll", &["SomethingElse"])]);
        let pe = PeFile::parse(&image).expect("the fixture is a PE");
        let digest = file_digest(&pe, HashAlgorithm::Sha1).expect("a digest");
        (image, digest)
    }

    /// A chain whose leaf names `publisher`.
    fn chain(publisher: &str) -> Vec<Vec<u8>> {
        vec![chain_link(
            b"\x01",
            publisher,
            "Wenle Test Root",
            "200101000000Z",
            "300101000000Z",
        )]
    }

    /// Build the index from `dir` right now, and say whether the cache answered.
    fn hit(dir: &Path, cache: &Path) -> (CatalogIndex, bool) {
        let index = CatalogIndex::from_directory_cached(dir, cache).expect("the store is readable");
        let cached = index.cache_hit();
        (index, cached)
    }

    /// The state a cache of `dir` is keyed on, for the tests that write one by
    /// hand.
    fn state_of(dir: &Path) -> StoreState {
        store_state(dir)
            .expect("the store is readable")
            .expect("the store is stampable")
    }

    #[test]
    fn the_second_build_reads_the_cache_and_answers_the_same() {
        // The point of the module, and the differential that earns it: the
        // cached index must answer what the store says, not merely load.
        let dir = scratch("warm");
        let cache = dir.join(FILE_NAME);
        let (first_image, first) = covered();
        let (second_image, second) = covered_differently();
        fs::write(
            dir.join("one.cat"),
            catalog_signed_by(&[&first], &chain("Contoso Publisher")),
        )
        .unwrap();
        fs::write(
            dir.join("two.cat"),
            catalog_signed_by(&[&second], &chain("Fabrikam Publisher")),
        )
        .unwrap();

        let (cold, was_cached) = hit(&dir, &cache);
        assert!(!was_cached, "there was nothing to read yet");
        assert_eq!(cold.catalogs_read(), 2);
        assert_eq!(cold.catalogs_refused(), 0);
        assert_eq!(cold.digest_count(), 2);

        let (warm, was_cached) = hit(&dir, &cache);
        assert!(was_cached, "the second build must come out of the cache");
        assert_eq!(warm.catalogs_read(), 2);
        assert_eq!(warm.catalogs_refused(), 0);
        assert_eq!(warm.digest_count(), 2);

        for image in [&first_image, &second_image] {
            let pe = PeFile::parse(image).unwrap();
            assert!(warm.lists(&pe), "the cached index lost a listed file");
            // The publisher is the half the cache does *not* hold, so this also
            // pins that a cached index still reads the catalogs for it.
            let listing = warm.catalogs_listing(&pe);
            let subject = &listing.first().expect("the digest is listed").subject;
            assert!(
                subject.contains("Contoso") || subject.contains("Fabrikam"),
                "the publisher must come from the catalog, got {subject:?}"
            );
        }

        let pe = PeFile::parse(&first_image).unwrap();
        let cached_subject = warm.catalogs_listing(&pe);
        let store_subject = cold.catalogs_listing(&pe);
        assert_eq!(
            cached_subject.first().unwrap().subject,
            store_subject.first().unwrap().subject,
            "both indexes must name the same publisher for the same file"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_catalog_added_to_the_store_is_not_missed() {
        let dir = scratch("added");
        let cache = dir.join(FILE_NAME);
        let (_first_image, first) = covered();
        let (second_image, second) = covered_differently();
        fs::write(dir.join("one.cat"), catalog(&[&first])).unwrap();
        let (cold, _) = hit(&dir, &cache);
        assert_eq!(cold.digest_count(), 1);

        // A cumulative update lands in the store, which is the ordinary way this
        // directory changes under the product's feet.
        fs::write(dir.join("two.cat"), catalog(&[&second])).unwrap();

        let (warm, was_cached) = hit(&dir, &cache);
        assert!(
            !was_cached,
            "a store with a new catalog is not the cached one"
        );
        assert_eq!(warm.digest_count(), 2);
        let pe = PeFile::parse(&second_image).unwrap();
        assert!(warm.lists(&pe), "the new catalog's file must be listed");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_catalog_removed_from_the_store_is_not_still_listed() {
        let dir = scratch("removed");
        let cache = dir.join(FILE_NAME);
        let (first_image, first) = covered();
        let (second_image, second) = covered_differently();
        fs::write(dir.join("one.cat"), catalog(&[&first])).unwrap();
        fs::write(dir.join("two.cat"), catalog(&[&second])).unwrap();
        let (cold, _) = hit(&dir, &cache);
        assert_eq!(cold.digest_count(), 2);

        fs::remove_file(dir.join("two.cat")).unwrap();

        let (warm, was_cached) = hit(&dir, &cache);
        assert!(
            !was_cached,
            "a store that lost a catalog is not the cached one"
        );
        assert_eq!(warm.digest_count(), 1);
        let pe = PeFile::parse(&second_image).unwrap();
        assert!(
            !warm.lists(&pe),
            "a removed catalog must stop vouching for its files"
        );
        let pe = PeFile::parse(&first_image).unwrap();
        assert!(warm.lists(&pe), "the catalog that stayed must still list");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_catalog_rewritten_in_place_is_read_again() {
        // The case a cache of this shape gets wrong if it keys on the file list
        // alone: the name is the same and only the bytes changed, which is what
        // an in-place update of a catalog looks like.
        let dir = scratch("rewritten");
        let cache = dir.join(FILE_NAME);
        let (first_image, first) = covered();
        let (second_image, second) = covered_differently();
        fs::write(dir.join("one.cat"), catalog(&[&first])).unwrap();
        let (cold, _) = hit(&dir, &cache);
        assert!(cold.lists(&PeFile::parse(&first_image).unwrap()));

        fs::write(dir.join("one.cat"), catalog(&[&second])).unwrap();

        let (warm, was_cached) = hit(&dir, &cache);
        assert!(
            !was_cached,
            "the catalog is not the file the cache recorded"
        );
        let pe = PeFile::parse(&second_image).unwrap();
        assert!(warm.lists(&pe), "the new contents must be indexed");
        let pe = PeFile::parse(&first_image).unwrap();
        assert!(
            !warm.lists(&pe),
            "the digest the catalog used to list is gone and must not linger"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_cache_built_from_another_store_is_not_used() {
        // Two stores holding identically named, identically sized catalogs: the
        // directory in the state is the only thing that separates them, and
        // without it the cache would answer for a store it never read.
        let first = scratch("other-store-first");
        let second = scratch("other-store-second");
        let cache = scratch("other-store-cache").join(FILE_NAME);
        let (_image, digest) = covered();
        for dir in [&first, &second] {
            fs::write(dir.join("one.cat"), catalog(&[&digest])).unwrap();
        }

        let (_, was_cached) = hit(&first, &cache);
        assert!(!was_cached);
        let (index, was_cached) = hit(&second, &cache);
        assert!(
            !was_cached,
            "a cache built from another directory must not answer for this one"
        );
        assert_eq!(index.digest_count(), 1);

        let _ = fs::remove_dir_all(&first);
        let _ = fs::remove_dir_all(&second);
    }

    /// One way a cache file can be damaged: a name for the failure mode, and
    /// the function that turns the intact bytes into the damaged ones.
    type Damage = (&'static str, fn(&[u8]) -> Vec<u8>);

    #[test]
    fn every_way_a_cache_can_be_damaged_rebuilds_rather_than_panicking() {
        // Truncation, a flipped byte and zeroes: the three shapes a cache file
        // takes after a power loss, a bad sector, and somebody emptying it. Each
        // must be a miss with the right answer, and each must leave the cache
        // rewritten so the damage costs one scan.
        let dir = scratch("damaged");
        let cache = dir.join(FILE_NAME);
        let (image, digest) = covered();
        fs::write(dir.join("one.cat"), catalog(&[&digest])).unwrap();
        let (_, was_cached) = hit(&dir, &cache);
        assert!(!was_cached);
        let intact = fs::read(&cache).unwrap();
        assert!(intact.len() > 64, "the cache is worth damaging");

        let damage: [Damage; 3] = [
            ("truncated", |bytes: &[u8]| {
                bytes[..bytes.len() / 2].to_vec()
            }),
            // Inside the digest sets rather than in the header, so the checksum
            // is what catches it: a reader without one would take this file and
            // answer from a mangled index.
            ("a flipped byte", |bytes: &[u8]| {
                let mut bytes = bytes.to_vec();
                let at = bytes.len() / 2;
                bytes[at] ^= 0xff;
                bytes
            }),
            ("zeroed", |bytes: &[u8]| vec![0u8; bytes.len()]),
        ];

        for (what, damage) in damage {
            fs::write(&cache, damage(&intact)).unwrap();
            let (index, was_cached) = hit(&dir, &cache);
            assert!(!was_cached, "{what}: a damaged cache must not be used");
            assert_eq!(
                index.digest_count(),
                1,
                "{what}: the rebuild must be complete"
            );
            let pe = PeFile::parse(&image).unwrap();
            assert!(index.lists(&pe), "{what}: the rebuilt index must answer");
            let (_, was_cached) = hit(&dir, &cache);
            assert!(was_cached, "{what}: the cache must have been rewritten");
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_cache_from_a_later_layout_is_refused_rather_than_misread() {
        // Why the version byte exists: the digest arrays are addressed by offset,
        // so a layout that added a field would have this reader parse nonsense
        // out of a file that is structurally valid. It must be a miss.
        let dir = scratch("version");
        let cache = dir.join(FILE_NAME);
        let (image, digest) = covered();
        fs::write(dir.join("one.cat"), catalog(&[&digest])).unwrap();
        let (_, was_cached) = hit(&dir, &cache);
        assert!(!was_cached);

        // Rewritten with a later version and a checksum that matches, which is
        // what an upgrade of this code would leave behind.
        let mut bytes = fs::read(&cache).unwrap();
        bytes[MAGIC.len()] = VERSION + 1;
        let end = bytes.len() - Sha256::output_size();
        let refreshed = Sha256::digest(&bytes[..end]);
        bytes[end..].copy_from_slice(&refreshed);
        fs::write(&cache, &bytes).unwrap();

        let (index, was_cached) = hit(&dir, &cache);
        assert!(!was_cached, "another layout's file must not be read");
        assert_eq!(index.digest_count(), 1);
        assert!(index.lists(&PeFile::parse(&image).unwrap()));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_cache_claiming_a_gigantic_index_is_refused_without_allocating() {
        // The counts in the file are its author's to choose, and a
        // `Vec::with_capacity` on a number they chose is an abort rather than a
        // cache miss. Every count must be checked against the bytes behind it.
        let dir = scratch("gigantic");
        let cache = dir.join(FILE_NAME);
        let (image, digest) = covered();
        fs::write(dir.join("one.cat"), catalog(&[&digest])).unwrap();
        let (_, was_cached) = hit(&dir, &cache);
        assert!(!was_cached);

        let mut bytes = fs::read(&cache).unwrap();
        // The counts of the SHA-1 set, at an offset this test decodes out of the
        // header rather than computes, so a change to the layout moves the test
        // with it instead of leaving it to corrupt the wrong byte and pass.
        let set_at = offset_of_first_set(&bytes);
        bytes[set_at..set_at + 4].copy_from_slice(&20u32.to_le_bytes());
        bytes[set_at + 4..set_at + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes[set_at + 8..set_at + 12].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes[set_at + 12..set_at + 16].copy_from_slice(&u32::MAX.to_le_bytes());
        let end = bytes.len() - Sha256::output_size();
        let refreshed = Sha256::digest(&bytes[..end]);
        bytes[end..].copy_from_slice(&refreshed);
        fs::write(&cache, &bytes).unwrap();

        let (index, was_cached) = hit(&dir, &cache);
        assert!(!was_cached, "a claimed four billion keys must be refused");
        assert_eq!(index.digest_count(), 1);
        assert!(index.lists(&PeFile::parse(&image).unwrap()));

        let _ = fs::remove_dir_all(&dir);
    }

    /// Where the SHA-1 digest set starts, decoded rather than computed.
    fn offset_of_first_set(bytes: &[u8]) -> usize {
        let mut at = Reader::new(bytes);
        assert_eq!(at.take(MAGIC.len()), Some(MAGIC.as_slice()));
        assert_eq!(at.u8(), Some(VERSION));
        at.text().expect("the store path");
        let count = at.u32().expect("the catalog count");
        for _ in 0..count {
            at.text().expect("a name");
            at.u64().expect("a size");
            if at.u8() == Some(1) {
                at.i64().expect("seconds");
                at.u32().expect("nanos");
            }
        }
        at.at
    }

    #[test]
    fn a_forged_cache_cannot_make_a_catalog_vouch_for_a_file_it_does_not_list() {
        // The security property, exercised end to end. The cache directory is
        // writable by any local user on this machine — measured, see the module
        // documentation — so this is what an attacker who can write it could
        // write: a well-formed cache, state matching, checksum correct, naming a
        // *real* catalog in the store as the owner of a digest it does not list.
        //
        // Nothing in the cache is authenticated, so nothing in it can be a trust
        // claim: the catalog is asked, and it says no.
        let dir = scratch("forged");
        let cache = dir.join(FILE_NAME);
        let (vouched_image, vouched) = covered();
        let (target_image, target) = covered_differently();
        // `one.cat` lists one digest and is published by Contoso; `two.cat`
        // lists the other and carries no chain at all.
        fs::write(
            dir.join("one.cat"),
            catalog_signed_by(&[&vouched], &chain("Contoso Publisher")),
        )
        .unwrap();
        fs::write(dir.join("two.cat"), catalog(&[&target])).unwrap();
        let (index, was_cached) = hit(&dir, &cache);
        assert!(!was_cached);

        // Before the forgery: the file is listed by `two.cat` — which carries no
        // chain at all, so nothing vouches for it. That is the state the forgery
        // exists to change, and the state it must fail to change.
        let pe = PeFile::parse(&target_image).unwrap();
        let listing = index.catalogs_listing(&pe);
        assert_eq!(listing.len(), 1, "one catalog lists the file");
        assert!(
            listing[0].issuers.is_empty(),
            "and no authority vouches for it, got {:?}",
            listing[0].issuers
        );

        // Forge: both digests owned by catalog 0, which is `one.cat` — the
        // catalog that lists the *other* file and is published by Contoso. This
        // is the whole attack: make a strange file look like a vendor's.
        let sets = (
            DigestSet::build(20, vec![(vouched.clone(), 0), (target.clone(), 0)]),
            DigestSet::build(32, Vec::new()),
        );
        let forged = encode(&state_of(&dir), (&sets.0, &sets.1), (2, 0, 0));
        fs::write(&cache, &forged).unwrap();

        let (warm, was_cached) = hit(&dir, &cache);
        assert!(
            was_cached,
            "the forged cache describes this store, so it is used — which is the \
             assumption this test exists to check"
        );
        assert!(
            warm.digest_count() > 0,
            "the forged digests are in the index"
        );
        let pe = PeFile::parse(&target_image).unwrap();
        assert!(
            !warm.lists(&pe),
            "a cache naming a catalog that does not list the file must not make \
             that catalog vouch for it"
        );
        assert!(
            warm.catalogs_listing(&pe).is_empty(),
            "and it must not report a publisher for it either"
        );
        let pe = PeFile::parse(&vouched_image).unwrap();
        assert!(
            warm.lists(&pe),
            "the file the named catalog really does list is still vouched for"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_cache_directory_that_cannot_be_written_does_not_fail_the_build() {
        // A cache is an optimisation, and one that turns a working scan into a
        // failed one is worse than no optimisation. The cache path here is under
        // a *file*, so neither its directory nor the file can be created.
        let dir = scratch("unwritable");
        let (image, digest) = covered();
        fs::write(dir.join("one.cat"), catalog(&[&digest])).unwrap();
        let cache = dir.join("one.cat").join(FILE_NAME);

        let index = CatalogIndex::from_directory_cached(&dir, &cache)
            .expect("a cache that cannot be written is not a store failure");
        assert!(!index.cache_hit());
        assert_eq!(index.digest_count(), 1);
        assert!(index.lists(&PeFile::parse(&image).unwrap()));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_cache_path_being_a_directory_is_a_miss_and_not_an_error() {
        let dir = scratch("cache-is-a-directory");
        let cache = dir.join(FILE_NAME);
        let (image, digest) = covered();
        fs::write(dir.join("one.cat"), catalog(&[&digest])).unwrap();
        fs::create_dir_all(&cache).unwrap();

        let index =
            CatalogIndex::from_directory_cached(&dir, &cache).expect("the store is readable");
        assert!(!index.cache_hit());
        assert!(index.lists(&PeFile::parse(&image).unwrap()));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_write_leaves_no_temp_file_behind_and_sweeps_an_abandoned_one() {
        let dir = scratch("temp-files");
        let cache = dir.join(FILE_NAME);
        let (_, digest) = covered();
        fs::write(dir.join("one.cat"), catalog(&[&digest])).unwrap();
        let (_, was_cached) = hit(&dir, &cache);
        assert!(!was_cached);

        let names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names.iter().filter(|name| name.contains(".tmp.")).count(),
            0,
            "a successful write must leave no temp file, got {names:?}"
        );

        // A process killed mid-write leaves one. It must be swept by the next
        // run, and a temp file young enough to belong to a live writer must not.
        let abandoned = dir.join(format!("{FILE_NAME}.tmp.1.0"));
        let live = dir.join(format!("{FILE_NAME}.tmp.2.0"));
        fs::write(&abandoned, b"half a cache").unwrap();
        fs::write(&live, b"half a cache").unwrap();
        let old = SystemTime::now() - (STALE_TEMP + Duration::from_secs(60));
        File::options()
            .write(true)
            .open(&abandoned)
            .unwrap()
            .set_modified(old)
            .unwrap();

        // The sweep runs when the cache is written, and a cache that is still
        // valid is not written — so this run has to be one that writes. A second
        // catalog in the store is the ordinary way that happens.
        fs::write(dir.join("two.cat"), catalog(&[&digest])).unwrap();
        let (_, was_cached) = hit(&dir, &cache);
        assert!(
            !was_cached,
            "a store with a new catalog is not the cached one"
        );
        assert!(!abandoned.exists(), "an abandoned temp file must be swept");
        assert!(
            live.exists(),
            "a temp file a writer still owns must be left"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_store_is_cached_and_comes_back_empty() {
        // The differential a caller cannot afford to lose: "no catalog lists this
        // file" must survive a round trip as that, and not become "the store
        // could not be read".
        let dir = scratch("empty");
        let cache = dir.join(FILE_NAME);
        let (image, _digest) = covered();

        let (cold, was_cached) = hit(&dir, &cache);
        assert!(!was_cached);
        assert!(cold.is_empty());
        let (warm, was_cached) = hit(&dir, &cache);
        assert!(was_cached, "an empty store is still a store worth caching");
        assert!(warm.is_empty());
        assert_eq!(warm.catalogs_read(), 0);
        assert!(!warm.lists(&PeFile::parse(&image).unwrap()));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_catalog_that_cannot_be_read_is_counted_the_same_either_way() {
        // Store corruption is the case where the cached build and the live build
        // could disagree, because one of them re-reads the bytes and the other
        // does not. The counters are what an operator reads to find out that a
        // file in CatRoot is unreadable, so they have to survive the round trip.
        let dir = scratch("refused");
        let cache = dir.join(FILE_NAME);
        let (image, digest) = covered();
        fs::write(dir.join("one.cat"), catalog(&[&digest])).unwrap();
        fs::write(dir.join("two.cat"), b"not a catalog at all").unwrap();
        fs::write(dir.join("three.cat"), b"nor is this one").unwrap();

        let (cold, _) = hit(&dir, &cache);
        assert_eq!(cold.catalogs_read(), 1);
        assert_eq!(cold.catalogs_refused(), 2);

        let (warm, was_cached) = hit(&dir, &cache);
        assert!(was_cached);
        assert_eq!(warm.catalogs_read(), cold.catalogs_read());
        assert_eq!(warm.catalogs_refused(), cold.catalogs_refused());
        assert!(warm.lists(&PeFile::parse(&image).unwrap()));

        let _ = fs::remove_dir_all(&dir);
    }

    // -- measurements ----------------------------------------------------------
    //
    // Separate from the tests above, and `#[ignore]`d, because they read the
    // installed Windows catalog store — 1.2 GB — and because a number is not an
    // assertion:
    //
    //     cargo test -p av-signatures --release --lib catalog_cache::tests::the_cache -- --ignored --nocapture
    //
    // The differential they check is the one the cache exists for: the same
    // answers as a full build, in a fraction of the time.

    #[test]
    #[ignore = "reads the installed Windows catalog store"]
    fn the_cache_is_worth_what_it_costs_on_this_machines_store() {
        use std::time::Instant;

        let Some(dir) = crate::catalog::store_directory() else {
            println!("no catalog store on this platform");
            return;
        };
        let cache = std::env::temp_dir()
            .join("wenle-catalog-cache-measure")
            .join(FILE_NAME);
        let _ = fs::remove_file(&cache);

        // What the store's own state costs — 7,300 `stat`s — because the warm
        // path pays that whether or not it can use the cache. This is the number
        // that decides whether the design is a saving or a relocation of the
        // cost, so it is measured rather than assumed.
        let started = Instant::now();
        let state = store_state(&dir)
            .expect("the store is readable")
            .expect("the store is stampable");
        println!("store enumeration:      {:?}", started.elapsed());
        println!("catalogs in the store:  {}", state.files.len());

        // The baseline in the same conditions rather than quoted from an earlier
        // run: this is what a scan pays today, and the number the cache has to
        // beat. It runs first so that both builds after it are measured against
        // the same page cache — the first of them benefits from this one, and
        // saying so is the difference between a measurement and a sales pitch.
        let started = Instant::now();
        let baseline = CatalogIndex::from_directory(&dir).expect("the store is readable");
        println!("uncached (from_store):  {:?}", started.elapsed());

        let started = Instant::now();
        let cold =
            CatalogIndex::from_directory_cached(&dir, &cache).expect("the store is readable");
        let cold_elapsed = started.elapsed();
        assert!(!cold.cache_hit(), "nothing was cached yet");
        println!(
            "cold (build + write):   {cold_elapsed:?}  ({} catalogs, {} digests, {} refused)",
            cold.catalogs_read(),
            cold.digest_count(),
            cold.catalogs_refused()
        );

        let bytes = fs::metadata(&cache).map(|metadata| metadata.len());
        println!("cache file:             {bytes:?} bytes");

        let started = Instant::now();
        let warm =
            CatalogIndex::from_directory_cached(&dir, &cache).expect("the store is readable");
        let warm_elapsed = started.elapsed();
        assert!(warm.cache_hit(), "the cache must be usable straight away");
        println!("warm (read the cache):  {warm_elapsed:?}");

        println!(
            "saved:                  {:?} ({:.0}% of the build)",
            cold_elapsed.saturating_sub(warm_elapsed),
            100.0 * warm_elapsed.as_secs_f64() / cold_elapsed.as_secs_f64().max(f64::EPSILON),
        );

        // The differential: the same index, not merely a loaded one.
        assert_eq!(warm.catalogs_read(), cold.catalogs_read());
        assert_eq!(warm.catalogs_refused(), cold.catalogs_refused());
        assert_eq!(warm.catalogs_oversized(), cold.catalogs_oversized());
        assert_eq!(warm.digest_count(), cold.digest_count());
        assert_eq!(warm.is_empty(), cold.is_empty());
        assert_eq!(warm.digest_count(), baseline.digest_count());
        assert_eq!(warm.catalogs_read(), baseline.catalogs_read());

        // And the same answers about real files, which is the half a digest
        // count cannot show: the cached index has no publisher of its own and
        // reads each catalog back to produce one.
        let files = sample_files(&dir, 400);
        println!("files compared:         {}", files.len());
        let started = Instant::now();
        let mut listed = 0usize;
        for path in &files {
            let Ok(data) = fs::read(path) else {
                continue;
            };
            let Ok(pe) = PeFile::parse(&data) else {
                continue;
            };
            let from_store = cold.catalogs_listing(&pe);
            let from_cache = warm.catalogs_listing(&pe);
            assert_eq!(
                from_store.len(),
                from_cache.len(),
                "{} is listed by {} catalogs and the cache says {}",
                path.display(),
                from_store.len(),
                from_cache.len()
            );
            for (one, other) in from_store.iter().zip(&from_cache) {
                assert_eq!(
                    one.subject,
                    other.subject,
                    "{} must be vouched for by the same publisher either way",
                    path.display()
                );
            }
            if !from_cache.is_empty() {
                listed += 1;
            }
        }
        println!("catalogued among them:  {listed}");
        println!("answers for those:      {:?}", started.elapsed());

        // A second pass, which is the case a scan is actually in: the publishers
        // are memoised by then, so this is what a lookup costs once warm.
        let started = Instant::now();
        for path in &files {
            let Ok(data) = fs::read(path) else {
                continue;
            };
            let Ok(pe) = PeFile::parse(&data) else {
                continue;
            };
            let _ = warm.catalogs_listing(&pe);
        }
        println!("answers, second pass:   {:?}", started.elapsed());

        let _ = fs::remove_file(&cache);
    }

    /// Real files to compare two indexes on, from the installed `System32`.
    ///
    /// Bounded by `limit`, because this is a measurement and not a scan: enough
    /// files to include the catalogued ones and the uncatalogued ones, and few
    /// enough that reading them does not become the measurement.
    fn sample_files(_store: &std::path::Path, limit: usize) -> Vec<std::path::PathBuf> {
        let Some(system32) = crate::catalog::store_directory().and_then(|store| {
            // The store directory is `System32\CatRoot\{...}`, so the files it
            // covers are two levels up. Derived rather than hardcoded so that a
            // store elsewhere in a test VM still finds its files.
            store
                .parent()
                .and_then(|catroot| catroot.parent())
                .map(std::path::Path::to_path_buf)
        }) else {
            return Vec::new();
        };
        let Ok(entries) = fs::read_dir(&system32) else {
            return Vec::new();
        };
        entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case("dll") || e.eq_ignore_ascii_case("exe"))
            })
            .take(limit)
            .collect()
    }
}
