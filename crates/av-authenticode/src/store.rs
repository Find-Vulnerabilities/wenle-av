//! The platform's chain engine, and the one decision this crate rests on.
//!
//! # The decision, stated plainly
//!
//! **Chain building and root trust are the platform's. Everything about the
//! file is ours.**
//!
//! Concretely: this module calls `CertGetCertificateChain` from `crypt32`, and
//! [`crate::chain`] interprets what it returns. This crate does not walk a
//! chain itself, does not hold a root list, and does not decide whether a
//! certificate is a CA, whether a name constraint applies, or whether a key
//! usage permits what it was used for. It *does* decide whether the signature
//! over the file holds, which is the half the platform's engine is not asked
//! about.
//!
//! # Why, in the terms the alternatives fail
//!
//! Three designs were on the table.
//!
//! **Hand-rolled chain building with roots read from the OS store** is not a
//! design. It is OS-dependent — so this code's behaviour cannot be reasoned
//! about without the OS — *and* hand-rolled, so every subtle part is still
//! ours: name constraints, basic constraints, key usage, EKU, the intersection
//! of validity periods across a chain, and the expired-leaf-but-timestamped
//! case that is 30.5% of the measured population. It takes on all the work of
//! a chain engine and none of the freedom of owning the roots, and the way a
//! second implementation of a chain engine fails is by being **more
//! permissive** than the first. Permissive divergence is the failure that
//! matters: it is the one that clears a detection on a file that should not
//! have been cleared. It was rejected on those grounds, not on cost.
//!
//! **Embedding our own roots** would make this crate's behaviour independent of
//! the machine, which is a real virtue, and it is not ours to take. The trust
//! anchor list is *security policy*, and it is the OS vendor's to set: it moves
//! when a CA is distrusted, when a root is retired, when a government-issued CA
//! is removed after an incident. A copy embedded here would be a snapshot of a
//! policy that changes, updated on this project's release schedule rather than
//! on the schedule of the incident that forces it, and the failure mode is
//! trusting a CA that has been distrusted everywhere else.
//!
//! **Asking the OS whether the signature is good** — `WinVerifyTrust` — was on
//! the table and is the design that was measured against. It was not rejected
//! for being forbidden: the product's no-cloud rule is about where a *verdict*
//! comes from, not about whether an OS API may touch the network, and
//! `WinVerifyTrust` has flags for exactly that. It was rejected on the
//! measurement. The numbers are in the module documentation of [`crate::chain`],
//! which is where the two routes are compared call by call.
//!
//! # The measurement
//!
//! A probe ran both routes over every file in an installed `System32`: this
//! module's `CertGetCertificateChain` plus the crate's own digest and RSA
//! arithmetic, and `WinVerifyTrust` with `WTD_UI_NONE | WTD_REVOKE_NONE |
//! WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4`. The counts, the wall
//! times and the failure taxonomy are in the module documentation of
//! [`crate::chain`], which is where the two are compared call by call.
//!
//! The conclusion is narrow and worth stating narrowly: on this population the
//! two routes agree on every file whose signature is well-formed, and they
//! differ exactly on the files whose chain needs the certificates the file
//! itself carries. `WinVerifyTrust` with cache-only retrieval does not use the
//! blob's own certificates as an additional store, so a file whose intermediate
//! is in its own `PKCS#7` and nowhere on the machine comes back as a chaining
//! failure rather than as the honest answer. Supplying those certificates as
//! `hAdditionalStore` and building offline gives the honest answer — which is
//! what this module does.
//!
//! # What is given up by not using it
//!
//! Candour about the trade, since a stated trade is the point:
//!
//! - **Revocation is not checked.** Checking it means fetching CRLs and OCSP
//!   responses, which is a network operation whose result would make a scan
//!   non-reproducible, and whose absence offline would make every file
//!   undetermined. `CertGetCertificateChain` is asked with
//!   `CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL` and no revocation flags, which means
//!   a cached CRL is used if one happens to be there and nothing is fetched.
//!   A signature that has been revoked therefore reads as valid. That is a real
//!   gap and it is the largest one here — and the probe's taxonomy shows how
//!   visible it is: a chain the engine rejects for revocation is reported as a
//!   *rejection*, not silently accepted.
//! - **`WinVerifyTrust` applies more policy than chain building.** It also
//!   checks the file against the *catalog* when there is no embedded
//!   signature, applies driver-signing and Windows Store policies, and honours
//!   the `AuthRoot` and disallowed-certificate stores through its own code
//!   paths. None of that is reproduced. The engine's catalog handling lives in
//!   [`av_signatures::catalog`] and is somebody else's job to wire together
//!   with this; what this crate answers is strictly about the embedded
//!   signature.
//! - **Unprocessed critical extensions** are the platform's business, which is
//!   the point of delegating: the chain engine enforces that rule over the
//!   whole path, including the parts this crate never parses.
//!
//! # The cache-only flag is a decision, not a default
//!
//! `CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL` is set. Without it the chain engine
//! will fetch certificates, CRLs and OCSP responses over the network, and a
//! scan's verdict would then depend on whether the machine had a working
//! connection — and the product's no-cloud rule makes a verdict that comes from
//! a remote server the wrong shape of answer regardless. The cost is measured:
//! the probe's taxonomy names the files that chain online and not offline, and
//! they land in [`crate::Verdict::Untrusted`] with a named reason rather than
//! being reported as trusted or as invalid.

use crate::error::AuthError;

/// A chain the platform's engine built.
///
/// The fields are the engine's own words rather than a conclusion, which is
/// deliberate: the interpretation is in [`crate::chain`], so that "what the
/// platform said" and "what this crate makes of it" are two readable things
/// rather than one function with both jobs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformChain {
    /// The error status of the whole chain, as the platform reports it — the
    /// `dwErrorStatus` bitmask of the chain context. Zero means the engine was
    /// satisfied.
    ///
    /// Kept as the raw bitmask rather than as a list of decoded names, because
    /// the names are this crate's reading of it and the bitmask is the
    /// platform's statement. [`crate::chain`] decodes it; a log line can carry
    /// both and a person can check the bits against Microsoft's documentation
    /// without trusting the decoding.
    pub status: u32,
    /// The subjects of the first simple chain's elements, subject first and the
    /// anchor last.
    ///
    /// Only the first simple chain: the engine returns alternates when it can
    /// build more than one path, and concatenating them would produce a list
    /// that is not a chain.
    pub subjects: Vec<String>,
    /// The subject of the last element, which is the anchor the chain reached.
    ///
    /// Empty when the engine's element list was unreadable.
    pub root: String,
    /// Whether that anchor is one of this machine's trusted roots.
    ///
    /// Taken from the engine's own `CERT_TRUST_IS_UNTRUSTED_ROOT` bit rather
    /// than by comparing the anchor's subject against a list read separately:
    /// the engine knows which store it drew the anchor from, and a comparison
    /// against a second reading of the stores could disagree with it — in the
    /// permissive direction, which is the one that matters.
    pub root_is_trusted: bool,
}

/// A moment to judge a chain at.
///
/// A named type rather than a bare `i64` because the difference between
/// "judge at the current time" and "judge at the time the counter-signature
/// asserts" is the difference between 30.5% of `System32` reading as expired
/// and not, and a bare integer at a call site says nothing about which is
/// meant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum At {
    /// The current time.
    Now,
    /// A specific instant, in Unix seconds, from a verified counter-signature.
    Unix(i64),
}

/// Build a chain for `leaf_der`, at `at`, using only what is already on this
/// machine and whatever `extra` supplies.
///
/// `extra` is where the certificates the *file itself* carries go. It matters:
/// the files whose intermediate is in the blob and nowhere on the machine are
/// the files the alternative route gets wrong, and without them the chain fails
/// for a reason that says more about the machine than about the file.
///
/// On a non-Windows host this is not available and returns [`AuthError::Store`],
/// which [`crate::chain`] turns into [`crate::Verdict::Undetermined`]. That is
/// the fail-closed direction: a platform without a chain engine cannot produce
/// a trusted verdict, and guessing would be worse than saying so.
#[cfg(windows)]
pub fn chain_for(leaf_der: &[u8], extra: &[&[u8]], at: At) -> Result<PlatformChain, AuthError> {
    imp::chain_for(leaf_der, extra, at)
}

/// See the Windows implementation.
///
/// `reason` is a `String` and not a `&'static str`, so the literal is converted.
/// This arm is compiled out on Windows, which is the only platform this product
/// ships for — which is exactly why the conversion has to be written carefully:
/// a body that is never compiled on the machine it is developed on is a body
/// that nothing here would notice was wrong.
#[cfg(not(windows))]
pub fn chain_for(_leaf_der: &[u8], _extra: &[&[u8]], _at: At) -> Result<PlatformChain, AuthError> {
    Err(AuthError::Store {
        reason: "chain building needs the platform's chain engine, and this build has none"
            .to_string(),
    })
}

/// The subjects of the root certificates this machine trusts.
///
/// Exposed so a caller can answer "is this root one of ours" without building
/// a chain, and so a diagnostic can say which store it read. It is **not** used
/// to decide a verdict: the chain engine already reports whether the anchor it
/// used was a trusted one, and deciding separately would be a second opinion
/// that could disagree with the first.
#[cfg(windows)]
pub fn trusted_root_subjects() -> Result<Vec<String>, AuthError> {
    imp::trusted_root_subjects()
}

/// See the Windows implementation.
///
/// Converted for the reason [`chain_for`]'s non-Windows arm gives.
#[cfg(not(windows))]
pub fn trusted_root_subjects() -> Result<Vec<String>, AuthError> {
    Err(AuthError::Store {
        reason: "the root store is a Windows facility and this build has no access to it"
            .to_string(),
    })
}

#[cfg(windows)]
mod imp {
    use super::{At, PlatformChain};
    use crate::error::AuthError;
    use std::ffi::c_void;
    use std::ptr;

    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::Security::Cryptography::{
        CertAddEncodedCertificateToStore, CertCloseStore, CertCreateCertificateContext,
        CertEnumCertificatesInStore, CertFreeCertificateChain, CertFreeCertificateContext,
        CertGetCertificateChain, CertGetNameStringW, CertOpenStore,
        CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, CERT_CHAIN_CONTEXT, CERT_CHAIN_PARA,
        CERT_CLOSE_STORE_FORCE_FLAG, CERT_CONTEXT, CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CERT_OPEN_STORE_FLAGS, CERT_STORE_ADD_ALWAYS, CERT_STORE_PROV_MEMORY,
        CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE,
        CERT_TRUST_IS_UNTRUSTED_ROOT, CERT_USAGE_MATCH, HCERTSTORE, PKCS_7_ASN_ENCODING,
        USAGE_MATCH_TYPE_AND, X509_ASN_ENCODING,
    };

    /// `X509_ASN_ENCODING | PKCS_7_ASN_ENCODING`, which is what every call here
    /// is made with.
    fn encoding() -> windows::Win32::Security::Cryptography::CERT_QUERY_ENCODING_TYPE {
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
    }

    /// The chain engine, asked about one certificate.
    pub fn chain_for(leaf_der: &[u8], extra: &[&[u8]], at: At) -> Result<PlatformChain, AuthError> {
        // `CertCreateCertificateContext` copies `leaf_der` into a context it
        // owns, so the returned pointer outlives this borrow and the guard below
        // is what releases it. Every early return after this point goes through
        // the guards, and there is no path that leaks one.
        let leaf = unsafe { CertCreateCertificateContext(encoding(), leaf_der) };
        if leaf.is_null() {
            return Err(AuthError::Store {
                reason: "the leaf certificate could not be turned into a context".to_owned(),
            });
        }
        let leaf = LeafGuard(leaf);

        // The file's own certificates, in a memory store. `hAdditionalStore` is
        // what makes a file whose intermediate is in its own blob chain offline:
        // a machine store cannot supply a certificate no machine store has.
        let additional = memory_store(extra)?;

        // An empty `RequestedUsage` with `USAGE_MATCH_TYPE_AND` asks for no
        // particular usage, which is what passing no chain parameters at all
        // means. The usage a signer must have is a fact about the certificate
        // and is checked by [`crate::chain`] against the leaf, not here: a
        // verifier that narrowed the engine's search by EKU would get a
        // *different chain* rather than a rejection, and then be unable to say
        // why.
        let para = CERT_CHAIN_PARA {
            cbSize: std::mem::size_of::<CERT_CHAIN_PARA>() as u32,
            RequestedUsage: CERT_USAGE_MATCH {
                dwType: USAGE_MATCH_TYPE_AND,
                ..Default::default()
            },
            ..Default::default()
        };

        let mut file_time = to_filetime(at);
        let time_ptr: *const FILETIME = match at {
            At::Now => ptr::null(),
            At::Unix(_) => &file_time,
        };

        let mut chain: *mut CERT_CHAIN_CONTEXT = ptr::null_mut();
        let built = unsafe {
            CertGetCertificateChain(
                None,
                leaf.0,
                Some(time_ptr),
                additional.as_ref().map(|store| store.0),
                &para,
                // Cache-only: a verdict must not depend on whether this machine
                // had a working connection. See the module documentation.
                CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL,
                None,
                &mut chain,
            )
        };
        // Kept alive for the duration of the call above and no longer; the
        // `FILETIME` is only read while the engine is building.
        let _ = &mut file_time;

        if let Err(error) = built {
            // A refusal to *build* is a different answer from a chain that was
            // built and rejected, and the two lead to different verdicts: one
            // says the machine could not be asked, the other says the machine
            // answered. See [`AuthError::NoChain`].
            return Err(AuthError::NoChain {
                reason: format!("the chain engine refused to build a chain: {error}"),
            });
        }
        if chain.is_null() {
            return Err(AuthError::NoChain {
                reason: "the chain engine reported success and returned no chain".to_owned(),
            });
        }
        let chain_guard = ChainGuard(chain);

        let context = unsafe { &*chain_guard.0 };
        let status = context.TrustStatus.dwErrorStatus;

        // The first simple chain, not every one. `cChain` counts alternate
        // paths the engine could build; concatenating them would produce a list
        // that is not a path from the leaf to a root, and the anchor is the end
        // of the path the engine actually chose.
        let mut subjects = Vec::new();
        let mut root_is_trusted = false;
        if context.cChain > 0 && !context.rgpChain.is_null() {
            let simple = unsafe { &**context.rgpChain };
            for index in 0..simple.cElement as usize {
                let element = unsafe { simple.rgpElement.add(index) };
                if element.is_null() {
                    continue;
                }
                let element = unsafe { &**element };
                let certificate = element.pCertContext;
                if certificate.is_null() {
                    continue;
                }
                if let Some(subject) = unsafe { subject_of(&*certificate) } {
                    subjects.push(subject);
                }
            }

            // Whether the anchor is a root this machine trusts. There is no
            // per-element field for it — `CERT_CHAIN_ELEMENT` carries
            // `TrustStatus` and nothing else about the anchor — so it is read
            // from the simple chain's own error status, which is where the
            // engine sets `CERT_TRUST_IS_UNTRUSTED_ROOT` for the path it built.
            //
            // Assigned only when a chain was actually readable, so the default
            // stays `false`: an element list this code could not walk must not
            // read as "the anchor is fine".
            root_is_trusted = simple.TrustStatus.dwErrorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT == 0;
        }

        let root = subjects.last().cloned().unwrap_or_default();

        Ok(PlatformChain {
            status,
            subjects,
            root,
            root_is_trusted,
        })
    }

    /// The subjects of the roots in the machine's stores.
    pub fn trusted_root_subjects() -> Result<Vec<String>, AuthError> {
        let mut out = Vec::new();
        for location in [
            CERT_SYSTEM_STORE_LOCAL_MACHINE,
            CERT_SYSTEM_STORE_CURRENT_USER,
        ] {
            // `CERT_STORE_PROV_SYSTEM_W` wants a wide string, and it is read
            // only while the store is open — so the buffer is built here and
            // lives until the end of the iteration.
            let name: Vec<u16> = "ROOT\0".encode_utf16().collect();
            let opened = unsafe {
                CertOpenStore(
                    CERT_STORE_PROV_SYSTEM_W,
                    // The encoding is irrelevant for a system store — the store
                    // holds whatever it holds and the provider ignores it — but
                    // it is passed as the crate's one encoding rather than as a
                    // bare zero, so that the two calls here cannot drift apart
                    // in what they say the bytes are.
                    encoding(),
                    None,
                    CERT_OPEN_STORE_FLAGS(location),
                    Some(name.as_ptr() as *const c_void),
                )
            };
            let Ok(store) = opened else { continue };
            let store = StoreGuard(store);

            let mut context: *const CERT_CONTEXT = ptr::null();
            loop {
                context = unsafe { CertEnumCertificatesInStore(store.0, Some(context)) };
                if context.is_null() {
                    break;
                }
                // The contexts `CertEnumCertificatesInStore` hands back are
                // owned by the store and freed by the *next* call on it, which
                // is why nothing frees them here.
                if let Some(subject) = unsafe { subject_of(&*context) } {
                    out.push(subject);
                }
            }
        }
        Ok(out)
    }

    /// The simple display name of a certificate, as the platform renders it.
    ///
    /// Rendering the name with the platform's own call rather than by decoding
    /// the `Name` here is deliberate: it is the same string `certutil` and the
    /// certificate manager show, so a report's subject can be compared against
    /// what the user sees without a second name decoder to disagree with.
    ///
    /// # Safety
    ///
    /// `context` must be a valid `CERT_CONTEXT` for the duration of the call.
    unsafe fn subject_of(context: &CERT_CONTEXT) -> Option<String> {
        // First call with no buffer returns the length, including the
        // terminator. Zero means the call failed or the name is empty, and
        // either way there is nothing to render.
        let len =
            unsafe { CertGetNameStringW(context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None) };
        if len <= 1 {
            return None;
        }
        let mut buffer = vec![0u16; len as usize];
        let written = unsafe {
            CertGetNameStringW(
                context,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                None,
                Some(&mut buffer),
            )
        };
        if written == 0 {
            return None;
        }
        // `written` counts the terminator; the slice that is actually a name is
        // everything before it.
        let end = (written as usize).saturating_sub(1).min(buffer.len());
        String::from_utf16(buffer.get(..end)?).ok()
    }

    /// A memory store holding the given certificates.
    ///
    /// `Ok(None)` when there are none, so the caller passes no additional store
    /// rather than an empty one. The engine treats the two differently: an
    /// empty store is a store it must search and find nothing in.
    fn memory_store(extra: &[&[u8]]) -> Result<Option<StoreGuard>, AuthError> {
        if extra.is_empty() {
            return Ok(None);
        }
        let store = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_MEMORY,
                encoding(),
                None,
                CERT_OPEN_STORE_FLAGS(0),
                None,
            )
        }
        .map_err(|_| AuthError::Store {
            reason: "a memory store for the file's own certificates could not be opened".to_owned(),
        })?;
        let store = StoreGuard(store);

        for der in extra {
            // A certificate the blob carries that will not parse is skipped
            // rather than fatal: the engine is being offered candidates, and one
            // it cannot use is one it will not use. Refusing the whole chain
            // because a blob carried one malformed certificate would fail a
            // correctly signed file.
            unsafe {
                let _ = CertAddEncodedCertificateToStore(
                    Some(store.0),
                    encoding(),
                    der,
                    CERT_STORE_ADD_ALWAYS,
                    None,
                );
            }
        }
        Ok(Some(store))
    }

    /// A `FILETIME` for the given instant.
    ///
    /// `FILETIME` counts 100-nanosecond intervals since 1601-01-01, and Unix
    /// seconds since 1970-01-01. The offset between them is a constant, and the
    /// arithmetic is `i64` rather than `u64` because the conversion is then the
    /// same expression in both directions.
    fn to_filetime(at: At) -> FILETIME {
        const EPOCH_DIFFERENCE: i64 = 11_644_473_600;
        let seconds = match at {
            // Only reached for `At::Now`, where the pointer handed to the
            // engine is null and this value is never read.
            At::Now => 0,
            At::Unix(seconds) => seconds,
        };
        let intervals = (seconds + EPOCH_DIFFERENCE) * 10_000_000;
        FILETIME {
            dwLowDateTime: (intervals & 0xffff_ffff) as u32,
            dwHighDateTime: ((intervals >> 32) & 0xffff_ffff) as u32,
        }
    }

    /// Frees a certificate context on the way out.
    struct LeafGuard(*const CERT_CONTEXT);

    impl Drop for LeafGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = CertFreeCertificateContext(Some(self.0));
            }
        }
    }

    /// Frees a chain context on the way out.
    struct ChainGuard(*const CERT_CHAIN_CONTEXT);

    impl Drop for ChainGuard {
        fn drop(&mut self) {
            unsafe {
                CertFreeCertificateChain(self.0);
            }
        }
    }

    /// Closes a store on the way out.
    struct StoreGuard(HCERTSTORE);

    impl Drop for StoreGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = CertCloseStore(Some(self.0), CERT_CLOSE_STORE_FORCE_FLAG);
            }
        }
    }
}
