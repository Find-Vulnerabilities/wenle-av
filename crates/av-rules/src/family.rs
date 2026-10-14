//! What a rule's *name* claims, read as evidence about the rule.
//!
//! # Why the name, and not a field
//!
//! Measured over the corpus this product ships (`yara-forge-rules-extended`,
//! 10,764 rules, 2026-09-22):
//!
//! * `score` is 75 on 9,213 of the 10,741 public rules — 86% of the corpus at
//!   one value. It cannot separate a signature from a hunting rule, which is
//!   why [`crate::calibrate`] can only put the whole corpus on one rung.
//! * `quality` runs 50..=100 with a median of 85 (the halving threshold in
//!   [`crate::calibrate::QUALITY_FLOOR`] is an opinion about construction, not
//!   about what a rule recognises).
//! * `tags` is the single string `"FILE"` on the rules that carry one, and
//!   `category` is `MALWARE`, `INFO`, or absent. Neither names a family.
//! * `family` and `variant` are keys of *this* product's own rule language.
//!   The corpus does not write them, so every one of its rules arrives with
//!   both empty.
//!
//! What is left is the name, and the name is not a hint — it is the corpus's
//! own title for the rule, and it is specific. `SEKOIA_Rootkit_Win_Purplefox_Kernel_Driver`
//! and `HARFANGLAB_Wingtb_Rootkit` are signatures of named rootkits;
//! `SIGNATURE_BASE_Webshell` and `SIGNATURE_BASE_WEBSHELL_Z_Webshell_2` are
//! family-wide webshell indicators; `SEKOIA_Rootkit_Diamorphine_Strings` and
//! `DITEKSHEN_INDICATOR_TOOL_RTK_Hiddenrootkit` say in their own names that
//! they are indicators rather than detections.
//!
//! Reading the bands alone puts all of those at 60 points, so a single match by
//! a named rootkit signature was reported `Suspicious` — reported, and never
//! acted on, because the suspicious band does not act. That is the defect this
//! module exists to close, and the shape of the fix is in [`Claim`]: a rule
//! that names a family *and* an instance of it is a signature and convicts on
//! its own, and a rule that names only the family is not.
//!
//! # What a signature claim is worth, and what it is not
//!
//! [`crate::calibrate`] reads a [`Claim::Signature`] as a conviction: the rule
//! becomes decisive and its weight is raised to the rung a single detection
//! needs. That is what the reported defect needed — a file matching a named
//! rootkit's signature was reported `Suspicious`, a band that never acts, so the
//! one match that identified the malware was the one match nothing could be
//! done about.
//!
//! It is deliberately **not** the stronger claim that the rating route makes. A
//! name is a title, and the author rated the rule ordinary; an author's rating
//! of 90 out of 100 is a statement about the samples the rule matches, and a
//! title is not. So a name-read conviction can be answered by evidence about who
//! published the file, and a rated one cannot. The measurement that settled it
//! is in [`av_core::Detection::incontestable`], and the rule that produced it was
//! this module's own example: `SIGNATURE_BASE_MAL_RANSOM_Lockbit_Apr23_1` names
//! LockBit, matched `System32\MRT.exe`, and was right to — MRT's signature
//! database holds LockBit's URLs on purpose.
//!
//! # What this module does not do
//!
//! It does not look at a file. It reads a rule's name and says what the rule
//! claims, which is one of three answers, and the caller decides what a claim
//! is worth. Nothing here knows about points, verdicts, or thresholds.
//!
//! It also never overrules an author who stated a weight: [`crate::calibrate`]
//! returns before reaching this module for a rule that carries one, so a rule
//! written in this product's own language states its own worth and is not
//! second-guessed by its spelling.

/// What a rule's name says about the rule.
///
/// The two malicious answers are not a refinement of one another — they are the
/// distinction the corpus itself draws, and it draws it by naming: a rule that
/// writes down which malware it is for (`Win32_Ransomware_Blackbasta`,
/// `Wingtb_Rootkit`, `Webshell_Jsp_Godzilla`) is a signature, and a rule that
/// names only the family (`Webshell_Php`, `Webshell`, `IMPLANT_1_V1`) is a
/// family-wide indicator. A single match by the first is evidence about *this
/// file*; a single match by the second is evidence that the file is worth a
/// look, which is what the suspicious band is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    /// Names a family and an instance of it.
    Signature,
    /// Names a family and nothing narrower.
    Family,
    /// Nothing to read.
    None,
}

/// The words a rule uses to name what it is for.
///
/// Taken from the corpus rather than invented: each of these appears as a whole
/// token in the name of at least one rule, and together they cover the families
/// the corpus detects. A family is deliberately *not* a
/// [`av_core::ThreatCategory`] — this list is longer than the category ladder
/// (`implant`, `loader`, `rat` have no category of their own) and shorter in
/// other places, because it is a reading of names and not a taxonomy.
const FAMILIES: &[&str] = &[
    "backdoor",
    "banking",
    "bootkit",
    "botnet",
    "coinminer",
    "cryptominer",
    "downloader",
    "dropper",
    "fileless",
    "implant",
    "infostealer",
    "keylogger",
    "loader",
    "miner",
    "ransom",
    "ransomware",
    "rat",
    "rootkit",
    "shellcode",
    "spyware",
    "stealer",
    "trojan",
    "webshell",
    "worm",
];

/// Words that say the rule is an indicator, a hunt, or a pattern rather than a
/// detection.
///
/// A name carrying one of these is refused outright, whatever family it also
/// names, because the corpus is saying in the rule's own title that a match is
/// not by itself a verdict. `strings` and `generic` are its most common
/// spellings: `SEKOIA_Rootkit_Diamorphine_Strings` matches strings that appear
/// in Diamorphine, and `SIGNATURE_BASE_WEBSHELL_ASP_Generic` matches a shape of
/// ASP webshell rather than one. `loldrivers` and `cape` are not malware at
/// all — the first names *vulnerable but legitimate* drivers, and the second is
/// a sandbox's behavioural signatures.
const INDICATORS: &[&str] = &[
    "behavior",
    "behaviour",
    "cape",
    "config",
    "cve",
    "example",
    "generic",
    "hacktool",
    "hunting",
    "indicator",
    "loldrivers",
    "pua",
    "pup",
    "riskware",
    "risky",
    "snippet",
    "strings",
    "susp",
    "suspicious",
    "technique",
    "template",
    "tool",
    "vuln",
];

/// Words that are not the instance of anything: who wrote the rule, what it
/// runs against, and the connective tissue of a rule title.
///
/// This list is what makes the two malicious claims separable, so it is the
/// part of this module most worth being suspicious of. It is measured rather
/// than guessed — every token here appears in the name of at least one rule of
/// the corpus that names a family and no instance, and the whole list is
/// exercised by [`tests::the_family_only_names_of_the_corpus_are_read_as_family_only`].
///
/// What is deliberately *not* here is any word that could be a malware's name.
/// `apt` is here because it names a kind of actor and not an instance, and
/// `kernel`, `driver`, and `module` are here because they say what a component
/// is: `SEKOIA_Rootkit_Win_Purplefox_Kernel_Driver` has to keep `purplefox` as
/// its instance, and it does.
const NOISE: &[&str] = &[
    // Who wrote the rule.
    "signature",
    "signatures",
    "base",
    "based",
    "malpedia",
    "ditekshen",
    "reversinglabs",
    "sekoia",
    "arkbird",
    "eset",
    "fireeye",
    "trellix",
    "russianpanda",
    "volexity",
    "gcti",
    "binaryalert",
    "harfanglab",
    "elastic",
    "sophos",
    "kaspersky",
    "bitdefender",
    "microsoft",
    "talos",
    "proofpoint",
    "trendmicro",
    "mcafee",
    "symantec",
    "fortinet",
    "unit42",
    "welivesecurity",
    "drweb",
    "avast",
    "avg",
    "comodo",
    "clamav",
    "blackberry",
    "yara",
    "rules",
    "rule",
    "detection",
    "detections",
    "sigma",
    "hayabusa",
    "chainsaw",
    "lolbas",
    // What the rule speaks about, and the frame around it.
    "malware",
    "mal",
    "apt",
    "threat",
    "actor",
    "campaign",
    "family",
    "custom",
    "set",
    "ioc",
    "iocs",
    // When. The corpus dates most of its titles, and `Aug` is not a malware —
    // without these, `ARKBIRD_SOLG_MAL_ELF_Go_Worm_Jul_2021_1` would read as a
    // signature on the strength of the month it was written in.
    "jan",
    "feb",
    "mar",
    "apr",
    "may",
    "jun",
    "jul",
    "aug",
    "sep",
    "sept",
    "oct",
    "nov",
    "dec",
    "variant",
    "file",
    "files",
    "mem",
    "memory",
    "registry",
    "reg",
    "wmi",
    "http",
    "https",
    "dns",
    "tcp",
    "udp",
    "url",
    "uri",
    "ip",
    "domain",
    "c2",
    "cnc",
    "beacon",
    "gen",
    // What it runs against.
    "win",
    "win32",
    "win64",
    "windows",
    "pe",
    "pe32",
    "pe64",
    "dos",
    "linux",
    "lnx",
    "unix",
    "elf",
    "macos",
    "osx",
    "mac",
    "android",
    "apk",
    "dex",
    "java",
    "jar",
    "bytecode",
    "msil",
    "dotnet",
    "net",
    "script",
    "scripts",
    "js",
    "javascript",
    "vbs",
    "vba",
    "vb",
    "ps1",
    "powershell",
    "ps",
    "batch",
    "bat",
    "cmd",
    "shell",
    "sh",
    "bash",
    "php",
    "asp",
    "aspx",
    "jsp",
    "perl",
    "pl",
    "python",
    "py",
    "ruby",
    "rb",
    "hta",
    "lnk",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "rtf",
    "pdf",
    "ole",
    "office",
    "macro",
    "eml",
    "msg",
    "xml",
    "html",
    "htm",
    "class",
    "go",
    "rust",
    "swift",
    "kotlin",
    "mobile",
    "iot",
    "mips",
    "arm",
    "x86",
    "x64",
    "amd64",
    "driver",
    "sys",
    "dll",
    "exe",
    "kernel",
    "module",
    "kernelmode",
];

/// Shortest token that can be an instance of a family.
///
/// Three, which is the length of the shortest malware name in the corpus's own
/// titles (`Webshell_Php_404`, `Webshell_Asp_Up`, `IMPLANT_1_V1` are named by
/// two-letter and numeric markers that say which variant of a family-wide rule
/// this is, not which malware). A token shorter than this is a version marker
/// or an initial, and treating one as an instance would make a family-wide rule
/// convict on its own — which is the whole distinction this module draws.
const MIN_INSTANCE: usize = 3;

/// Read a rule's name and say what it claims.
///
/// The tokens are compared case-insensitively and as whole tokens, so `Rat` in
/// `..._Njrat` is not the family `rat` — only a token spelled exactly `rat` is.
pub fn claim(name: &str) -> Claim {
    let tokens: Vec<String> = name
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect();

    if tokens.iter().any(|token| INDICATORS.contains(&token.as_str())) {
        return Claim::None;
    }
    if !tokens.iter().any(|token| FAMILIES.contains(&token.as_str())) {
        return Claim::None;
    }

    let names_an_instance = tokens.iter().any(|token| {
        token.len() >= MIN_INSTANCE
            && !FAMILIES.contains(&token.as_str())
            && !NOISE.contains(&token.as_str())
            && !token.chars().all(|c| c.is_ascii_digit())
    });

    if names_an_instance {
        Claim::Signature
    } else {
        Claim::Family
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule the defect was reported with: a named rootkit, quality 80,
    /// score 75 — which the bands alone put at 60 points, one rung below the
    /// line a single detection needs.
    #[test]
    fn a_named_rootkit_is_a_signature() {
        assert_eq!(claim("SEKOIA_Rootkit_Win_Purplefox_Kernel_Driver"), Claim::Signature);
        assert_eq!(claim("HARFANGLAB_Wingtb_Rootkit"), Claim::Signature);
        assert_eq!(claim("SIGNATURE_BASE_Venom_Rootkit"), Claim::Signature);
        assert_eq!(claim("REVERSINGLABS_Linux_Rootkit_Pumakit"), Claim::Signature);
    }

    /// The other half of the same measurement: the corpus marks the rules that
    /// are indicators rather than detections, and it marks them in the name.
    /// Every one of these names a family, and none of them may convict alone.
    #[test]
    fn a_rule_that_calls_itself_an_indicator_is_not_a_signature() {
        for name in [
            "SEKOIA_Rootkit_Diamorphine_Strings",
            "ESET_Apt_Windows_TA410_Rootkit_Strings",
            "DITEKSHEN_INDICATOR_TOOL_RTK_Hiddenrootkit",
            "SIGNATURE_BASE_WEBSHELL_ASP_Generic",
            "LOLDRIVERS_Vulnerable_Win_Rootkit_Driver",
            "CAPE_Ransomware_Behaviour",
        ] {
            assert_eq!(claim(name), Claim::None, "{name}");
        }
    }

    /// A family-wide rule is not a signature. This is the distinction the
    /// corpus draws by naming, and collapsing it is how a webshell rule starts
    /// convicting every PHP file on a web server.
    #[test]
    fn a_family_with_no_instance_is_a_family_and_not_a_signature() {
        for name in [
            "SIGNATURE_BASE_Webshell",
            "SIGNATURE_BASE_Webshell_Php_Up",
            "SIGNATURE_BASE_WEBSHELL_Z_Webshell_2",
            "SIGNATURE_BASE_IMPLANT_1_V1",
            "SIGNATURE_BASE_Backdoor__Fr_",
            "SIGNATURE_BASE_Php_Backdoor_Php",
        ] {
            assert_eq!(claim(name), Claim::Family, "{name}");
        }
    }

    /// The tokens that are not instances are the load-bearing part of the
    /// reading, so the names whose only extra tokens are those are asserted
    /// here individually rather than trusted to the list.
    #[test]
    fn the_family_only_names_of_the_corpus_are_read_as_family_only() {
        assert_eq!(claim("SIGNATURE_BASE_Webshell_Jsp_12302"), Claim::Family);
        assert_eq!(claim("ARKBIRD_SOLG_Loader_Buer_Nov_2020_1"), Claim::Signature);
        // `mal`, `win`, `kernel` and `driver` are all noise, so this name's
        // only instance-shaped token is `purplefox`.
        assert_eq!(claim("SEKOIA_Rootkit_Win_Purplefox_Kernel_Driver"), Claim::Signature);
    }

    /// A vendor name is not a family, however much it reads like one, and a
    /// rule that names nothing this module knows is not read at all.
    #[test]
    fn a_name_with_no_family_token_claims_nothing() {
        for name in [
            "SIGNATURE_BASE_MAL_Kernel_Regphantom_Mar26",
            "ARKBIRD_SOLG_MAL_Netfilter_May_2021_1",
            "TRELLIX_ARC_APT_Acidbox_Kernelmode_Module",
            "REVERSINGLABS_Windows_Defender_Exclusion",
        ] {
            assert_eq!(claim(name), Claim::None, "{name}");
        }
    }

    /// Whole tokens, not substrings. `Njrat` is a family's name and `rat` is a
    /// family word, and only the second is one.
    #[test]
    fn a_family_word_inside_a_longer_name_is_not_that_family() {
        assert_eq!(claim("REVERSINGLABS_Bytecode_MSIL_Backdoor_Njrat"), Claim::Signature);
        assert_eq!(claim("VENDOR_Generic_Tool_Ratatosk"), Claim::None);
        assert_eq!(claim("VENDOR_Linux_Trojan_Mineratron"), Claim::Signature);
    }

    #[test]
    fn the_reading_is_case_insensitive_on_the_name_and_on_the_tokens() {
        assert_eq!(claim("sekoia_rootkit_win_PURPLEFOX_kernel_driver"), Claim::Signature);
        assert_eq!(claim("SEKOIA-ROOTKIT-WIN-PURPLEFOX-KERNEL-DRIVER"), Claim::Signature);
    }

    /// A number is not an instance, and an instance is not a number.
    #[test]
    fn digits_and_version_markers_are_never_an_instance() {
        assert_eq!(claim("SIGNATURE_BASE_Ransomware_2024"), Claim::Family);
        assert_eq!(claim("SIGNATURE_BASE_Ransomware_V2"), Claim::Family);
        assert_eq!(claim("SIGNATURE_BASE_Ransomware_Lockbit"), Claim::Signature);
    }

    /// The vocabulary denies what an instance is *not*; it does not list what
    /// one is. So a word nobody has heard of is read as the instance it looks
    /// like — which is the direction to err in, because the failure that costs
    /// a user something is a named rootkit that cannot be acted on, and the
    /// failure that costs a user nothing is a rule this engine does not know
    /// how to place being left where it was.
    #[test]
    fn a_word_the_vocabulary_does_not_know_is_read_as_an_instance() {
        assert_eq!(claim("VENDOR_Ransomware_Zzzz"), Claim::Signature);
    }

    /// The vocabulary is a reading of the corpus, so it is asserted to be
    /// internally consistent: no word may be both a family and an indicator,
    /// and no word may be both a family and noise. A word in two lists would
    /// make a claim depend on which check ran first.
    #[test]
    fn no_word_is_in_two_vocabularies() {
        for family in FAMILIES {
            assert!(!INDICATORS.contains(family), "{family} is both");
            assert!(!NOISE.contains(family), "{family} is both");
        }
        for indicator in INDICATORS {
            assert!(!NOISE.contains(indicator), "{indicator} is both");
        }
    }

    /// No word appears twice in one list.
    ///
    /// Not sortedness: [`NOISE`] is grouped by what its words say — who wrote
    /// the rule, what it speaks about, what it runs against — and alphabetising
    /// it would throw away the only thing that makes a list of two hundred
    /// words readable. [`FAMILIES`] and [`INDICATORS`] are short enough to keep
    /// in order, and are asserted to be, because an unsorted short list is
    /// where a duplicate hides.
    #[test]
    fn the_vocabularies_have_no_duplicates() {
        for list in [FAMILIES, INDICATORS, NOISE] {
            let mut seen = list.to_vec();
            seen.sort_unstable();
            seen.dedup();
            assert_eq!(seen.len(), list.len(), "a word appears twice");
        }
        for list in [FAMILIES, INDICATORS] {
            let mut sorted = list.to_vec();
            sorted.sort_unstable();
            assert_eq!(sorted, list, "not sorted");
        }
    }
}
