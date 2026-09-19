//! Threat naming.
//!
//! Names follow the industry-standard `<platform>.<category>.<family>[.<variant>]`
//! convention (the CARO-style scheme used by essentially every commercial
//! engine), so detections read like `Win32.Ransomware.LockBit` or
//! `Win32.Trojan.Emotet.gen` and can be cross-referenced with public reports.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The platform a threat targets. Determined from the host file's format, not
/// from where it was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Win32,
    Win64,
    /// A native Windows binary whose bitness we could not determine.
    Win,
    /// VBScript / JScript / PowerShell / batch.
    Script,
    /// VBA / Excel 4.0 macros.
    Macro,
    /// `.NET` assemblies.
    DotNet,
    Java,
    Android,
    Linux,
    Unknown,
}

impl Platform {
    pub const fn as_str(self) -> &'static str {
        match self {
            Platform::Win32 => "Win32",
            Platform::Win64 => "Win64",
            Platform::Win => "Win",
            Platform::Script => "Script",
            Platform::Macro => "Macro",
            Platform::DotNet => "MSIL",
            Platform::Java => "Java",
            Platform::Android => "Android",
            Platform::Linux => "Linux",
            Platform::Unknown => "Generic",
        }
    }

    /// Best-effort mapping from a YARA-style platform tag.
    pub fn from_tag(tag: &str) -> Option<Self> {
        let t = tag.to_ascii_lowercase();
        Some(match t.as_str() {
            "win32" | "pe32" => Platform::Win32,
            "win64" | "pe64" => Platform::Win64,
            "windows" | "pe" | "win" => Platform::Win,
            "script" | "powershell" | "js" | "vbs" => Platform::Script,
            "macro" | "office" | "ole" => Platform::Macro,
            "dotnet" | "msil" | ".net" | "csharp" => Platform::DotNet,
            "java" | "jar" => Platform::Java,
            "android" | "apk" | "dex" => Platform::Android,
            "linux" | "elf" => Platform::Linux,
            _ => return None,
        })
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What kind of malicious (or unwanted) software we are looking at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatCategory {
    Virus,
    Worm,
    Trojan,
    Backdoor,
    Ransomware,
    RansomNote,
    Infostealer,
    Keylogger,
    Spyware,
    Banking,
    Botnet,
    Downloader,
    Dropper,
    Loader,
    Rootkit,
    Bootkit,
    Exploit,
    Shellcode,
    Fileless,
    Miner,
    Adware,
    Pua,
    Rogue,
    HackTool,
    Webshell,
    Phishing,
    Ransom,
    Unknown,
}

impl ThreatCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            ThreatCategory::Virus => "Virus",
            ThreatCategory::Worm => "Worm",
            ThreatCategory::Trojan => "Trojan",
            ThreatCategory::Backdoor => "Backdoor",
            ThreatCategory::Ransomware => "Ransomware",
            ThreatCategory::RansomNote => "RansomNote",
            ThreatCategory::Infostealer => "Infostealer",
            ThreatCategory::Keylogger => "Keylogger",
            ThreatCategory::Spyware => "Spyware",
            ThreatCategory::Banking => "Banking",
            ThreatCategory::Botnet => "Botnet",
            ThreatCategory::Downloader => "Downloader",
            ThreatCategory::Dropper => "Dropper",
            ThreatCategory::Loader => "Loader",
            ThreatCategory::Rootkit => "Rootkit",
            ThreatCategory::Bootkit => "Bootkit",
            ThreatCategory::Exploit => "Exploit",
            ThreatCategory::Shellcode => "Shellcode",
            ThreatCategory::Fileless => "Fileless",
            ThreatCategory::Miner => "Miner",
            ThreatCategory::Adware => "Adware",
            ThreatCategory::Pua => "PUA",
            ThreatCategory::Rogue => "Rogue",
            ThreatCategory::HackTool => "HackTool",
            ThreatCategory::Webshell => "Webshell",
            ThreatCategory::Phishing => "Phishing",
            ThreatCategory::Ransom => "Ransom",
            ThreatCategory::Unknown => "Malware",
        }
    }

    /// Whether this category covers software that is *unwanted* rather than
    /// outright malicious. Such detections default to a lower severity and are
    /// the ones users most often want to allow.
    pub const fn is_unwanted_not_malicious(self) -> bool {
        matches!(
            self,
            ThreatCategory::Adware
                | ThreatCategory::Pua
                | ThreatCategory::Rogue
                | ThreatCategory::HackTool
        )
    }

    /// Map a free-form tag (from YARA rule metadata, a rule author, or a file
    /// name convention) onto a category.
    pub fn from_tag(tag: &str) -> Option<Self> {
        let t = tag.to_ascii_lowercase();
        let t = t.trim().trim_start_matches("tc_detection_type:").trim();
        Some(match t {
            "virus" => ThreatCategory::Virus,
            "worm" => ThreatCategory::Worm,
            "trojan" | "trojan_downloader" | "trojan_dropper" => ThreatCategory::Trojan,
            "backdoor" | "rat" | "remote_access" => ThreatCategory::Backdoor,
            "ransomware" | "ransom" => ThreatCategory::Ransomware,
            "ransomnote" | "ransom_note" => ThreatCategory::RansomNote,
            "infostealer" | "stealer" | "credential" | "password_stealer" => {
                ThreatCategory::Infostealer
            }
            "keylogger" => ThreatCategory::Keylogger,
            "spyware" => ThreatCategory::Spyware,
            "banking" | "banker" | "banker_trojan" => ThreatCategory::Banking,
            "botnet" | "bot" | "ircbot" => ThreatCategory::Botnet,
            "downloader" | "dropper" | "loader" => ThreatCategory::Downloader,
            "rootkit" => ThreatCategory::Rootkit,
            "bootkit" => ThreatCategory::Bootkit,
            "exploit" | "exploit_kit" => ThreatCategory::Exploit,
            "shellcode" => ThreatCategory::Shellcode,
            "fileless" | "memory_only" => ThreatCategory::Fileless,
            "miner" | "coinminer" | "cryptominer" | "mining" => ThreatCategory::Miner,
            "adware" => ThreatCategory::Adware,
            "pua" | "pup" | "unwanted" | "potentially_unwanted" => ThreatCategory::Pua,
            "rogue" | "scareware" | "fakeav" => ThreatCategory::Rogue,
            "hacktool" | "hacking_tool" | "tool" | "riskware" => ThreatCategory::HackTool,
            "webshell" | "web_shell" => ThreatCategory::Webshell,
            "phishing" => ThreatCategory::Phishing,
            "malware" | "malicious" | "generic" => ThreatCategory::Unknown,
            _ => return None,
        })
    }
}

impl fmt::Display for ThreatCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A structured detection name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThreatName {
    pub platform: Platform,
    pub category: ThreatCategory,
    /// Malware family, e.g. `Emotet`. `None` for generic detections.
    pub family: Option<String>,
    /// Variant or generation marker, e.g. `gen`, `a`, `2`.
    pub variant: Option<String>,
}

impl ThreatName {
    pub fn new(platform: Platform, category: ThreatCategory) -> Self {
        Self {
            platform,
            category,
            family: None,
            variant: None,
        }
    }

    pub fn with_family(mut self, family: impl Into<String>) -> Self {
        let f = family.into();
        if !f.is_empty() {
            self.family = Some(f);
        }
        self
    }

    pub fn with_variant(mut self, variant: impl Into<String>) -> Self {
        let v = variant.into();
        if !v.is_empty() {
            self.variant = Some(v);
        }
        self
    }

    /// A generic detection for a given category, e.g. `Win32.Ransomware.gen`.
    pub fn generic(platform: Platform, category: ThreatCategory) -> Self {
        Self::new(platform, category).with_variant("gen")
    }

    /// Sanitise an arbitrary string into a legal family/variant component:
    /// alphanumeric only, no separators, so a crafted rule name cannot forge a
    /// different detection name by smuggling in dots.
    pub fn sanitize_component(raw: &str) -> String {
        let cleaned: String = raw
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(32)
            .collect();
        if cleaned.is_empty() {
            "gen".to_string()
        } else {
            cleaned
        }
    }
}

impl fmt::Display for ThreatName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.platform, self.category)?;
        if let Some(family) = &self.family {
            write!(f, ".{family}")?;
            if let Some(variant) = &self.variant {
                write!(f, ".{variant}")?;
            }
        } else {
            write!(f, ".gen")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_name_renders_all_components() {
        let name = ThreatName::new(Platform::Win32, ThreatCategory::Ransomware)
            .with_family("LockBit")
            .with_variant("3");
        assert_eq!(name.to_string(), "Win32.Ransomware.LockBit.3");
    }

    #[test]
    fn name_without_family_falls_back_to_gen() {
        let name = ThreatName::new(Platform::Win64, ThreatCategory::Trojan);
        assert_eq!(name.to_string(), "Win64.Trojan.gen");
    }

    #[test]
    fn sanitize_strips_separators_so_names_cannot_be_forged() {
        assert_eq!(ThreatName::sanitize_component("..Win32.Evil"), "Win32Evil");
        assert_eq!(ThreatName::sanitize_component("!!!"), "gen");
        assert_eq!(ThreatName::sanitize_component(""), "gen");
    }

    #[test]
    fn tag_mapping_covers_common_yara_tags() {
        assert_eq!(
            ThreatCategory::from_tag("RANSOMWARE"),
            Some(ThreatCategory::Ransomware)
        );
        assert_eq!(
            ThreatCategory::from_tag("pup"),
            Some(ThreatCategory::Pua)
        );
        assert_eq!(ThreatCategory::from_tag("nonsense"), None);
    }

    #[test]
    fn unwanted_categories_are_flagged() {
        assert!(ThreatCategory::Adware.is_unwanted_not_malicious());
        assert!(!ThreatCategory::Ransomware.is_unwanted_not_malicious());
    }
}
