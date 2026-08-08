#![cfg(windows)]
#![allow(dead_code)]

use std::process::Command;

use crate::certs::{Ca, Leaf};
use crate::learnfixture::TempDir;

const PASSWORD: &str = "rsl-interop-ephemeral";

pub struct WindowsCertStore {
    directory: TempDir,
    my: Vec<String>,
    trusted_people: Vec<String>,
}

impl WindowsCertStore {
    pub fn new(name: &str) -> WindowsCertStore {
        WindowsCertStore {
            directory: TempDir::new(name),
            my: Vec::new(),
            trusted_people: Vec::new(),
        }
    }

    pub fn trust_peer(&mut self, leaf: &Leaf, name: &str) {
        let path = self.directory.join(&format!("{name}-trusted.pem"));
        std::fs::write(&path, leaf.leaf_pem()).expect("write trusted peer PEM");
        run_powershell(
            r#"
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    $env:RSL_CERT_PEER)
$store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
    "TrustedPeople",
    [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$store.Add($cert)
$store.Close()
"#,
            &[("RSL_CERT_PEER", path.as_os_str())],
        );
        self.trusted_people.push(leaf.thumbprint().to_string());
    }

    pub fn install_identity(&mut self, leaf: &Leaf, name: &str) {
        let cert = self.directory.join(&format!("{name}.pem"));
        let key = self.directory.join(&format!("{name}.key"));
        let pfx = self.directory.join(&format!("{name}.pfx"));
        std::fs::write(&cert, leaf.leaf_pem()).expect("write leaf PEM");
        std::fs::write(&key, leaf.key_pem()).expect("write key PEM");
        run_powershell(
            r#"
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile(
    $env:RSL_CERT_PEM,
    $env:RSL_KEY_PEM)
$bytes = $cert.Export(
    [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx,
    $env:RSL_PFX_PASSWORD)
[System.IO.File]::WriteAllBytes($env:RSL_PFX_PATH, $bytes)
$flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet `
    -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet `
    -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
$imported = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    $env:RSL_PFX_PATH,
    $env:RSL_PFX_PASSWORD,
    $flags)
$store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
    "My",
    [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$store.Add($imported)
$found = $store.Certificates.Find(
    [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
    $imported.Thumbprint,
    $false)
if ($found.Count -ne 1 -or -not $found[0].HasPrivateKey) {
    throw "imported certificate has no persisted private key"
}
$store.Close()
"#,
            &[
                ("RSL_CERT_PEM", cert.as_os_str()),
                ("RSL_KEY_PEM", key.as_os_str()),
                ("RSL_PFX_PATH", pfx.as_os_str()),
                ("RSL_PFX_PASSWORD", std::ffi::OsStr::new(PASSWORD)),
            ],
        );
        self.my.push(leaf.thumbprint().to_string());
    }
}

impl Drop for WindowsCertStore {
    fn drop(&mut self) {
        for thumbprint in &self.my {
            remove_certificate("My", thumbprint);
        }
        for thumbprint in &self.trusted_people {
            remove_certificate("TrustedPeople", thumbprint);
        }
    }
}

fn remove_certificate(store: &str, thumbprint: &str) {
    if store == "My" {
        let _ = Command::new("certutil.exe")
            .args(["-user", "-delstore", "My", thumbprint])
            .output();
        return;
    }
    let _ = Command::new("pwsh.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            r#"
$store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
    $env:RSL_CERT_STORE,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$matches = $store.Certificates.Find(
    [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
    $env:RSL_CERT_THUMBPRINT,
    $false)
foreach ($cert in $matches) { $store.Remove($cert) }
$store.Close()
"#,
        ])
        .env("RSL_CERT_STORE", store)
        .env("RSL_CERT_THUMBPRINT", thumbprint)
        .status();
}

fn run_powershell(script: &str, environment: &[(&str, &std::ffi::OsStr)]) {
    let mut command = Command::new("pwsh.exe");
    command.args(["-NoProfile", "-NonInteractive", "-Command", script]);
    for (name, value) in environment {
        command.env(name, value);
    }
    let output = command
        .output()
        .expect("run PowerShell certificate workflow");
    assert!(
        output.status.success(),
        "certificate workflow failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn configure_oracle(
    command: &mut Command,
    local: &Leaf,
    accepted_b: Option<&Leaf>,
    validate_chain: bool,
) {
    command
        .env("RSL_TLS_STORE_SCOPE", "CurrentUser")
        .env("RSL_TLS_THUMBPRINT_A", local.thumbprint().to_string())
        .env(
            "RSL_TLS_VALIDATE_CHAIN",
            if validate_chain { "yes" } else { "no" },
        )
        .env("RSL_TLS_CHECK_REVOCATION", "no")
        .env("RSL_TLS_WHITELIST", "yes");
    if let Some(peer) = accepted_b {
        command.env("RSL_TLS_THUMBPRINT_B", peer.thumbprint().to_string());
    } else {
        command.env_remove("RSL_TLS_THUMBPRINT_B");
    }
}

pub fn configure_subject(command: &mut Command, slot: &str, subject: &str, parent: &Ca) {
    command.env(format!("RSL_TLS_SUBJECT_{slot}"), subject).env(
        format!("RSL_TLS_PARENT_{slot}"),
        parent.thumbprint().to_string(),
    );
}
