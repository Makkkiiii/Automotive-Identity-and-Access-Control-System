<p align="center">
  <img width="100%" src="https://capsule-render.vercel.app/api?type=waving&color=0:1b171c,100:d3869b&height=180&section=header&text=AIACS&fontColor=e8d8d4&fontSize=48&animation=fadeIn" />
</p>

<h2 align="center">Automotive Identity and Access Control System</h2>

<p align="center">
  A Rust-based vehicle access provisioning prototype for digital key fob registration, certificate-based authentication, secure session establishment, adversarial validation, audit reporting, and cloud-backed provisioning metadata storage.
</p>

<p align="center">
  <img src="https://skillicons.dev/icons?i=rust" />
</p>

<p align="center"><strong>Core Stack</strong></p>
<p align="center">
  <img src="https://img.shields.io/badge/Rust-B7410E?style=flat-square&logo=rust&logoColor=white" />
  <img src="https://img.shields.io/badge/Iced_GUI-7DA9D8?style=flat-square&logo=rust&logoColor=white" />
  <img src="https://img.shields.io/badge/PostgreSQL-316192?style=flat-square&logo=postgresql&logoColor=white" />
  <img src="https://img.shields.io/badge/Neon_Cloud-00E599?style=flat-square&logo=neon&logoColor=black" />
</p>

<p align="center"><strong>Cryptography</strong></p>
<p align="center">
  <img src="https://img.shields.io/badge/Ed25519-6D28D9?style=flat-square" />
  <img src="https://img.shields.io/badge/X25519-7C3AED?style=flat-square" />
  <img src="https://img.shields.io/badge/AES--GCM-0F766E?style=flat-square" />
  <img src="https://img.shields.io/badge/HKDF--SHA256-14B8A6?style=flat-square" />
  <img src="https://img.shields.io/badge/PKI_Certificates-8B5CF6?style=flat-square" />
</p>

<p align="center"><strong>Project Type</strong></p>
<p align="center">
  <img src="https://img.shields.io/badge/Vehicle_Access-Provisioning-D3869B?style=flat-square" />
  <img src="https://img.shields.io/badge/Secure_Session-Establishment-0EA5E9?style=flat-square" />
  <img src="https://img.shields.io/badge/Adversarial-Validation-E06C75?style=flat-square" />
  <img src="https://img.shields.io/badge/Audit-Reporting-A78BFA?style=flat-square" />
</p>

<p align="center"><strong>Status</strong></p>
<p align="center">
  <img src="https://img.shields.io/badge/Local_Validation-Passing-1F7A3D?style=flat-square" />
  <img src="https://img.shields.io/badge/Cloud_Metadata-Sync_Ready-00A36C?style=flat-square" />
  <img src="https://img.shields.io/badge/License-MIT-2563EB?style=flat-square" />
</p>

## Technical Snapshot

| Category           | Implementation        |
| ------------------ | --------------------- |
| Language           | Rust                  |
| GUI                | Iced                  |
| Database           | Neon PostgreSQL       |
| Digital Signature  | Ed25519               |
| Key Exchange       | X25519                |
| Session Protection | HKDF-SHA256 + AES-GCM |
| Trust Model        | Certificate-based PKI |

The main desktop application is the **Vehicle Access Provisioning Console**. Security diagnostics are kept separate in `src/bin/aiacs_diagnostics.rs`.

---

## Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Project Structure](#project-structure)
4. [System Architecture](#system-architecture)
5. [Workflow Illustration](#workflow-illustration)
6. [Demo Records](#demo-records)
7. [GUI Pages](#gui-pages)
8. [Cryptographic Protocol Flow](#cryptographic-protocol-flow)
9. [Diagnostics and Attack Validation](#diagnostics-and-attack-validation)
10. [Cloud Database Support](#cloud-database-support)
11. [Environment Configuration](#environment-configuration)
12. [Neon PostgreSQL Setup](#neon-postgresql-setup)
13. [Installation](#installation)
14. [Running the Application](#running-the-application)
15. [Testing and Validation](#testing-and-validation)
16. [Runtime Generated Files](#runtime-generated-files)
17. [Provisioning Audit Report](#provisioning-audit-report)
18. [Screenshots](#screenshots)
19. [Security Design Notes](#security-design-notes)
20. [Development Status](#development-status)
21. [Academic Scope and Limitations](#academic-scope-and-limitations)
22. [License](#license)

---

## Overview

AIACS demonstrates a complete digital vehicle access provisioning path:

- A technician selects a customer, vehicle, and digital key fob.
- The system initializes a vehicle trust root and certificate authority.
- A key fob identity is registered and issued a CA-signed access certificate.
- A challenge-response authentication flow verifies certificate trust, identity binding, signature validity, freshness, and replay resistance.
- A secure session is established using X25519, HKDF-SHA256, and AES-GCM.
- Safe provisioning metadata can be synced to a Neon PostgreSQL database.
- Audit logs and reports expose protocol state without revealing sensitive key material.

AIACS is an academic prototype. It is designed to demonstrate protocol structure, software-side security controls, redaction practices, and validation strategy. It is not a production automotive access system.

---

## Key Features

| Area                  | Capability                                                                         |
| --------------------- | ---------------------------------------------------------------------------------- |
| Vehicle provisioning  | Dealer/technician-side flow for customer, vehicle, and digital key fob setup       |
| Certificate authority | Root trust initialization and CA-signed key fob certificate issuance               |
| Authentication        | Ed25519 challenge-response authentication with PKI validation                      |
| Replay protection     | Nonce freshness, nonce reuse detection, and timestamp validation                   |
| Secure session        | X25519 key agreement, HKDF-SHA256 derivation, and AES-GCM authenticated encryption |
| Access decisions      | Structured grant/reject decisions with displayable denial reasons                  |
| Diagnostics           | Separate adversarial validation tool for controlled protocol testing               |
| Audit reporting       | Human-readable provisioning report with redacted secrets                           |
| Cloud metadata        | Neon PostgreSQL schema creation and safe customer/vehicle/key fob metadata sync    |
| Secret handling       | Public debug/log/report output redacts private keys and session secrets            |

---

## Project Structure

AIACS is organized around a GUI-safe controller facade and backend modules for cryptographic provisioning, authentication, session handling, diagnostics, and cloud metadata storage.

<div>
  <p><img width="17" src="https://api.iconify.design/lucide/folder-root.svg?color=%23d3869b" alt="root" /> <strong><code>Cryptography/</code></strong></p>
  <ul>
    <li><img width="15" src="https://api.iconify.design/lucide/file-cog.svg?color=%23e6c384" alt="manifest" /> <code>Cargo.toml</code></li>
    <li><img width="15" src="https://api.iconify.design/lucide/file-lock-2.svg?color=%23e6c384" alt="lockfile" /> <code>Cargo.lock</code></li>
    <li><img width="15" src="https://api.iconify.design/lucide/file-text.svg?color=%237da9d8" alt="readme" /> <code>README.md</code></li>
    <li><img width="15" src="https://api.iconify.design/lucide/scale.svg?color=%237da9d8" alt="license" /> <code>LICENSE</code></li>
    <li><img width="15" src="https://api.iconify.design/lucide/file-key-2.svg?color=%238f7f82" alt="env example" /> <code>.env.example</code></li>
    <li>
      <img width="15" src="https://api.iconify.design/lucide/folder.svg?color=%23d3869b" alt="folder" /> <code>assets/</code>
      <ul>
        <li><img width="15" src="https://api.iconify.design/lucide/image.svg?color=%23d3869b" alt="icons" /> <code>icons/</code></li>
      </ul>
    </li>
    <li>
      <img width="15" src="https://api.iconify.design/lucide/folder-code.svg?color=%237da9d8" alt="source" /> <code>src/</code>
      <ul>
        <li><img width="15" src="https://api.iconify.design/lucide/monitor.svg?color=%237da9d8" alt="gui" /> <code>main.rs</code></li>
        <li><img width="15" src="https://api.iconify.design/lucide/library.svg?color=%23a7d28d" alt="library" /> <code>lib.rs</code></li>
        <li><img width="15" src="https://api.iconify.design/lucide/route.svg?color=%23e6c384" alt="controller" /> <code>app_controller/</code></li>
        <li><img width="15" src="https://api.iconify.design/lucide/badge-check.svg?color=%23a7d28d" alt="access" /> <code>access/</code></li>
        <li><img width="15" src="https://api.iconify.design/lucide/radar.svg?color=%23e06c75" alt="attacks" /> <code>attacks/</code></li>
        <li><img width="15" src="https://api.iconify.design/lucide/fingerprint.svg?color=%23d3869b" alt="auth" /> <code>auth/</code></li>
        <li><img width="15" src="https://api.iconify.design/lucide/shield-check.svg?color=%23a7d28d" alt="certificate authority" /> <code>ca/</code></li>
        <li><img width="15" src="https://api.iconify.design/lucide/database.svg?color=%2300e599" alt="cloud storage" /> <code>cloud_storage/</code></li>
        <li><img width="15" src="https://api.iconify.design/lucide/key-round.svg?color=%23d3869b" alt="crypto" /> <code>crypto/</code></li>
        <li><img width="15" src="https://api.iconify.design/lucide/key-square.svg?color=%23d3869b" alt="keyfob" /> <code>keyfob/</code></li>
        <li><img width="15" src="https://api.iconify.design/lucide/lock.svg?color=%23a7d28d" alt="session" /> <code>session/</code></li>
        <li><img width="15" src="https://api.iconify.design/lucide/car.svg?color=%237da9d8" alt="vehicle" /> <code>vehicle/</code></li>
        <li>
          <img width="15" src="https://api.iconify.design/lucide/folder-cog.svg?color=%23e6c384" alt="binary" /> <code>bin/</code>
          <ul>
            <li><img width="15" src="https://api.iconify.design/lucide/terminal.svg?color=%23e6c384" alt="diagnostics binary" /> <code>aiacs_diagnostics.rs</code></li>
          </ul>
        </li>
      </ul>
    </li>
    <li><img width="15" src="https://api.iconify.design/lucide/folder-check.svg?color=%23a7d28d" alt="certificates" /> <code>certs/</code></li>
    <li><img width="15" src="https://api.iconify.design/lucide/folder-key.svg?color=%23d3869b" alt="keys" /> <code>keys/</code></li>
    <li><img width="15" src="https://api.iconify.design/lucide/folder-clock.svg?color=%237da9d8" alt="logs" /> <code>logs/</code></li>
    <li><img width="15" src="https://api.iconify.design/lucide/folder-git-2.svg?color=%238f7f82" alt="target" /> <code>target/</code></li>
  </ul>
</div>

---

## System Architecture

```mermaid
flowchart LR
    GUI["Vehicle Access Provisioning Console"]
    CTRL["AppController Safe Facade"]
    CA["Certificate Authority"]
    FOB["Digital Key Fob"]
    VEH["Vehicle Nonce Manager"]
    AUTH["Authentication Engine"]
    SESSION["Session Module"]
    ACCESS["Access Decision Engine"]
    DB["Neon PostgreSQL Cloud DB"]
    DIAG["Separate Diagnostics Tool"]

    GUI --> CTRL
    DIAG --> CTRL
    CTRL --> CA
    CTRL --> FOB
    CTRL --> VEH
    CTRL --> AUTH
    CTRL --> SESSION
    CTRL --> ACCESS
    CTRL --> DB
```

The GUI calls `AppController` only. `AppController` is the safe application facade that coordinates backend modules and prevents GUI code from duplicating cryptographic, authentication, session, access, or diagnostics logic.

### Module Map

| Module                         | Purpose                                                                                            |
| ------------------------------ | -------------------------------------------------------------------------------------------------- |
| `src/app_controller/mod.rs`    | GUI-safe facade for provisioning, diagnostics launch, reports, logs, and cloud metadata operations |
| `src/ca/mod.rs`                | Certificate authority initialization, certificate issuance, and chain validation                   |
| `src/crypto/mod.rs`            | Ed25519, AES-GCM, hashing, nonce generation, and key helpers                                       |
| `src/keyfob/mod.rs`            | Digital key fob identity, key generation, challenge signing, certificate storage                   |
| `src/vehicle/mod.rs`           | Vehicle nonce generation, replay tracking, and freshness checks                                    |
| `src/auth/mod.rs`              | Authentication proof validation and `AuthResult` generation                                        |
| `src/session/mod.rs`           | X25519, HKDF-SHA256, AES-GCM session establishment and validation                                  |
| `src/access/mod.rs`            | Access grant/reject decision evaluation                                                            |
| `src/attacks/mod.rs`           | Adversarial validation scenarios                                                                   |
| `src/cloud_storage/mod.rs`     | Neon/PostgreSQL connection, schema creation, and safe metadata sync                                |
| `src/bin/aiacs_diagnostics.rs` | Separate diagnostics executable                                                                    |

### Cloud Data Model

```mermaid
erDiagram
    CUSTOMERS ||--o{ VEHICLES : owns
    VEHICLES ||--o{ KEY_FOBS : provisions
    KEY_FOBS ||--o{ CERTIFICATES : receives
    KEY_FOBS ||--o{ ENCRYPTED_KEYS : stores
    VEHICLES ||--o{ PROVISIONING_SESSIONS : records
    PROVISIONING_SESSIONS ||--o{ AUDIT_LOGS : produces
```

---

## Workflow Illustration

```mermaid
sequenceDiagram
    participant Operator
    participant GUI as AIACS Console
    participant CA as Certificate Authority
    participant Fob as Digital Key Fob
    participant Vehicle as Vehicle Module
    participant Auth as Authentication Engine
    participant Session as Session Module
    participant DB as Neon PostgreSQL

    Operator->>GUI: Select customer, vehicle, and key fob
    Operator->>GUI: Connect vehicle
    GUI->>Vehicle: Generate vehicle provisioning context
    Operator->>GUI: Register key fob
    GUI->>Fob: Generate Ed25519 keypair
    Operator->>GUI: Initialize vehicle trust
    GUI->>CA: Generate CA root keypair
    Operator->>GUI: Issue access certificate
    CA->>Fob: Issue CA-signed certificate
    Operator->>GUI: Verify authentication
    Vehicle->>Fob: Nonce challenge
    Fob->>Auth: Signed canonical payload + certificate
    Auth->>Auth: Verify certificate, subject binding, signature, freshness, replay protection
    Auth->>GUI: Authentication successful
    Operator->>GUI: Activate secure session
    GUI->>Session: X25519 + HKDF-SHA256 + AES-GCM
    GUI->>DB: Sync safe metadata
```

### Provisioning Stages

| Stage                       | Actions                                                                      |
| --------------------------- | ---------------------------------------------------------------------------- |
| Vehicle Connection          | Connect vehicle                                                              |
| Key Fob Setup               | Detect key fob, register key fob                                             |
| Certificate Provisioning    | Initialize vehicle trust, issue access certificate, view certificate details |
| Authentication Verification | Generate challenge, sign canonical payload, verify authentication            |
| Secure Session              | Activate secure session                                                      |
| Finalize                    | Export provisioning report, sync safe metadata                               |

---

## Demo Records

The GUI uses stable demonstration records suitable for academic presentation and repeatable testing.

### Customer

| Field         | Value                |
| ------------- | -------------------- |
| `customer_id` | `CUST-0001`          |
| `owner_name`  | `XYZ `               |
| `email`       | `XYZZ.m@example.com` |

### Vehicle

| Field                  | Value      |
| ---------------------- | ---------- |
| `vehicle_id`           | `VEH-0001` |
| `vehicle_display_name` | `Nissan`   |
| `make`                 | `Nissan`   |
| `model`                | `Magnite`  |
| `year`                 | `2023`     |

### Key Fob

| Field       | Value             |
| ----------- | ----------------- |
| `fob_id`    | `FOB-0001`        |
| `fob_label` | `Primary Key Fob` |

### Session

| Field        | Value          |
| ------------ | -------------- |
| `session_id` | `SESSION-0001` |

The README uses only the current generic demo records shown above.

---

## GUI Pages

The desktop GUI is organized as a multi-page vehicle provisioning console.

| Page               | Purpose                                                                                                                                  |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------- |
| Dashboard          | High-level overview of active customer, selected vehicle, registered key fob, and provisioning status                                    |
| Customers          | Demo customer/owner details and GUI-only customer actions                                                                                |
| Vehicles           | Selected vehicle details, technical ID, make/model/year, and owner association                                                           |
| Key Fobs           | Digital key fob details, certificate state, public fingerprint, and redacted private key state                                           |
| Provisioning       | Primary staged workflow for normal vehicle access provisioning                                                                           |
| Protocol Artifacts | Selectable protocol artifacts such as challenge message, authentication proof, certificate details, session summary, and access decision |
| Credential Storage | Safe credential paths, fingerprints, storage mode, and `[REDACTED]` private key values                                                   |
| Logs / Report      | Event log, protocol trace, export report action, and clear log action                                                                    |
| Diagnostics        | Launch page for the separate diagnostics tool                                                                                            |
| Cloud Storage      | Neon connection health check and safe metadata sync controls                                                                             |

Diagnostics are not part of the normal provisioning workflow. The main GUI launches diagnostics separately and does not show attack buttons inside the provisioning page.

---

## Cryptographic Protocol Flow

```mermaid
flowchart TD
    A["Vehicle generates nonce challenge"] --> B["Key fob builds canonical payload"]
    B --> C["Key fob signs payload using Ed25519"]
    C --> D["Authentication Engine validates certificate"]
    D --> E["Subject identity binding check"]
    E --> F["Ed25519 signature verification"]
    F --> G["Nonce freshness and replay check"]
    G --> H["Access Decision: Grant or Reject"]
    H --> I["Secure session: X25519 + HKDF + AES-GCM"]
```

### Authentication Checks

| Check                 | Expected Success Condition                                                         |
| --------------------- | ---------------------------------------------------------------------------------- |
| Certificate chain     | The trusted CA returns `Ok(true)` for the key fob certificate                      |
| Certificate validity  | Certificate is within its validity window                                          |
| Subject binding       | Authentication proof subject matches certificate subject                           |
| Signature             | Ed25519 verification succeeds over the canonical payload                           |
| Freshness             | Nonce timestamp is inside the configured freshness window                          |
| Replay protection     | Nonce has not already been used                                                    |
| Session establishment | X25519/HKDF/AES-GCM session material is established without exposing raw key bytes |

Certificate validation is strict: only `Ok(true)` from CA validation is accepted. `Ok(false)` and `Err(_)` are rejected.

---

## Diagnostics and Attack Validation

Diagnostics are run through the separate binary:

```bash
cargo run --bin aiacs_diagnostics
```

| Attack               | Expected Outcome                                                    |
| -------------------- | ------------------------------------------------------------------- |
| Replay Attack        | Rejected because reused nonce is detected                           |
| Forged Signature     | Rejected because Ed25519 verification fails                         |
| Fake Certificate     | Rejected because CA validation fails                                |
| Identity Mismatch    | Rejected because proof subject and certificate subject do not match |
| Delayed Relay        | Rejected because freshness timeout fails                            |
| Packet Tampering     | Rejected because payload/signature binding fails                    |
| Unauthorized Key Fob | Rejected because identity is not authorized                         |
| Tampered Ciphertext  | Rejected because AES-GCM integrity check fails                      |
| Wrong Session Key    | Rejected because session decryption/integrity validation fails      |

The diagnostics tool exercises the real protocol path through `AppController`. It does not bypass the authentication engine or duplicate CA validation logic.

---

## Cloud Database Support

AIACS includes Neon/PostgreSQL support for safe cloud-backed provisioning metadata.

### Tables

| Table                   | Purpose                                                               |
| ----------------------- | --------------------------------------------------------------------- |
| `customers`             | Owner/customer metadata                                               |
| `vehicles`              | Vehicle metadata and provisioning status                              |
| `key_fobs`              | Key fob labels, fingerprints, certificate status, provisioning status |
| `certificates`          | Safe certificate metadata sync                                        |
| `encrypted_keys`        | Client-side encrypted private key blobs, never plaintext private keys |
| `provisioning_sessions` | Safe provisioning session metadata sync                               |
| `audit_logs`            | Safe provisioning workflow audit events                               |
| `diagnostic_results`    | Future diagnostics result records                                     |

### Current Behavior

- Schema can be created automatically.
- Safe customer, vehicle, and key fob metadata can be synced.
- Safe certificate metadata can be synced.
- Safe provisioning session metadata can be synced after secure session activation.
- Safe provisioning workflow audit events can be synced with `[REDACTED]` markers.
- Private key blobs can be encrypted locally before cloud upload.
- Raw private keys are not uploaded.
- Raw session keys, shared secrets, HKDF output, AES keys, and X25519 private keys are not uploaded.
- Certificate JSON and diagnostics are not uploaded in the current metadata phase.
- Cloud Phase 6C adds audit log sync only; diagnostic results remain planned future work.

---

## Environment Configuration

Create a local `.env.local` file for development:

```env
DATABASE_URL=postgresql://USER:PASSWORD@HOST/DATABASE?sslmode=require
AIACS_MASTER_KEY=base64_encoded_32_byte_key
```

Rules:

- `.env.local` is local only.
- Never commit `.env.local`.
- `.env.example` contains placeholders only.
- `DATABASE_URL` comes from Neon.
- `AIACS_MASTER_KEY` is generated by the developer or operator.
- Do not print, log, or paste either value into reports or screenshots.

The project ignore rules should keep local environment files out of version control:

```gitignore
.env
.env.local
.env.*
!.env.example
```

Generate a local 32-byte master key:

```bash
python -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"
```

`AIACS_MASTER_KEY` is reserved for future client-side encryption of confidential key material before cloud upload.

---

## Neon PostgreSQL Setup

1. Create a Neon PostgreSQL project.
2. Copy the project connection string.
3. Add it to `.env.local` as `DATABASE_URL`.
4. Add a locally generated `AIACS_MASTER_KEY`.
5. Run the optional live cloud test only when you intentionally want to connect to Neon.

Git Bash:

```bash
AIACS_RUN_LIVE_DB_TESTS=1 cargo test cloud -- --nocapture
```

PowerShell:

```powershell
$env:AIACS_RUN_LIVE_DB_TESTS="1"
cargo test cloud -- --nocapture
```

Verify created tables in the Neon SQL Editor:

```sql
SELECT table_schema, table_name
FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;
```

Verify safe metadata:

```sql
SELECT * FROM customers;
SELECT * FROM vehicles;
SELECT * FROM key_fobs;
```

Verify synced audit log metadata without exposing secrets:

```sql
SELECT
  log_id,
  session_id,
  event_type,
  severity,
  actor,
  created_at
FROM audit_logs
ORDER BY log_id;
```

Expected demo records:

| Table       | Expected Record                |
| ----------- | ------------------------------ |
| `customers` | `CUST-0001` / `XYZ`            |
| `vehicles`  | `VEH-0001` / `Nissan `         |
| `key_fobs`  | `FOB-0001` / `Primary Key Fob` |
| `audit_logs` | `AUDIT-0001` through `AUDIT-0007` |

---

## Installation

### Prerequisites

- Rust stable toolchain from [rustup.rs](https://rustup.rs)
- Git
- Optional: Neon PostgreSQL account for cloud metadata tests

### Clone and Build

```bash
git clone <repository-url>
cd Cryptography
cargo build
```

Release build:

```bash
cargo build --release
```

Windows PowerShell and Git Bash both work for standard Cargo commands. PowerShell uses `$env:NAME="value"` for temporary environment variables, while Git Bash uses `NAME=value command`.

---

## Running the Application

Start the main GUI:

```bash
cargo run
```

Run the diagnostics tool:

```bash
cargo run --bin aiacs_diagnostics
```

Run the release binary on Windows:

```powershell
.\target\release\aiacs.exe
```

Run the release binary on Linux/macOS:

```bash
./target/release/aiacs
```

### Recommended Demo Flow

1. Open the GUI with `cargo run`.
2. Review the Dashboard page.
3. Open Customers, Vehicles, and Key Fobs to view the selected demo records.
4. Open Provisioning.
5. Complete the staged vehicle access workflow.
6. Review Protocol Artifacts.
7. Review Credential Storage and confirm private key values are redacted.
8. Open Cloud Storage and run safe metadata sync if `.env.local` is configured.
9. Export the provisioning report from Logs / Report.
10. Launch diagnostics separately when testing adversarial validation.

---

## Testing and Validation

Run library tests:

```bash
cargo test --lib
```

Run full local validation:

```bash
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
cargo test --lib
cargo check --all-targets
cargo check --bins
```

Optional live cloud tests:

```bash
AIACS_RUN_LIVE_DB_TESTS=1 cargo test cloud -- --nocapture
```

Current validation status:

| Area                    | Status                                       |
| ----------------------- | -------------------------------------------- |
| Unit tests              | 147+ tests                                   |
| Diagnostics             | Separate from main provisioning console      |
| Cloud tests             | Normal tests do not require a live database  |
| Live cloud verification | Available behind `AIACS_RUN_LIVE_DB_TESTS=1` |
| Secret redaction        | Covered by Debug/log/report tests            |

---

## Runtime Generated Files

The application may generate local runtime files:

```text
keys/
certs/
logs/
```

Examples:

```text
keys/ca_private.json
keys/ca_public.json
keys/fob_FOB-0001_private.json
keys/fob_FOB-0001_public.json
certs/fob_FOB-0001.json
logs/aiacs_gui.log
logs/aiacs_protocol_trace.log
logs/aiacs_provisioning_report.txt
```

Private material may exist in local runtime storage for the prototype, but GUI output, logs, reports, and Debug formatting must redact sensitive values.

---

## Provisioning Audit Report

The exported audit report is designed for demonstration and academic review. It includes:

- Provisioning Summary
- Credential Storage
- Certificate Details
- Authentication Verification
- Secure Session Establishment
- Security Notes
- Protocol Trace
- Diagnostics Summary

All secrets must remain redacted. Reports may include safe metadata, certificate metadata, algorithm names, public fingerprints, timestamps, and `[REDACTED]` markers.

---

## Screenshots

> Yet to be added.

---

## Security Design Notes

AIACS treats the following values as sensitive. They must never be displayed, logged, printed, committed, or uploaded as plaintext:

- CA private key
- Key fob private key
- X25519 private key
- Shared secret
- AES session key
- Raw session key bytes
- `AIACS_MASTER_KEY`
- `DATABASE_URL`
- Neon password

Allowed in GUI, logs, reports, or cloud metadata:

- Customer metadata
- Vehicle metadata
- Key fob metadata
- Public key fingerprints
- Certificate metadata
- Algorithm names
- Key file paths
- Timestamps
- Nonces where safe
- Future encrypted blobs
- `[REDACTED]` markers

`[REDACTED]` means sensitive material may exist internally for protocol operation, but it is intentionally hidden from GUI output, logs, reports, Debug formatting, README examples, and cloud metadata sync.

---

## Academic Scope and Limitations

AIACS demonstrates software-side protocol design and validation for automotive digital access provisioning. It is appropriate for academic demonstration, prototype evaluation, and security workflow discussion.

AIACS does not claim:

- Production automotive readiness
- Hardware-backed secure element protection
- TPM-backed key isolation
- Real RF relay attack elimination
- Compliance with an automotive OEM security standard
- Safety certification
- Complete cloud production hardening

The project is intentionally scoped as a prototype. Its value is in showing protocol composition, safe GUI/backend boundaries, strict certificate validation, adversarial testing, audit reporting, and secret redaction discipline.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
