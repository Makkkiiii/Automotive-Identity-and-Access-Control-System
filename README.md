<p align="center">
  <img width="100%" src="https://capsule-render.vercel.app/api?type=waving&color=0:1b171c,100:d3869b&height=180&section=header&text=AIACS&fontColor=e8d8d4&fontSize=48&animation=fadeIn" />
</p>

<h2 align="center">Automotive Identity and Access Control System</h2>

<p align="center">
  A Rust-based vehicle access provisioning prototype for digital key fob registration, certificate-based authentication, secure session establishment, adversarial validation, audit reporting, and cloud-backed provisioning metadata storage.
</p>

<p align="center">
  <img src="https://skillicons.dev/icons?i=rust,postgres,github" />
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
  <img src="https://img.shields.io/badge/Cloud_Metadata-Sync_Active-00A36C?style=flat-square" />
  <img src="https://img.shields.io/badge/License-MIT-2563EB?style=flat-square" />
</p>

## Technical Snapshot

| Category           | Implementation            |
| ------------------ | ------------------------- |
| Language           | Rust                      |
| GUI                | Iced                      |
| Database           | Neon PostgreSQL           |
| Digital Signature  | Ed25519                   |
| Key Exchange       | X25519                    |
| Session Protection | HKDF-SHA256 + AES-256-GCM |
| Trust Model        | Certificate-based PKI     |
| Fingerprints       | SHA-256 previews          |

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
15. [Docker Support](#docker-support)
16. [Testing and Validation](#testing-and-validation)
17. [Runtime Generated Files](#runtime-generated-files)
18. [Provisioning Audit Report](#provisioning-audit-report)
19. [Screenshots](#screenshots)
20. [Security Design Notes](#security-design-notes)
21. [Academic Scope and Limitations](#academic-scope-and-limitations)
22. [License](#license)

---

## Overview

AIACS demonstrates a complete digital vehicle access provisioning path:

- A technician selects a customer, vehicle, and digital key fob.
- The system initializes a vehicle trust root and certificate authority.
- A key fob identity is registered and issued a CA-signed access certificate.
- A challenge-response authentication flow verifies certificate trust, identity binding, signature validity, freshness, and replay resistance.
- A secure session is established using X25519, HKDF-SHA256, and AES-256-GCM.
- Safe provisioning metadata can be synced to a Neon PostgreSQL database.
- Audit logs and reports expose protocol state without revealing sensitive key material.

AIACS is an academic prototype. It is designed to demonstrate protocol structure, software-side security controls, redaction practices, and validation strategy. It is not a production automotive access system.

---

## Key Features

| Area                  | Capability                                                                             |
| --------------------- | -------------------------------------------------------------------------------------- |
| Vehicle provisioning  | Dealer/technician-side flow for customer, vehicle, and digital key fob setup           |
| Certificate authority | Root trust initialization and CA-signed key fob certificate issuance                   |
| Authentication        | Ed25519 challenge-response authentication with PKI validation                          |
| Replay protection     | Nonce freshness, nonce reuse detection, and timestamp validation                       |
| Secure session        | X25519 key agreement, HKDF-SHA256 derivation, and AES-256-GCM authenticated encryption |
| Access decisions      | Structured grant/reject decisions with displayable denial reasons                      |
| Diagnostics           | Separate adversarial validation tool for controlled protocol testing                   |
| Audit reporting       | Human-readable provisioning report with redacted secrets                               |
| Cloud metadata        | Neon PostgreSQL schema creation, hydration, and safe selected-context metadata sync     |
| Encrypted recovery    | AES-256-GCM encrypted key backup metadata and local-only recovery evidence             |
| Attacker artifacts    | Report-friendly No-AIACS and protected attack evidence folders                         |
| Docker packaging      | Reproducible build/test/diagnostics container support                                  |
| Secret handling       | Public debug/log/report output redacts private keys and session secrets                |

---

## Project Structure

AIACS is organized around a GUI-safe controller facade and backend modules for cryptographic provisioning, authentication, secure sessions, diagnostics, cloud metadata storage, and local evidence generation.

| Path                          | Purpose                                                                                   |
| ----------------------------- | ----------------------------------------------------------------------------------------- |
| `Cargo.toml`                  | Rust package manifest and dependency configuration                                        |
| `Cargo.lock`                  | Locked dependency versions for reproducible application builds                             |
| `Dockerfile`                  | Multi-stage Docker build for reproducible build/test/diagnostics support                  |
| `.dockerignore`               | Excludes local secrets and generated artifacts from Docker build context                   |
| `.env.example`                | Safe placeholder environment file                                                         |
| `README.md`                   | Project documentation                                                                     |
| `LICENSE`                     | MIT license                                                                               |
| `assets/icons/`               | Local SVG icons used by the Iced GUI                                                      |
| `Screenshots/`                | GUI and Neon screenshots for the final report                                             |
| `src/main.rs`                 | Iced desktop GUI presentation layer; calls `AppController` only                           |
| `src/lib.rs`                  | Library module exports                                                                    |
| `src/app_controller/mod.rs`   | Main application facade for GUI actions, provisioning, diagnostics, reports, and cloud    |
| `src/access/mod.rs`           | Access grant/reject decision logic                                                        |
| `src/attacks/mod.rs`          | Core adversarial validation scenarios                                                     |
| `src/auth/mod.rs`             | Certificate, identity, signature, freshness, and replay validation                        |
| `src/ca/mod.rs`               | Certificate authority initialization, issuance, validation, and persistence               |
| `src/cloud_storage/mod.rs`    | Neon/PostgreSQL schema setup, migrations, metadata sync, and safe cloud records           |
| `src/crypto/mod.rs`           | Ed25519, AES-256-GCM, SHA-256, nonce, and key helper functions                            |
| `src/keyfob/mod.rs`           | Digital key fob identity, key generation, challenge signing, and certificate association  |
| `src/session/mod.rs`          | X25519, HKDF-SHA256, AES-256-GCM session establishment and validation                     |
| `src/vehicle/mod.rs`          | Vehicle nonce generation, freshness, replay tracking, and context helpers                 |
| `src/bin/aiacs_diagnostics.rs`| Separate diagnostics executable                                                           |
| `certs/`                      | Local certificate artifacts generated by the prototype                                    |
| `keys/`                       | Local prototype key files; sensitive and not for sharing                                  |
| `logs/`                       | GUI logs, protocol trace, and exported provisioning report                                |
| `attacker_artifacts/`         | No-AIACS clone evidence and protected encrypted `.enc` attacker artifacts                 |
| `diagnostic_results/`         | Local diagnostic evidence JSON files                                                      |
| `recovery_artifacts/`         | Local encrypted/decrypted key recovery evidence files                                     |
| `target/`                     | Cargo build output; not part of source submission                                         |

Generated runtime folders may contain sensitive or report-only artifacts. Review `.gitignore` and `.dockerignore` before sharing builds or screenshots.

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
    FILES["Local Evidence Artifacts"]
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
    CTRL --> FILES
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
| `src/cloud_storage/mod.rs`     | Neon/PostgreSQL connection, schema migrations, hydration, and safe metadata sync                   |
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
    PROVISIONING_SESSIONS ||--o{ DIAGNOSTIC_RESULTS : validates
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
| Finalize                    | Finalize & Export Report, sync safe audit metadata                           |

---

## Demo / Fallback Records

AIACS keeps stable demonstration records for tests, documentation, and controlled local fallback. The GUI does **not** auto-select these records on startup; operators select or create customer, vehicle, and key fob records before provisioning.

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

These records are examples only. Normal provisioning, diagnostics, cloud sync, and artifact paths use the active selected customer, vehicle, and key fob context.

---

## GUI Pages

The desktop GUI is organized as a multi-page vehicle provisioning console.

| Page               | Purpose                                                                                                                                           |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| Dashboard          | High-level overview of active customer, selected vehicle, registered key fob, and provisioning status                                             |
| Customers          | Cloud-backed customer records with manual owner, email, and phone input; customer IDs are generated automatically                                 |
| Vehicles           | Cloud-backed vehicle records with manual display name, make, model, year, VIN, and registration input; vehicle IDs are generated automatically    |
| Key Fobs           | Cloud-backed key fob records with manual fob label input, public fingerprint, and redacted private key state; fob IDs are generated automatically |
| Provisioning       | Primary guided workflow for normal vehicle access provisioning                                                                                    |
| Protocol Artifacts | Selectable protocol artifacts such as challenge message, authentication proof, certificate details, session summary, and access decision          |
| Credential Storage | Safe credential paths, fingerprints, storage mode, and `[REDACTED]` private key values                                                            |
| Logs / Report      | Event log, protocol trace, export report action, and clear log action                                                                             |
| Diagnostics        | Selected-context attack validation dashboard with isolated controls, latest result, evidence paths, and cloud sync status                         |

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

Diagnostics are isolated from normal vehicle access provisioning. The GUI exposes a dedicated Diagnostics page, and the project also includes the separate `aiacs_diagnostics` binary for controlled validation runs.

Diagnostics use the active selected customer, vehicle, and key fob context. They must not silently fall back to demo IDs unless those records are explicitly selected.

### Implemented Diagnostic Scenarios

| Diagnostic                         | Purpose                                                                                     |
| ---------------------------------- | ------------------------------------------------------------------------------------------- |
| No-AIACS Clone                     | Compares an insecure plaintext/static signal clone against AIACS-protected rejection         |
| Replay Attack                      | Compares insecure baseline replay success against protected nonce/freshness rejection        |
| Forged Signature                   | Verifies invalid Ed25519 signatures are rejected                                            |
| Fake Certificate                   | Verifies certificates from an untrusted CA are rejected                                      |
| Identity Mismatch                  | Verifies certificate subject and proof subject mismatches are rejected                       |
| Delayed Relay                      | Verifies freshness timeout behavior                                                         |
| Packet Tampering                   | Verifies tampered authentication payloads are rejected                                       |
| Tampered Ciphertext                | Verifies AES-GCM authenticated decryption rejects modified ciphertext                        |
| Wrong Session Key                  | Verifies session key binding rejects incorrect session material                              |
| Wrong Master Key                   | Verifies encrypted key recovery fails safely with an incorrect `AIACS_MASTER_KEY`            |

### No-AIACS Clone Evidence

The No-AIACS Clone diagnostic is a software simulation only. It does not perform real RF capture, radio replay, rolling-code cloning, or vehicle unlocking.

It creates selected-fob evidence under:

```text
attacker_artifacts/<active_fob_id>/
```

Typical files:

```text
insecure_cloned_signal.json
protected_cloned_signal.json
attacker_clone_evidence.json
protected_capture.enc
```

The insecure file intentionally shows a simulated plaintext/static signal to demonstrate why protection is needed. The protected files use redacted metadata or encrypted `.enc` artifacts and never expose private keys, session keys, raw signatures, raw nonces, or raw ciphertext in GUI/report text.

### Diagnostic Cloud Sync

Diagnostic results are synced to Neon in the `diagnostic_results` table with safe selected-context metadata:

- `customer_id`
- `vehicle_id`
- `fob_id`
- `certificate_id`
- `session_id`
- `baseline_result`
- `protected_result`
- `actual_result`
- `security_control_triggered`
- `pass_fail`
- `cloud_sync_status`
- `created_at_nepal_time`

Legacy compatibility columns are also populated where applicable. Cloud sync status is only marked synced when the database write succeeds.

---

## Cloud Database Support

AIACS includes Neon/PostgreSQL support for safe cloud-backed provisioning metadata, startup hydration, selected-context state restoration, diagnostic result sync, and encrypted key backup metadata.

### Tables

| Table                   | Purpose                                                               |
| ----------------------- | --------------------------------------------------------------------- |
| `customers`             | Owner/customer metadata and selected customer records                               |
| `vehicles`              | Vehicle metadata, customer ownership, and provisioning status                       |
| `key_fobs`              | Key fob labels, fingerprints, certificate status, and provisioning status           |
| `certificates`          | Safe certificate metadata including issuer, subject, fingerprint, and status        |
| `encrypted_keys`        | Client-side encrypted private key blobs and safe metadata; never plaintext keys     |
| `provisioning_sessions` | Authentication/session/access status, report path, and selected-context IDs         |
| `audit_logs`            | Safe provisioning workflow audit events with customer/vehicle/fob/session context   |
| `diagnostic_results`    | Safe adversarial validation outcomes, evidence paths, and cloud sync status         |

Cloud rows use canonical `TIMESTAMPTZ` values where appropriate. User-facing GUI, logs, reports, and evidence files use Nepal time strings in the format `YYYY-MM-DD HH:MM:SS NPT`.

Plaintext private keys, session keys, shared secrets, HKDF output, AES keys, raw payloads, raw signatures, raw nonces, and database credentials are never uploaded as plaintext cloud metadata.

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

`AIACS_MASTER_KEY` is used locally for AES-256-GCM encrypted key backup and recovery evidence. Neon stores encrypted blobs and safe metadata only; decryption happens locally.

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

Verify encrypted key backup metadata without exposing encrypted blobs or nonce bytes:

```sql
SELECT
  key_id,
  owner_type,
  owner_id,
  public_key_fingerprint,
  encryption_algorithm,
  key_purpose,
  storage_status,
  created_at
FROM encrypted_keys
ORDER BY created_at DESC;
```

Verify provisioning session metadata:

```sql
SELECT
  session_id,
  customer_id,
  vehicle_id,
  fob_id,
  certificate_id,
  auth_status,
  auth_result,
  session_status,
  session_algorithm,
  session_method,
  access_decision,
  provisioning_status,
  report_path,
  updated_at
FROM provisioning_sessions
ORDER BY updated_at DESC;
```

Verify synced audit log metadata without exposing secrets:

```sql
SELECT
  log_id,
  event_tag,
  customer_id,
  vehicle_id,
  fob_id,
  session_id,
  certificate_id,
  message,
  severity,
  actor,
  created_at
FROM audit_logs
ORDER BY created_at DESC;
```

Verify synced diagnostic result metadata without exposing secrets:

```sql
SELECT
  diagnostic_id,
  attack_name,
  customer_id,
  vehicle_id,
  fob_id,
  certificate_id,
  session_id,
  baseline_result,
  protected_result,
  actual_result,
  security_control_triggered,
  pass_fail,
  denial_reason,
  cloud_sync_status,
  evidence_file_path,
  created_at_nepal_time
FROM diagnostic_results
ORDER BY created_at DESC;
```

Optional controlled fallback/demo records may exist for tests and local fallback. They are not auto-selected by the GUI:

| Table                | Expected Record                                          |
| -------------------- | -------------------------------------------------------- |
| `customers`          | `CUST-0001` / `XYZ`                                      |
| `vehicles`           | `VEH-0001` / `Nissan `                                   |
| `key_fobs`           | `FOB-0001` / `Primary Key Fob`                           |
| `audit_logs`         | `AUDIT-0001` through `AUDIT-0007`                        |
| `diagnostic_results` | `DIAG-REPLAY-0001` through `DIAG-WRONG-SESSION-KEY-0001` |

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

Run the GUI explicitly:

```bash
cargo run --bin aiacs
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
3. Open Customers, Vehicles, and Key Fobs to manually create, load, and select cloud-backed records.
4. Open Provisioning.
5. Connect the vehicle, register the key fob, initialize vehicle trust, issue the certificate, generate the challenge, sign the canonical payload, verify authentication, activate the secure session, and finalize/export the report.
6. Review Protocol Artifacts and confirm selected-context certificate/session details are loaded.
7. Review Credential Storage and confirm private key values are redacted.
8. Use the encrypted key recovery action only when intentionally producing local recovery evidence.
9. Open Diagnostics and run the No-AIACS Clone or protected attack validations.
10. Review `attacker_artifacts/`, `diagnostic_results/`, and Neon `diagnostic_results` rows for report evidence.

Selected cloud metadata records are now bound to the cryptographic provisioning flow: a selected/custom key fob uses its own Ed25519 keypair, receives a CA-issued certificate for that fob ID, signs the vehicle challenge as that fob, and syncs only safe certificate/session/audit metadata. Plaintext private keys and session secrets are not uploaded.

---

## Docker Support

Docker support is provided for reproducible build, test, clippy, diagnostics execution, and dependency consistency. The native host binary is still recommended for the full Iced desktop GUI demo. GUI execution inside Docker is optional and depends on host display forwarding, especially on Linux X11/Wayland.

Secrets are not baked into the image. Provide `DATABASE_URL` and `AIACS_MASTER_KEY` at runtime only, and persist generated artifacts with volume mounts when needed.

Build the image:

```bash
docker build -t aiacs:final .
```

Run diagnostics/headless:

```bash
docker run --rm \
  -e DATABASE_URL="your_neon_database_url" \
  -e AIACS_MASTER_KEY="your_local_master_key" \
  -v "$PWD/attacker_artifacts:/app/attacker_artifacts" \
  -v "$PWD/diagnostic_results:/app/diagnostic_results" \
  -v "$PWD/recovery_artifacts:/app/recovery_artifacts" \
  aiacs:final
```

Run the GUI on Linux X11, optional:

```bash
xhost +local:docker
docker run --rm -it \
  -e DISPLAY=$DISPLAY \
  -e DATABASE_URL="your_neon_database_url" \
  -e AIACS_MASTER_KEY="your_local_master_key" \
  -v /tmp/.X11-unix:/tmp/.X11-unix \
  -v "$PWD/attacker_artifacts:/app/attacker_artifacts" \
  -v "$PWD/diagnostic_results:/app/diagnostic_results" \
  -v "$PWD/recovery_artifacts:/app/recovery_artifacts" \
  aiacs:final aiacs
```

On Windows, GUI execution through Docker may require WSLg or an external X server. For submission, Docker is best used to validate reproducible build/test/diagnostics support, while the GUI demo is best performed natively.

---

## Testing and Validation

Run library tests:

```bash
cargo test --lib
```

Run full local validation:

```bash
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --lib
cargo test --bins
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
| Library tests           | 280 passing tests                            |
| Binary/GUI tests        | 31 passing tests                             |
| Diagnostics             | Separate from main provisioning console      |
| Cloud tests             | Normal tests do not require a live database  |
| Live cloud verification | Available behind `AIACS_RUN_LIVE_DB_TESTS=1` |
| Secret redaction        | Covered by Debug/log/report tests            |
| Docker                  | Dockerfile and `.dockerignore` provided for reproducible build/test/diagnostics support |

---

## Runtime Generated Files

The application may generate local runtime files:

```text
keys/
certs/
logs/
attacker_artifacts/
diagnostic_results/
recovery_artifacts/
report_exports/
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
attacker_artifacts/<fob_id>/attacker_clone_evidence.json
attacker_artifacts/<fob_id>/protected_capture.enc
diagnostic_results/<fob_id>/replay_attack.json
recovery_artifacts/<fob_id>/encrypted_fob_key_local.bin
recovery_artifacts/<fob_id>/encrypted_fob_key_cloud.bin
recovery_artifacts/<fob_id>/recovery_evidence.json
```

Private material may exist in local runtime storage for the prototype, especially under `keys/` and the explicitly generated decrypted recovery file. GUI output, logs, reports, report-safe evidence, and Debug formatting must redact sensitive values.

Recovery artifacts are local-only unless deliberately copied for review. `recovery_evidence.json` is report-safe by design; `decrypted_fob_key_recovered.json` is sensitive and must not be shared or committed.

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

Project screenshots are available in [Screenshots](Screenshots/).

---

## Security Design Notes

AIACS treats the following values as sensitive. They must never be displayed, logged, printed, committed, or uploaded as plaintext:

- CA private key
- Key fob private key
- X25519 private key
- Shared secret
- AES session key
- Raw session key bytes
- HKDF output
- Raw authentication payloads
- Raw signatures
- Raw nonce bytes
- Raw ciphertext
- Encrypted key blob bytes in GUI/report output
- Encryption nonce bytes in GUI/report output
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
- Nonce fingerprints or redacted nonce markers
- Encrypted key backup status and fingerprints
- Encrypted backup metadata
- Diagnostic evidence paths
- Attacker artifact paths
- Nepal time display strings
- `[REDACTED]` markers

`[REDACTED]` means sensitive material may exist internally for protocol operation, but it is intentionally hidden from GUI output, logs, reports, Debug formatting, README examples, and cloud metadata sync.

Neon may store `encrypted_key_blob` and `encryption_nonce` in the `encrypted_keys` table for encrypted backup. These bytes are not displayed in GUI/report text and are not decrypted by the cloud. Recovery is local-only and requires the operator's local `AIACS_MASTER_KEY`.

---

## Academic Scope and Limitations

AIACS demonstrates software-side protocol design and validation for automotive digital access provisioning. It is appropriate for academic demonstration, prototype evaluation, and security workflow discussion.

AIACS does not claim:

- Production automotive readiness
- Hardware-backed secure element protection
- TPM-backed key isolation
- Real RF distance bounding
- Real RF relay attack elimination
- CAN bus integration
- Compliance with an automotive OEM security standard
- Safety certification
- Complete cloud production hardening

Relay mitigation in this prototype is limited to software-level nonce freshness, replay detection, and timestamp validation. It does not prove physical proximity or replace automotive-grade RF distance-bounding hardware.

The project is intentionally scoped as a prototype. Its value is in showing protocol composition, safe GUI/backend boundaries, strict certificate validation, adversarial testing, audit reporting, and secret redaction discipline.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
