# AIACS

## Automotive Identity and Access Control System

A Rust-based cryptographic protocol prototype implementing certificate-based challenge-response authentication with adversarial protocol validation.

```
    ┌─────────────────────────────────────────────────────────┐
    │                                                         │
    │         VEHICLE CONTROL MODULE (VCM)                   │
    │                                                         │
    │     Generates nonce challenge → Verifies signature     │
    │     Validates certificate chain → Grants/rejects access│
    │                                                         │
    └──────────────────────┬──────────────────────────────────┘
                           │
                    Ed25519 Challenge
                    (128-bit nonce)
                           │
    ┌──────────────────────▼──────────────────────────────────┐
    │                                                         │
    │      DIGITAL KEY FOB MODULE (DKF)                       │
    │                                                         │
    │     Receives challenge → Signs with private key        │
    │     Returns signature + certificate                    │
    │                                                         │
    └──────────────────────┬──────────────────────────────────┘
                           │
                    Signature Response
                           │
    ┌──────────────────────▼──────────────────────────────────┐
    │                                                         │
    │      AUTHENTICATION ENGINE                              │
    │                                                         │
    │     Verify signature (Ed25519)                         │
    │     Validate certificate chain                         │
    │     Check nonce freshness                              │
    │     Establish AES-GCM session                          │
    │                                                         │
    └──────────────────────┬──────────────────────────────────┘
                           │
                    Access Decision
                           │
            ┌──────────────┴──────────────┐
            │                             │
        GRANTED                       REJECTED
    (AES-GCM session)        (Replay/Forge/Timeout)
```

---

## Project Overview

AIACS is an academic prototype demonstrating:

- **Certificate-Based Authentication** — PKI trust model with root CA, key fob certificates, and trust chain validation
- **Replay Resistance** — Nonce freshness validation and timeout enforcement
- **Protocol-Level Relay Mitigation** — Software timing threshold validation
- **Cryptographic Integrity** — AES-GCM authenticated encryption after successful authentication
- **Adversarial Testing** — Six attack scenarios to validate protocol robustness

### What This Is NOT

- Not a production automotive system
- Not a cloud platform or database-backed service
- Not a hardware TPM implementation
- Not a real RF/relay elimination (software timing only)
- Not a general-purpose login system

### Technology Stack

| Component     | Library       | Version |
| ------------- | ------------- | ------- |
| Language      | Rust          | stable  |
| Signatures    | ed25519-dalek | 2.1     |
| Encryption    | aes-gcm       | 0.10    |
| Randomness    | rand          | 0.8     |
| GUI           | iced          | 0.12    |
| Serialization | serde         | 1.0     |
| Hashing       | sha2          | 0.10    |
| Async         | tokio         | 1.0     |

---

## Architecture

### Core Modules

1. **Certificate Authority (CA)** — `src/ca/mod.rs`
   - Generates root CA keypair (Ed25519)
   - Issues certificates to key fobs
   - Validates certificate chains
   - Manages trust anchors

2. **Cryptographic Engine** — `src/crypto/mod.rs`
   - Ed25519 keypair generation and signing
   - AES-GCM encryption/decryption
   - Random nonce generation
   - SHA-256 hashing

3. **Vehicle Control Module (VCM)** — `src/vehicle/mod.rs`
   - Generates 128-bit nonce challenges
   - Verifies Ed25519 signatures
   - Validates certificate chains
   - Establishes AES-GCM sessions

4. **Digital Key Fob (DKF)** — `src/keyfob/mod.rs`
   - Stores private key securely
   - Signs nonce challenges
   - Returns certificate with signature
   - Participates in encrypted sessions

5. **Authentication Engine** — `src/auth/mod.rs`
   - Orchestrates challenge-response flow
   - Validates certificates
   - Checks nonce freshness (timeout-based)
   - Returns authentication result

6. **Session Validation** — `src/session/mod.rs`
   - Timestamps and freshness checks
   - Timeout enforcement
   - Session state management

7. **Access Decision Engine** — `src/access/mod.rs`
   - Aggregates all validation results
   - Issues grant/reject decisions with reasons
   - Logs access events

8. **Adversarial Validation Engine** — `src/attacks/mod.rs`
   - Simulates replay attacks (reused nonces)
   - Simulates forged signatures
   - Simulates fake certificates
   - Simulates delayed relay attacks
   - Simulates packet tampering
   - Simulates unauthorized identities

---

## GUI Overview

The Iced-based GUI provides 5 main screens:

```
MAIN MENU
├── Certificate Authority
│   ├── Initialize CA (generate root keypair)
│   └── Issue Certificate (to key fobs)
├── Authentication
│   └── Run Legitimate Authentication (VCM + DKF handshake)
├── Attack Simulation
│   ├── Replay Attack (reuse captured nonce)
│   ├── Forged Signature (invalid signature)
│   ├── Fake Certificate (untrusted cert)
│   ├── Delayed Relay (timeout simulation)
│   └── Packet Tampering (modify payload)
└── Session Monitor
    └── View active sessions and logs
```

---

## Installation & Setup

### Prerequisites

- Rust 1.70+ (install from [rustup.rs](https://rustup.rs))

### Clone & Build

```bash
git clone <repository>
cd Cryptography

# Download dependencies and build
cargo build --release

# Executable location
./target/release/aiacs  # Linux/macOS
./target/release/aiacs.exe  # Windows
```

---

## Running the Application

### Start the GUI

```bash
cargo run --release
```

This launches the Iced GUI with the main menu. Navigation is handled through on-screen buttons.

### Workflow Example

1. **Initialize CA**
   - Click "Certificate Authority" > "Initialize CA"
   - Generates root CA keypair (Ed25519)
   - Saves keys to `keys/` directory

2. **Issue Certificate**
   - Click "Certificate Authority" > "Issue Certificate"
   - Creates signed certificate for a key fob
   - Saves certificate to `certs/` directory

3. **Run Legitimate Authentication**
   - Click "Authentication" > "Legitimate Authentication"
   - VCM generates nonce challenge
   - DKF signs nonce and returns certificate
   - VCM verifies signature and certificate
   - Result: ACCESS GRANTED (with AES-GCM session established)

4. **Run Attack Simulations**
   - Click "Attack Simulation" and select attack type
   - Each attack demonstrates proper rejection:

   | Attack                | Expected Outcome                                |
   | --------------------- | ----------------------------------------------- |
   | Replay                | ACCESS REJECTED — Nonce Reuse                   |
   | Forged Signature      | ACCESS REJECTED — Invalid Signature             |
   | Fake Certificate      | ACCESS REJECTED — Certificate Validation Failed |
   | Delayed Relay         | ACCESS REJECTED — Freshness Timeout             |
   | Packet Tampering      | ACCESS REJECTED — Integrity Check Failed        |
   | Unauthorized Identity | ACCESS REJECTED — Unknown Identity              |

---

## Development Structure

```
Cryptography/
├── Cargo.toml                 # Dependencies and metadata
├── README.md                  # This file
├── LICENSE                    # MIT License
├── src/
│   ├── main.rs               # Iced GUI entry point
│   ├── ca/mod.rs             # Certificate Authority implementation
│   ├── crypto/mod.rs         # Cryptographic operations (Ed25519, AES-GCM)
│   ├── auth/mod.rs           # Authentication engine
│   ├── vehicle/mod.rs        # Vehicle Control Module
│   ├── keyfob/mod.rs         # Digital Key Fob
│   ├── session/mod.rs        # Session validation
│   ├── access/mod.rs         # Access decision logic
│   └── attacks/mod.rs        # Adversarial attack simulations
├── certs/                     # Stored certificates (generated at runtime)
├── keys/                      # Stored keys (generated at runtime)
└── logs/                      # Activity logs (generated at runtime)
```

---

## Cryptographic Flow

### Successful Authentication (Step-by-Step Animation)

**Phase 1: Challenge Generation**

```
VCM State:
[Idle] ──▶ [Generating Nonce] ──▶ [Nonce Ready]
         ↓
         Generate: 128-bit random value
         Nonce: 0xa7c3f2e1b4d9...
         Timestamp: 2026-05-24T12:34:56Z
```

**Phase 2: Challenge Transmission**

```
VCM                                    DKF
[Challenge Sent] ──────────────────▶ [Challenge Received]
                                      ↓
                                    Processing...
                                      N = 0xa7c3f2e1b4d9...
```

**Phase 3: Signature Generation**

```
DKF State:
[Processing] ──▶ [Signing] ──▶ [Signature Ready]
              ↓
              Sign(sk_fob, nonce)
              S = 0x3e8b5a2c9d7f...
              Certificate: pk_fob (issued by CA)
```

**Phase 4: Response Transmission**

```
DKF                                    VCM
[Response Ready] ──────────────────▶ [Response Received]
                                      ↓
                                    Validating...
```

**Phase 5: Validation Chain**

```
VCM Validation Pipeline:
├─▶ [Verify Signature]
│   └─ Ed25519(pk_fob, nonce, signature)
│      ✓ Valid
│
├─▶ [Validate Certificate]
│   └─ Check issuer = CA root
│      ✓ Trusted
│
├─▶ [Check Freshness]
│   └─ Now - Timestamp < 5 seconds
│      ✓ Fresh
│
└─▶ [Establish Session]
    └─ Session Key ← SHA256(shared_secret)
       ✓ AES-GCM ready
```

**Phase 6: Access Grant**

```
All Checks Passed:
✓ Signature valid
✓ Certificate trusted
✓ Nonce fresh
✓ Integrity verified

[Validation Complete] ──▶ [SESSION ESTABLISHED]

ACCESS GRANTED
Session Key: 0x5f8e3a2b1c9d...
Encryption: AES-256-GCM
Valid Until: 2026-05-24T12:39:56Z
```

---

### Failed Authentication (Example: Replay Attack)

**Phase 1: Attack Setup**

```
Attacker intercepts previous authentication:
├─ Old Nonce: N_old = 0xa7c3f2e1b4d9...
├─ Old Signature: S_old = 0x3e8b5a2c9d7f...
├─ Old Timestamp: 2026-05-24T12:30:00Z (5 minutes ago)
└─ Certificate: pk_fob
```

**Phase 2: Replay Attempt**

```
Attacker                                 VCM
[Sending old N_old + S_old] ──────────▶ [Challenge Received]
                                         ↓
                                       Validating...
```

**Phase 3: Validation Chain (Fails)**

```
VCM Validation Pipeline:
├─▶ [Verify Signature]
│   └─ Ed25519(pk_fob, nonce, signature)
│      ✓ Valid
│
├─▶ [Validate Certificate]
│   └─ Check issuer = CA root
│      ✓ Trusted
│
├─▶ [Check Freshness]
│   └─ Now - Timestamp < 5 seconds
│      └─ 2026-05-24T12:35:15Z - 2026-05-24T12:30:00Z = 315 seconds
│         ✗ TIMEOUT EXCEEDED
│
└─▶ [SESSION REJECTED]
```

**Phase 4: Access Denied**

```
Validation Failed:
✓ Signature valid
✓ Certificate trusted
✗ Nonce STALE (timeout exceeded)

[Validation Failed] ──▶ [SESSION REJECTED]

ACCESS REJECTED
Reason: Freshness Timeout (Replay Attack Detected)
Timestamp Threshold: 5 seconds
Elapsed Time: 315 seconds
```

---

### Attack Scenarios Visualization

**Scenario 1: Replay Attack**

```
Time ──────────────────────────────────────────────────
     │
     ├─ t=0: Normal auth (Nonce N, Signature S created)
     │
     ├─ t=0.5s: Attacker captures (N, S)
     │
     ├─ t=5m: Normal timeout window closed
     │
     └─ t=5m+1s: Attacker replays (N, S)
                  ✗ REJECTED (too old)
```

**Scenario 2: Forged Signature**

```
DKF sends: (N, S_valid, Cert)
                ↓
Attacker modifies: (N, S_forged, Cert)
                         ↓
VCM receives: (N, S_forged, Cert)
                ↓
Ed25519Verify(pk_fob, N, S_forged)
                ↓
           ✗ INVALID SIGNATURE
                ↓
         ACCESS REJECTED
```

**Scenario 3: Fake Certificate**

```
Attacker provides: (N, S_attacker, Cert_untrusted)
                                    ↓
VCM validates chain: Cert_untrusted
                     ├─ Issuer != CA root
                     ├─ Signature verification fails
                     └─ ✗ NOT TRUSTED
                        ↓
                 ACCESS REJECTED
```

**Scenario 4: Delayed Relay**

```
Message Path 1 (Normal):
VCM ──(N)──────────────▶ DKF: 0.1s
DKF ──(S, Cert)────────▶ VCM: 0.1s
Total RTT: 0.2s

Message Path 2 (Relay Attack):
VCM ──(N)──────────────▶ Relay (Delays 10s)
Relay ──(N)─────────▶ DKF: 0.1s
DKF ──(S, Cert)────────▶ Relay: 0.1s
Relay ──(S, Cert)──────▶ VCM (Delayed 10s total)
Total RTT: 10.2s

VCM receives response:
├─ Signature: ✓ Valid
├─ Certificate: ✓ Trusted
├─ Freshness check:
│  └─ Timestamp diff = 10.2 seconds
│     └─ Exceeds 5s threshold
│        ✗ TIMEOUT
│           ↓
│      ACCESS REJECTED
```

**Scenario 5: Packet Tampering**

```
Original Message:
[N=0xa7c3...][S=0x3e8b...][Cert]
     ↓
Attacker modifies Certificate bytes:
[N=0xa7c3...][S=0x3e8b...][Cert_modified]
     ↓
VCM receives and validates:
├─ Signature with (pk_fob_original, N, S): ✓ Valid
├─ Certificate chain with Cert_modified: ✗ INVALID
│  └─ Cert bytes don't match signature
│     ↓
│  ACCESS REJECTED
```

**Scenario 6: Unauthorized Identity**

```
Unknown DKF attempts auth:
├─ Nonce: N = 0xb9e4...
├─ Signature: S = 0x7f2c...
├─ Certificate: Cert_unknown (signed by CA but not registered)
     ↓
VCM validation:
├─ Signature verification: Ed25519Verify(pk_unknown, N, S)
│  ✗ pk_unknown NOT in whitelist
│  ✗ UNKNOWN IDENTITY
│     ↓
│  ACCESS REJECTED
```

---

## Academic Claims

### What We Demonstrate

- Protocol-level challenge-response authentication
- Certificate-based PKI trust model
- Ed25519 digital signature verification
- Nonce-based replay resistance
- Software-based timing validation for relay mitigation
- AES-GCM authenticated encryption
- Protocol robustness under 6 attack scenarios

### What We Do NOT Claim

- Real-world relay attack elimination (no hardware-layer defenses)
- Production automotive security
- Physical RF protection
- Hardware-rooted trust or TPM
- Real-time safety guarantees

---

## Testing & Validation

Each attack scenario validates that the protocol correctly rejects invalid authentication attempts:

```bash
cargo run --release
# Navigate to Attack Simulation
# Each attack produces deterministic rejection with clear reasoning
```

Expected behavior:

- Legitimate authentication: All checks pass → ACCESS GRANTED
- Any attack variant: At least one check fails → ACCESS REJECTED with reason

---

## File Locations

| Purpose             | Path                      |
| ------------------- | ------------------------- |
| Root CA private key | `keys/ca_private.der`     |
| Root CA public key  | `keys/ca_public.der`      |
| Key fob certificate | `certs/keyfob_cert.der`   |
| Key fob private key | `keys/keyfob_private.der` |
| Activity logs       | `logs/access.log`         |

---

## Future Enhancements (Post-Phase 1)

- Multi-vehicle support with key fob pairing
- GUI-based certificate lifecycle management
- Real-time attack simulation controls
- Session key renegotiation
- Enhanced logging with JSON export
- WebAssembly export for browser-based demos

---

## License

MIT License — See LICENSE file for details

---

## References

- [Ed25519 RFC 8037](https://tools.ietf.org/html/rfc8037)
- [AES-GCM NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [Iced GUI Framework](https://github.com/iced-rs/iced)
- [ed25519-dalek Documentation](https://docs.rs/ed25519-dalek/)
