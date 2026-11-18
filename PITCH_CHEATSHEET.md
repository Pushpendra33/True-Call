# TrueCall — Pitch & Stage Demo Cheat Sheet
**Tagline:** *"A deepfake can copy your face. It can't copy your key."*

---

## 🚀 Quick Launch Links
- **Dual Interactive Simulator:** [http://localhost:3001/](http://localhost:3001/) (or open `simulator/index.html`)
- **Pitch Slides Deck:** [http://localhost:3001/slides](http://localhost:3001/slides) (or open `presentation/index.html`)
- **Terminal Simulator:** Run `./run-sim.sh` from `/Users/pushpendra/Documents/truecall`

---

## ⏱️ 4-Minute Presentation & Demo Script

| Timestamp | What to Say (The Pitch) | What to Do (The Demo) |
|---|---|---|
| **0:00 - 0:30** | *"In January 2024, a finance employee at Arup joined a video call where his CFO and every colleague were AI deepfakes. He transferred $25.6 million to fraudulent bank accounts. Today, seeing and hearing someone on a call proves nothing. TrueCall solves this with dedicated hardware: A deepfake can copy your face. It can't copy your key."* | **Slide 1 & 2** (Title & The Arup Disaster) |
| **0:30 - 1:00** | *"Why do passkeys and phone callbacks fail? Passkeys authenticate website logins, not the wire transfer amount. Phone callbacks are intercepted with voice cloning. TrueCall moves the decision to Passport Prime—an air-gapped device that never connects to the call."* | **Slide 3** (Security Gap Analysis) |
| **1:00 - 1:30** | *"Here is the architecture: 2 QR exchanges, 1 signed approver directory. The finance tool encodes the payment into a request QR. The approver scans it on Prime, sees the exact amount and account, and signs with BIP340 Schnorr. Both QRs travel safely across the call."* | **Slide 4** (Architecture) → Switch to **Simulator** (`http://localhost:3001/`) |
| **1:30 - 2:40** | *"Now let's recreate the Arup attack live on stage and crush four real-world attack vectors:"*<br><br>1. **Attack 1 (Fake CFO):** *"The deepfake demands an urgent wire and tries to sign with a laptop key."* → **BLOCKED**: Key is not in the company's signed directory.<br><br>2. **Attack 2 (Swapped Bank Account):** *"The attacker swaps the IBAN to steal the funds."* → **BLOCKED**: Prime checks the vendor database, flags the changed account in bright red, and the real CFO clicks REJECT.<br><br>3. **Attack 3 (Amount Altered):** *"Malware tries to submit $250k when only $25k was approved."* → **BLOCKED**: Field hash mismatch breaks the signature.<br><br>4. **Attack 4 (Replaying Old Approval):** *"Attacker re-uses yesterday's approval."* → **BLOCKED**: One-time nonce already spent; timestamp expired. | In Simulator, click: <br>• **Attack 1** button<br>• **Attack 2** button<br>• **Attack 3** button<br>• **Attack 4** button<br><br>Show the verifier status card and audit log update live. |
| **2:40 - 3:15** | *"Now the honest flow. A legitimate $25,000 invoice to Autodesk. The CFO scans the QR, inspects the verified green account on Prime's screen, and clicks APPROVE. The bank wire releases immediately."* | Click **"⚡ Auto Demo (Honest Flow)"** in the simulator. Wire releases! |
| **3:15 - 3:45** | *"Beyond payments: TrueCall stops IT helpdesk social engineering (preventing Okta/MFA resets) and protects crypto treasuries with Bitcoin multisig."* | **Slide 7** (Roadmap & Foundation Enterprise Alignment) |
| **3:45 - 4:00** | *"The deepfake on the video call was 100% convincing. But without the physical key on Passport Prime, the money never moved. The deepfake was perfect. It just didn't matter."* | **Slide 8** (Conclusion & Q&A) |

---

## 🛡️ Answers for Judges' Hard Questions

### Q1: "What if the attacker enrolls their own key in the directory?"
> **Answer:** *"Enrolment is the root of trust. TrueCall enforces strict in-person enrolment with a security officer. Furthermore, the approver directory itself is cryptographically signed by the company's offline master admin key."*

### Q2: "Can the Prime camera reliably scan a QR from a video call screen share?"
> **Answer:** *"Yes. TrueCall uses high-contrast, compact QR serialization (under 150 bytes). Passport Prime's camera reads it from a laptop screen or 720p video call in milliseconds."*

### Q3: "Why not use a phone app like Google Authenticator or YubiKey?"
> **Answer:** *"Phones are connected to AI apps, cellular networks, browsers, and zero-day spyware. A compromised phone can display whatever the malware wants. Passport Prime is Human Authority Hardware: dedicated, air-gapped, with zero browser or everyday app attack surface."*

### Q4: "What if an executive is physically coerced?"
> **Answer:** *"Physical coercion is out of scope for digital authentication. However, high-value payments (over $200k) mandate dual-signers across separate executive devices, preventing any single person from acting under duress."*

---

## 🧪 Verification Proof Summary
- **Rust Core Tests:** 4/4 suites passing (`cargo test` in `truecall-core`)
- **CLI Simulator:** 100% working (`cargo run --bin truecall-sim`)
- **Cryptography Used:**
  - BIP340 Schnorr Signatures (`secp256k1`)
  - Tagged SHA-256 Request Hashes
  - Tamper-Evident Hash-Chained Audit Trail
  - Vendor Registry IBAN Verification

