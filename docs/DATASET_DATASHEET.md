# MailGuard Dataset Datasheet: Curated Security Corpus

## 1. Motivation
- **Purpose**: Provide a realistic, balanced, and diverse benchmark dataset for training and testing explainable phishing classifiers.
- **Coverage**: Represents current sophisticated threat actor tactics including MFA session expiration lures, CEO wire fraud, cloud credential harvesting, package delivery fees, and tax refund scams, paired with standard corporate, transactional, and personal communications.

---

## 2. Dataset Composition
- **Total Records**: 400 curated & augmented samples.
- **Classes**:
  - `label = 1` (Phishing / Malicious, ~50%)
  - `label = 0` (Legitimate / Ham, ~50%)
- **Attack Categories**:
  1. `credential_phishing`: Office 365, Google Workspace, Duo MFA, PayPal, Netflix.
  2. `bec_ceo_fraud`: Gift card scams, emergency confidential wire transfers, off-site executive requests.
  3. `invoice_fraud`: Overdue accounts payable, past-due wire instructions.
  4. `delivery_scam`: DHL hub parcel holds, FedEx customs clearance fee requests.
  5. `financial_phishing`: Bank fraud dispute alerts, ATM lockouts.
  6. `scam_lottery`: Unclaimed IRS refunds, crypto airdrop claims.
- **Legitimate Categories**:
  1. `workplace`: Sprint retrospectives, 1:1 meeting recaps, benefits open enrollment.
  2. `transactional`: GitHub PR notifications, Google Cloud invoices, flight confirmations, order receipts.
  3. `newsletter`: Tech digests, Python weekly updates, architectural blogs.
  4. `personal`: Hiking plans, weekend conversational messages.

---

## 3. Data Cleaning & Augmentation
- Injected realistic evasion techniques:
  - Invisible zero-width Unicode characters (`\u200b`, `\u2060`)
  - Cyrillic / Greek homoglyph letter substitutions (`\u0430` for `a`, `\u043e` for `o`)
  - Leetspeak spelling tricks (`paypa1`, `v3rify`, `acc0unt`)
  - Raw IP address links (`http://194.38.20.12/billing`)

---

## 4. Privacy & Ethical Considerations
- Zero PII (Personally Identifiable Information) from real human victims: all names, email addresses, and phone numbers are synthetic or sanitized RFC-compliant examples.
- Safe static URL analysis: all sample links use non-functional, defanged, or internal test endpoints.
