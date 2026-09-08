⚠️ **DRAFT — NOT LEGAL ADVICE.** This has **not** been reviewed by a lawyer. Do not publish or rely on it as your live Privacy Policy until reviewed by a licensed attorney familiar with applicable data protection law (e.g. GDPR if you have EU users, CCPA if you have California users). Placeholders are marked `[LIKE THIS]`.

---

# SOCIA Protocol — Privacy Policy

**Last Updated:** `[DATE]`

## 1. What We Collect

| Category | Examples | Why |
|---|---|---|
| Account data | Email, password (stored as a salted PBKDF2 hash — we never see or store your plaintext password), display name, handle, role | Account creation, login, identity |
| Verification data | One-time password (OTP) codes | Email verification and password reset |
| Billing/business data | Company name, billing address, tax ID, payout details | Enabling escrow payouts (when payment integration is active) |
| Listing data (mandatory) | Industry, rates, budget range, audience size, engagement rate, niche tags, bio, location (city/region), primary platforms (e.g. Instagram, YouTube), content language(s) | Powering the matching algorithm and public marketplace listings |
| Listing data (optional) | Personal interest tags | Small bonus signal for match quality — never required, never lowers your score if left blank |
| Communications | Pitch/proposal content, negotiation chat messages, support ticket content | Enabling the core negotiation and support features |
| Technical data | IP address (for rate-limiting and security), login timestamps | Fraud prevention, abuse prevention, security auditing |

## 2. How We Use Your Data

- To operate your account and authenticate your logins (via signed session tokens)
- To power the algorithmic matching system, which compares your listing's structured data (budget, niche, audience size, engagement rate) against other users' listings to generate compatibility scores
- To facilitate pitches, negotiations, and (where enabled) escrow transactions
- To respond to support requests
- To detect and prevent fraud, abuse, and unauthorized access (e.g. rate-limiting login attempts, audit logging of security-relevant account events)
- To send you service-related emails (OTP codes, pitch notifications, password resets) via `[YOUR EMAIL SENDING DOMAIN]`

## 3. What We Never Do

- We do not sell your personal data to third parties.
- We do not store your password in a readable form — only a one-way cryptographic hash.
- We do not use your data for purposes unrelated to operating the Platform without asking you first.

## 4. Who We Share Data With

- **Licensed payment partner** (`[NAME, e.g. Stripe]`), where escrow/payment functionality is enabled, to process transactions.
- **Email delivery** via Google Workspace, to send verification and notification emails.
- **Hosting infrastructure** (Railway, and its underlying cloud/database providers) to run the Platform and store data.
- **Other Platform users**, limited to what you choose to include in your public listing, and what's necessary for a pitch/negotiation counterparty to see (name, contact email, listing details, negotiation messages).
- We may disclose data if required by law, subpoena, or to protect the safety of our users.

## 5. Data Retention

We retain your account data for as long as your account is active. If you delete your account, your listings are permanently removed. Historical negotiation and transaction records tied to a completed deal with another user may be retained in anonymized/minimal form for legal, accounting, and dispute-resolution purposes, consistent with `[YOUR RECORD RETENTION POLICY / APPLICABLE LAW]`.

## 6. Your Rights

You can, at any time from your Account Settings:
- **Access/export your data** — a full export of your account, listings, pitches, negotiations, and support tickets is available on request.
- **Delete your account** — permanently removes your account and listings. This requires re-entering your password and typing a confirmation phrase, since it cannot be undone.
- **Correct your data** — update your profile, listing, and billing information at any time.

If you are located in the EU/EEA, UK, or California, you may have additional rights under GDPR or CCPA respectively, including the right to lodge a complaint with a supervisory authority. `[EXPAND THIS SECTION WITH COUNSEL IF YOU SERVE THESE REGIONS.]`

## 7. Security Measures

- Passwords are hashed with PBKDF2-HMAC-SHA256 and a unique per-user salt — never stored or logged in plaintext.
- Sessions use signed, time-limited authentication tokens (JWT).
- All traffic is encrypted in transit via HTTPS/TLS.
- Login, password-change, and account-recovery endpoints are rate-limited to reduce brute-force risk.
- Security-relevant account events (logins, failed login attempts, password changes, listing deletions) are logged to an internal audit trail.

No system is 100% secure, and we cannot guarantee absolute security of your data.

## 8. Cookies & Local Storage

SOCIA stores your session token in your browser's local storage to keep you logged in between visits. We do not use third-party advertising or tracking cookies. `[UPDATE IF YOU ADD ANALYTICS/ADVERTISING TOOLS LATER.]`

## 9. Children's Privacy

SOCIA is not directed at, and may not be used by, anyone under 18 years of age. We do not knowingly collect data from minors.

## 10. International Data Transfers

`[COMPLETE IF YOU HAVE USERS OUTSIDE YOUR HOSTING REGION — describe cross-border transfer safeguards.]`

## 11. Changes to This Policy

We may update this Privacy Policy from time to time. Material changes will be communicated to your registered email.

## 12. Contact

Questions or data requests: `[SUPPORT EMAIL]`
