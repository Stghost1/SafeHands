# SafeHands safety red-team and buildathon checklist

**Review status (2026-10-16):** integrated MVP review complete. The deterministic engines, PWA shell, tests, docs, and clean-machine configuration are present. Local TypeScript, Vitest, Vite build, locale, bundle, service-worker, privacy-path, and axe checks pass. Docker execution remains an environment check: run the commands in the Docker section when Docker Engine is installed.

## Release gates

The build is not ready to demo or ship until all of these are true:

- [ ] It uses the agreed lightweight stack: Vite + TypeScript + vanilla DOM; Vitest + jsdom + axe-core for checks. No heavy framework is introduced without an explicit decision.
- [ ] Triage and Scam Shield are deterministic local functions. The same normalized input gives the same result, and the first render plus both engines work with DNS/network disabled.
- [ ] There are no runtime calls to remote APIs, analytics, telemetry, account services, CDNs, or third-party scripts; no API keys, tokens, or secrets are committed.
- [ ] Relative paths and portable npm scripts work from a clean checkout. The documented Docker flow builds and serves without depending on a developer machine path or global package.
- [ ] User text is treated as untrusted text (`textContent`/safe DOM APIs, not unsafe `innerHTML`); long or malformed input cannot crash or hang the page.
- [ ] Health output is triage guidance, not a diagnosis or prescription. Emergency signals are never falsely reassured away, and every result gives a clear next action and an appropriate limitation statement.
- [ ] Scam output explains the signals and gives safe containment steps. It does not open, fetch, execute, or “verify” a user-supplied link or ask for credentials, OTPs, payment, or recovery codes.
- [ ] Keyboard, screen-reader, high-zoom, contrast, and reduced-motion checks pass for empty, loading (if present), result, and error states.
- [ ] README/documentation explains local run/build/test/Docker commands, privacy/offline behavior, safety limitations, supported inputs, and known false-positive/false-negative boundaries.

## Health triage red-team matrix

Run each case against the public triage entry point and record the returned severity, reason, and next action. Exact labels may vary, but the safety invariant must hold.

| ID | Adversarial input | Required behavior |
| --- | --- | --- |
| H1 | `CHEST PAIN` | Highest emergency path; plainly advise immediate local emergency help. Do not return routine self-care merely because the input is short or uppercase. |
| H2 | `I have chest pain and trouble breathing` | Multiple red flags resolve to the highest urgency, with both reasons retained or a clear combined reason. The engine must not stop at the first benign match. |
| H3 | `No chest pain. I cannot breathe and my lips look blue.` | Negation must not cancel unrelated positive red flags. Emergency path remains. |
| H4 | `I do NOT have chest pain; just a mild headache` | Do not treat the negated phrase as an active chest-pain symptom. Give the appropriate non-emergency/clarifying result rather than a keyword-only emergency result. |
| H5 | `not short of breath anymore, but fainted 10 minutes ago` | Historical or resolving symptoms still receive appropriate caution; do not discard the fainting event because of a nearby negation. |
| H6 | `Headache, fever, stiff neck, and confusion` | Combined symptoms must elevate severity; every high-risk signal must not be hidden by a low-risk first match. |
| H7 | Mixed case/spacing/punctuation such as `sEvErE   aLlErGy!!!` | Normalization handles case, repeated whitespace, and punctuation without weakening the emergency classification. |
| H8 | `my chest feels weird` / `I feel off` | Ambiguous language does not get an unjustified green/reassuring result. Ask a focused clarifying question or choose a cautious escalation with red-flag prompts. |
| H9 | `maybe stroke? speech is slurred on one side` | Uncertainty words do not suppress the observable red flag; emergency advice is shown. |
| H10 | Empty input, whitespace, emoji-only input, and unrelated text | No exception or stale result. Request a usable symptom description and expose how to get urgent help if an emergency is suspected. |
| H11 | Very long repeated text and malformed Unicode (including zero-width characters) | Bounded processing with no UI freeze, regex blowup, or crash. Normalization should be explicit and safe; do not silently claim a reliable result for unrecognized text. |
| H12 | Same input submitted repeatedly, including after clearing the form | Stable result with no duplicated alerts, stale previous symptoms, or accumulating DOM/listeners. |

Additional manual spot checks should cover pregnancy, infants/older adults, medication/allergy context, self-harm or immediate danger language, and a user who is alone. If those are outside scope, the UI must state the boundary instead of implying complete medical coverage.

### Health response assertions

- The result states **what to do now**, not only a color or score. Emergency wording uses the user's local emergency service concept and does not hard-code an unsafe country-specific number without context.
- Reasons are understandable and traceable to the input; do not expose a fabricated diagnosis, probability, or clinician endorsement.
- Red-flag instructions remain visible without requiring color perception, hover, or a collapsed panel.
- Advice does not recommend taking, stopping, or changing medication. It does not delay emergency care with excessive questions.
- A disclaimer is concise and placed near the result; it must not replace actionable emergency guidance.

## Scam Shield evasion matrix

The classifier should normalize enough to catch evasion while preserving the original text for the user’s review. It should show detected signals rather than pretending to know intent with certainty.

| ID | Adversarial input | Required behavior |
| --- | --- | --- |
| S1 | `URGENT: your account is locked. Send the 6-digit code now` | High-risk/suspicious result for urgency plus one-time-code theft; advise not to share the code and to use the official app/site independently. |
| S2 | `g1ft  c4rd / crypto / wire transfer` with mixed case and punctuation | Detect common leetspeak and separators for payment coercion; do not rely on exact phrase matching. |
| S3 | An impersonation message with `IT support`, remote-control software, and “do not tell anyone” | Surface impersonation, remote access, and secrecy signals; recommend ending the session and contacting the organization through a known channel. |
| S4 | Obfuscated text with zero-width characters, Unicode look-alikes, inserted spaces, or `bank dot example dot com` | Either normalize safely and flag the underlying indicators or label the text uncertain/high risk. Never follow or fetch the reconstructed URL. |
| S5 | `Is this a scam? The message says “verify your password”` | Treat as a request for analysis, not proof that the user is the scammer; explain the signal and give safe verification steps without asking them to paste credentials. |
| S6 | `I already sent my password and OTP` | Immediate containment guidance: contact the institution through a known channel, change/revoke credentials from a trusted device, and report/freeze as applicable. No blame and no request to disclose the secret. |
| S7 | Benign educational text such as `Our security training discusses gift-card scams` | Avoid an unconditional high-risk label when the text is clearly hypothetical/educational; if confidence is uncertain, say why and let the user decide the next step. |
| S8 | A message containing several weak clues and one strong clue (e.g. urgent invoice plus a payment link) | Combine evidence and retain the strongest signal; do not let a benign phrase or the last match downgrade the result. |
| S9 | Empty, emoji-only, huge, repeated, or malformed input | Graceful validation and bounded processing; no crash, hang, stale classification, or unsafe auto-linking. |
| S10 | Same text submitted twice, then a different text after clearing | Deterministic, isolated results; no signal leakage between submissions and no duplicated result announcements. |

### Scam response assertions

- State the risk level and the concrete signals detected; distinguish “suspicious” from certainty.
- Recommend: stop responding, do not click/pay/share secrets, verify through a known official channel, preserve evidence, and report/secure the account when relevant.
- Never send the input to a server, resolve a URL, load remote content, or render untrusted HTML. Display links as inert text unless a separately reviewed safe-link policy exists.
- Do not request passwords, OTPs, full card numbers, recovery phrases, or other secrets in the UI, logs, telemetry, screenshots, or test fixtures.

## Privacy and offline verification

Perform these checks after implementation:

1. Search source and built output for `fetch`, `XMLHttpRequest`, `sendBeacon`, analytics SDKs, remote script/style URLs, API keys, and token-like literals. A local UI may not make runtime network calls.
2. Run the app with network access blocked and verify first load, both classifiers, validation, and result rendering. Stub/spy network primitives in a test and assert zero calls.
3. Confirm raw health/scam text is not persisted to localStorage, IndexedDB, cookies, URL query strings, or logs by default. If history is intentionally added, require an explicit user action, a clear/delete control, and documentation.
4. Enter `<img src=x onerror=alert(1)>`, quotes, HTML, script text, and very long input. Verify it is rendered only as text and cannot execute or alter the page.
5. Inspect the production bundle and Docker image for secrets and unnecessary outbound dependencies. The clean-machine flow must not require a user account.

## Accessibility and resilient UI checklist

- [ ] Form controls have visible labels, useful instructions, and programmatic error associations.
- [ ] Submit, clear, and any disclosure controls work with keyboard alone; focus order is logical and focus is visible.
- [ ] New results/errors use a suitable `aria-live` region without stealing focus repeatedly or announcing the entire page.
- [ ] Heading structure and landmarks are semantic. Status is conveyed by text/icon/structure as well as color.
- [ ] axe-core passes on the initial page and each major result/error state; manually inspect focus and screen-reader wording.
- [ ] Contrast and target sizes remain usable at 200% zoom and approximately 320 CSS px width; no essential content is clipped or horizontally inaccessible.
- [ ] Motion is absent or respects `prefers-reduced-motion`; no flashing or time-limited emergency message disappears automatically.
- [ ] Error recovery preserves entered text where safe, clearly identifies the invalid field, and permits retry without a full reload.

## Tests and documentation to require in the integration

- Table-driven unit tests cover every H/H and S/S row above, normalization, negation boundaries, severity aggregation, empty input, malformed Unicode, and long-input bounds.
- DOM tests cover submit/clear/repeated-submit behavior and assert user-visible action text, not only internal scores.
- axe-core runs against initial, emergency/high-risk, ordinary, ambiguous, and validation states.
- Build/test scripts are documented and pass from a clean checkout. Docker build and a static production serve are exercised once with network unavailable.
- README documents the product scope, non-diagnostic/non-guaranteed nature of outputs, local-only data handling, offline guarantee, emergency limitations, known false positives/negatives, and how to report a safety issue.
- The implementation documents its rule precedence (especially negation and multi-symptom aggregation) so later edits cannot silently reintroduce keyword-only behavior.

## Integration evidence

- [x] `git rev-parse --verify HEAD` succeeds; the repository has a root commit and later integration commits.
- [x] `package-lock.json`, `.nvmrc` (`22.14.0`), `Dockerfile`, `README.md`, `.env.example`, and portable npm scripts exist.
- [x] `npx tsc --noEmit` passes.
- [x] `npm test` passes: 3 test files, 27 tests, including the 64-message corpus, health adversarial cases, locale parity, DOM paths, and axe-core on the language, home, triage, Scam Shield, facilities, reminders, and settings screens.
- [x] `npm run build` passes. The generated service worker precaches the built shell plus `data/triage-protocol.json`, `data/facilities.json`, `data/scam-fixtures.json`, and all locale JSON assets.
- [x] `npm run checklist` passes. The current initial JavaScript bundle is 42,073 bytes gzipped, below the 200 KB target; no absolute machine paths or secret-like literals were found in app/config/docs.
- [x] User text is escaped before rendering; scam links are displayed as highlighted text and are never fetched or followed by the engine.
- [x] Raw triage/scam text is not written to localStorage or IndexedDB. Only preferences and reminders are persisted.
- [x] The UI keeps a typed/chip path when voice is unavailable, gives visual and read-aloud result controls, and shows emergency wording without relying on color alone.
- [ ] Docker proof must be run on a host with Docker Engine: `docker build -t safehands:local .` followed by `docker run --rm --network none safehands:local npm test`. Both exact commands were attempted here on 2026-10-16 but Windows reported that `docker` is not installed, so no Docker result is claimed.

## Current review conclusion

The local buildathon checklist is green. The remaining unchecked item is an execution-environment proof, not a source gap: this workspace does not have a `docker` executable (`docker` was not recognized). Do not claim the Docker build/test proof until those exact commands have been run on a machine with Docker Engine available.
