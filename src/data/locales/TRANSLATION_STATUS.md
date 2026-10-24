# SafeHands translation status

The Nigerian Pidgin (`pcm`), Hindi (`hi`), Yoruba (`yo`), Hausa (`ha`), Arabic
(`ar`), Bengali (`bn`), French (`fr`), Portuguese (`pt`), Spanish (`es`), and
Swahili (`sw`) locale files are machine-drafted translations.
They need review by native speakers before being treated as final health or
safety wording. The picker exposes their native names, and each locale's
`app.machineDraft` message states this status in the selected language.

The synchronous maps in `src/i18n.ts` use the bundled JSON assets so the first
screen works without a fetch. If a future key is not yet translated, SafeHands
uses the English text through the existing `withEnglish` fallback; that
fallback is intentionally covered by the machine-draft status message.
