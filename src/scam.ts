/**
 * A small, deterministic scam detector.
 *
 * This module deliberately has no network, browser, or model dependency.  It
 * is intended to be useful both in the UI and in tests, so the output keeps
 * the matching evidence (including source offsets) alongside the score.
 */

export type Verdict = "SCAM" | "SUSPICIOUS" | "LIKELY SAFE";
export type Country = "India" | "Nigeria" | "Unknown";
export type MatchSource = "text" | "link";
export type RiskLevel = "high" | "medium" | "low";

export type ScamCategory =
  | "urgency"
  | "credentials"
  | "kyc"
  | "refund"
  | "upi"
  | "courier"
  | "advance-fee"
  | "jobs-loans-investment"
  | "impersonation"
  | "whatsapp"
  | "link";

export interface ScamMatch {
  /** Stable rule identifier, useful for analytics and targeted UI copy. */
  id: string;
  category: ScamCategory;
  /** The exact text that was matched. */
  phrase: string;
  /** UTF-16 offsets in the source named by `source`. */
  start: number;
  end: number;
  source: MatchSource;
  weight: number;
  reason: string;
}

export interface ReportingGuidance {
  country: Country;
  recommended: string[];
  india: string[];
  nigeria: string[];
}

export interface ScamAnalysis {
  verdict: Verdict;
  /** Compatibility shorthand for interfaces that use high/medium/low risk. */
  risk: RiskLevel;
  /** An integer from 0 through 100. */
  score: number;
  /** At most four de-duplicated, user-facing explanations. */
  reasons: string[];
  /** Alias with a descriptive name for consumers that prefer it. */
  topReasons: string[];
  /** Exact phrases, convenient for a simple highlighter. */
  matchedPhrases: string[];
  /** Structured matches with source offsets. */
  matches: ScamMatch[];
  matchedSpans: ScamMatch[];
  matchedPhraseSpans: ScamMatch[];
  actions: string[];
  actionIds: string[];
  safetyActions: string[];
  reportingGuidance: ReportingGuidance;
  /** Alias retained for callers that call the section simply `reporting`. */
  reporting: ReportingGuidance;
  warnFamilyMessage: string;
  familyWarning: string;
  /** Short first-step guidance for compact cards. */
  advice: string;
  /** Plain-text detail suitable for a secondary result line. */
  detail: string;
  /** Country inferred from strong country-specific words in the message. */
  country: Country;
  /** The categories which contributed evidence to the score. */
  categories: ScamCategory[];
}

interface ScanSource {
  source: MatchSource;
  text: string;
}

interface Finding extends ScamMatch {
  /** Used to de-duplicate repeated executions of a rule. */
  key: string;
}

const CATEGORY_CAPS: Record<ScamCategory, number> = {
  urgency: 24,
  credentials: 38,
  kyc: 22,
  refund: 24,
  upi: 36,
  courier: 24,
  "advance-fee": 36,
  "jobs-loans-investment": 32,
  impersonation: 42,
  whatsapp: 32,
  link: 40,
};

const INDIA_REPORTING = [
  "India: if money or account details were lost, call 1930 immediately.",
  "India: file or track a cyber-fraud report at cybercrime.gov.in and alert your bank or UPI provider.",
];

const NIGERIA_REPORTING = [
  "Nigeria: alert your bank or wallet provider immediately and ask it to freeze or trace the transaction.",
  "Nigeria: report suspected fraud to the EFCC and the Nigeria Police Force cybercrime unit; keep the sender, phone number, and payment evidence.",
  "Nigeria: scam SMS and calls can also be reported to the NCC (short code 622) where that channel is available.",
];

const BRAND_HOSTS: Record<string, RegExp> = {
  sbi: /(?:^|\.)sbi\.co\.in$/i,
  hdfc: /(?:^|\.)hdfcbank\.com$/i,
  icici: /(?:^|\.)icicibank\.com$/i,
  axis: /(?:^|\.)axisbank\.com$/i,
  paypal: /(?:^|\.)paypal\.com$/i,
  amazon: /(?:^|\.)amazon\.(?:in|com)$/i,
  flipkart: /(?:^|\.)flipkart\.com$/i,
  npci: /(?:^|\.)npci\.org\.in$/i,
  whatsapp: /(?:^|\.)whatsapp\.com$/i,
  gtbank: /(?:^|\.)gtbank\.com$/i,
  uba: /(?:^|\.)ubagroup\.com$/i,
  opay: /(?:^|\.)opayweb\.com$/i,
  palmpay: /(?:^|\.)palmpay\.com$/i,
};

function withGlobal(regex: RegExp): RegExp {
  const flags = regex.flags.indexOf("g") >= 0 ? regex.flags : `${regex.flags}g`;
  return new RegExp(regex.source, flags);
}

function eachMatch(
  text: string,
  regex: RegExp,
  callback: (phrase: string, start: number, end: number) => void,
): void {
  const matcher = withGlobal(regex);
  let match: RegExpExecArray | null;
  while ((match = matcher.exec(text)) !== null) {
    const phrase = match[0] || "";
    if (phrase.length > 0) {
      const start = match.index;
      callback(phrase, start, start + phrase.length);
    }
    // A defensive guard for a future zero-width rule.
    if (phrase.length === 0) matcher.lastIndex += 1;
  }
}

function hasNegativeContext(text: string, start: number, end: number): boolean {
  const before = text.slice(Math.max(0, start - 90), start).toLowerCase();
  const phrase = text.slice(start, end).toLowerCase();
  const after = text.slice(end, Math.min(text.length, end + 70)).toLowerCase();
  const local = `${before} ${phrase} ${after}`;

  // Educational and family-safety warnings should not be scored as the scam
  // they describe.  These checks intentionally look just outside the match so
  // a phrase such as "last warning" remains useful evidence on its own.
  if (
    /\b(?:never|don't|dont|do not|avoid|beware|protect yourself|stay safe)\b/.test(before) ||
    /\b(?:warning|beware|advice|tip|tips|educational|training|example)\b/.test(before)
  ) {
    return true;
  }
  // A threat rule deliberately contains "if you don't ..." as the thing the
  // scammer says.  Do not mistake that conditional for a safety warning.
  if (
    /\b(?:never|don't|dont|do not|avoid|beware)\b/.test(phrase) &&
    !/\b(?:if\s+you\s+(?:don't|dont|do\s+not)|unless\s+you|avoid\s+(?:arrest|jail|prosecution|legal\s+action))\b/.test(phrase)
  ) {
    return true;
  }

  // Handle formulations such as "a UPI PIN is not needed to receive money"
  // and "the bank will not ask for an OTP" without making a generic `not`
  // token suppress unrelated evidence.
  if (
    /\b(?:not|no)\b[^.!?\n]{0,38}\b(?:need|needed|required|asking|ask|request|requested|share|send|click|open|approve|pay|transfer|block|suspend|freeze|arrest|guaranteed|risk[- ]free|double|quick|easy)\b/.test(
      local,
    )
  ) {
    return true;
  }
  if (/\b(?:not|no)\s+(?:a\s+)?scam\b/.test(local)) return true;
  if (/\b(?:scams?|fraud|fake|hoax)\b[^.!?\n]{0,25}\b(?:fake|common|warning|hoax|fraud)\b/.test(after)) return true;
  if (
    /\b(?:processed|credited|received|settled|paid)\b/.test(phrase) &&
    !/\b(?:claim|verify|click|fee|pay|otp|pin|account|link|transfer|send|share)\b/.test(local)
  ) {
    return true;
  }
  return false;
}

function inferCountry(text: string, optionalLink?: string): Country {
  const value = `${text} ${optionalLink || ""}`.toLowerCase();
  let india = 0;
  let nigeria = 0;

  const indiaSignals: Array<[RegExp, number]> = [
    [/\b(?:india|indian|inr|rupees?|₹|rbi|npci|aadhaar|aadhar|pan|upi|phonepe|paytm|bhim|1930)\b/i, 2],
    [/\b(?:sbi|hdfc|icici|axis)\b/i, 1],
    [/\+91\b/i, 2],
  ];
  const nigeriaSignals: Array<[RegExp, number]> = [
    [/\b(?:nigeria|nigerian|naira|₦|bvn|efcc|cbn|gtbank|uba|opay|palmpay|622)\b/i, 2],
    [/\b(?:nin|fidelity bank|access bank|first bank)\b/i, 1],
    [/\+234\b/i, 2],
  ];

  for (const [signal, weight] of indiaSignals) if (signal.test(value)) india += weight;
  for (const [signal, weight] of nigeriaSignals) if (signal.test(value)) nigeria += weight;

  if (india === 0 && nigeria === 0) return "Unknown";
  if (india > nigeria) return "India";
  if (nigeria > india) return "Nigeria";
  // Aadhaar and UPI are stronger country markers than the ambiguous word
  // "NIN", so use the India tie-break only when those appear.
  if (/\b(?:aadhaar|aadhar|upi|1930)\b/i.test(value)) return "India";
  if (/\b(?:bvn|efcc|naira|₦)\b/i.test(value)) return "Nigeria";
  return "Unknown";
}

function extractHost(link: string): string | null {
  let candidate = link.trim();
  candidate = candidate.replace(/[\s.,!?;:)\]}>'"]+$/g, "");
  if (!candidate) return null;
  if (!/^[a-z][a-z\d+.-]*:\/\//i.test(candidate)) candidate = `https://${candidate}`;
  const match = candidate.match(/^[a-z][a-z\d+.-]*:\/\/([^/?#]+)/i);
  if (!match) return null;
  const hostAndPort = match[1].split("@").pop() || "";
  const host = hostAndPort.split(":")[0].toLowerCase().replace(/^www\./, "");
  return host || null;
}

function addFinding(
  findings: Finding[],
  source: ScanSource,
  id: string,
  category: ScamCategory,
  weight: number,
  reason: string,
  phrase: string,
  start: number,
  end: number,
): void {
  const key = `${id}|${source.source}|${start}|${end}`;
  if (findings.some((finding) => finding.key === key)) return;
  findings.push({
    key,
    id,
    category,
    weight,
    reason,
    phrase,
    start,
    end,
    source: source.source,
  });
}

function addPattern(
  findings: Finding[],
  source: ScanSource,
  id: string,
  category: ScamCategory,
  weight: number,
  reason: string,
  pattern: RegExp,
  options: { skipNegative?: boolean } = {},
): void {
  eachMatch(source.text, pattern, (phrase, start, end) => {
    if (options.skipNegative !== false && hasNegativeContext(source.text, start, end)) return;
    addFinding(findings, source, id, category, weight, reason, phrase, start, end);
  });
}

function scanMessagePatterns(source: ScanSource, findings: Finding[]): void {
  // Pressure and threats.
  addPattern(
    findings,
    source,
    "urgency-pressure",
    "urgency",
    8,
    "It pressures you to act immediately instead of giving you time to verify the request.",
    /\b(?:urgent(?:ly)?|act now|immediately|right away|asap|within\s+\d+\s*(?:minutes?|hours?|days?)|last warning|final notice|expires?\s+(?:today|now|soon))\b/i,
  );
  addPattern(
    findings,
    source,
    "account-threat",
    "urgency",
    14,
    "It threatens to block, suspend, freeze, or close an account or service if you do not comply.",
    /\b(?:account|card|wallet|sim|number|service|line)[^\n]{0,45}\b(?:block(?:ed|ing)?|suspend(?:ed|ing)?|freeze|clos(?:e|ed|ing)|deactivat(?:e|ed|ing)|terminat(?:e|ed|ing))\b/i,
  );
  addPattern(
    findings,
    source,
    "legal-threat",
    "urgency",
    18,
    "It uses arrest, police, court, or legal threats to force a quick payment or disclosure.",
    /\b(?:police|court|arrest|jail|prosecution|legal action|warrant|case)\b[^\n]{0,65}\b(?:unless|if you (?:do not|don't)|pay|send|share|verify|transfer|comply)\b/i,
  );
  addPattern(
    findings,
    source,
    "secrecy-pressure",
    "urgency",
    12,
    "It asks you to keep the contact or transaction secret, a common pressure tactic.",
    /\b(?:do not|don't|dont|never)\s+(?:tell|inform|discuss|share|contact|call)[^.!?\n]{0,35}\b(?:anyone|family|bank|police|friends?)\b/i,
    { skipNegative: false },
  );

  // Lightweight obfuscation and remote-access coercion. These rules flag the
  // text for human review without reconstructing or opening a destination.
  addPattern(
    findings,
    source,
    "wire-transfer-obfuscation",
    "advance-fee",
    30,
    "It contains a wire-transfer instruction, even though the wording is spaced or lightly obfuscated.",
    /\bw[i1]r[e3][\s._-]*tr[a4]nsfer\b/i,
  );
  addPattern(
    findings,
    source,
    "gift-card-payment",
    "advance-fee",
    30,
    "It asks for a gift card or gift-card code as payment, a common scam pattern.",
    /\bg[i1]ft[\s._-]*c[a4]rd\b[^.!?\n]{0,45}\b(?:send|pay|buy|code|number)\b/i,
  );
  addPattern(
    findings,
    source,
    "remote-access-request",
    "impersonation",
    28,
    "It asks for remote or screen access; end the session and contact the organization through a known channel.",
    /\b(?:remote[- ]?control|remote access|screen sharing|anydesk|teamviewer|rustdesk|quick support)\b[^.!?\n]{0,70}\b(?:install|download|allow|give|access|transfer|share|connect)\b/i,
  );
  addPattern(
    findings,
    source,
    "remote-access-term",
    "impersonation",
    18,
    "It mentions remote-control software or support; do not grant device access to an unexpected caller.",
    /\b(?:remote[- ]?control|remote access|screen sharing|anydesk|teamviewer|rustdesk|quick support)\b/i,
  );
  addPattern(
    findings,
    source,
    "support-impersonation",
    "impersonation",
    18,
    "It claims to be technical or IT support; verify the caller through the organization's known contact details.",
    /\b(?:IT support|technical support|helpdesk|help desk)\b/i,
  );
  addPattern(
    findings,
    source,
    "obfuscated-link-text",
    "link",
    28,
    "It hides a web address with words such as 'dot' or invisible characters; do not reconstruct or open it.",
    /\b(?:https?|www|bank|secure|account|login)\s+dot\s+[a-z0-9-]+\s+dot\s+[a-z]{2,}\b|[\u200B-\u200D\uFEFF]/i,
    { skipNegative: false },
  );

  // OTPs, PINs, identity numbers, and card details.
  addPattern(
    findings,
    source,
    "credential-request",
    "credentials",
    30,
    "It asks for an OTP, PIN, identity number, or card security detail that legitimate support should not request.",
    /\b(?:send|share|give|tell|provide|forward|read|dictate|enter|type|submit|confirm|reply\s+with|upload|text)[^\n]{0,42}\b(?:one[- ]time password|otp|verification code|security code|passcode|upi\s*pin|pin|cvv|cvc|bvn|nin|aadhaar|aadhar|pan|card(?:\s*(?:number|details))?|account\s*(?:number|details)?|password)\b/i,
  );
  addPattern(
    findings,
    source,
    "credential-request-reversed",
    "credentials",
    28,
    "It pairs a sensitive code or identity detail with a request to send or enter it.",
    /\b(?:one[- ]time password|otp|verification code|security code|passcode|upi\s*pin|pin|cvv|cvc|bvn|nin|aadhaar|aadhar|pan|card(?:\s*(?:number|details))?|account\s*(?:number|details)?|password)\b[^\n]{0,42}\b(?:send|share|give|tell|provide|forward|read|dictate|enter|type|submit|confirm|reply|upload|text)\b/i,
  );
  addPattern(
    findings,
    source,
    "already-shared-secret",
    "credentials",
    30,
    "It says a password, OTP, PIN, or identity detail may already have been shared; secure the account through a trusted channel now.",
    /\b(?:already|just)\s+(?:sent|shared|gave|given|provided|forwarded|read out|entered)\b[^.!?\n]{0,55}\b(?:otp|one[- ]time password|verification code|pin|password|bvn|nin|aadhaar|cvv|card details?)\b/i,
    { skipNegative: false },
  );
  addPattern(
    findings,
    source,
    "credential-verification-context",
    "credentials",
    24,
    "It connects a password or account detail to a verification request; use the official app instead of replying to the message.",
    /\b(?:verify|confirm|update|reactivate|unlock|secure)\b[^.!?\n]{0,45}\b(?:password|account details?|login|card details?)\b/i,
  );
  addPattern(
    findings,
    source,
    "sensitive-term",
    "credentials",
    4,
    "It mentions a sensitive code or identity/card detail; verify the request through an official channel before responding.",
    /\b(?:one[- ]time password|otp|verification code|security code|passcode|upi\s*pin|pin|cvv|cvc|bvn|nin|aadhaar|aadhar|pan|card\s*(?:number|details)|password)\b/i,
  );

  // KYC and account-verification lures.
  addPattern(
    findings,
    source,
    "kyc-action",
    "kyc",
    18,
    "It uses KYC or account verification as a reason to request an action, a link, a fee, or sensitive details.",
    /\b(?:kyc|know your customer|account verification|profile verification)[^\n]{0,78}\b(?:expire|expired|update|verify|reactivate|suspend|block|link|click|submit|complete|confirm|fee|otp|pin|details?)\b/i,
  );
  addPattern(
    findings,
    source,
    "kyc-action-reversed",
    "kyc",
    16,
    "It links a KYC or verification demand to a deadline or account consequence.",
    /\b(?:update|complete|verify|submit|confirm|reactivate|link|click)[^\n]{0,55}\b(?:kyc|know your customer|account verification|profile verification)\b/i,
  );
  addPattern(
    findings,
    source,
    "kyc-term",
    "kyc",
    4,
    "It mentions KYC or account verification; use the institution's official app or website to check it.",
    /\b(?:kyc|know your customer|account verification|profile verification)\b/i,
  );

  // Fake refunds, credits, cashback, and overpayments.
  addPattern(
    findings,
    source,
    "refund-lure",
    "refund",
    20,
    "It promises a refund, credit, cashback, or reversal while asking you to claim, verify, pay, or click.",
    /\b(?:refund|cashback|cash back|overpayment|reversal|tax refund|chargeback|credit(?:ed|ing)?)\b[^\n]{0,78}\b(?:claim|receive|collect|release|process|verify|click|fee|pay|otp|pin|account|link|transfer)\b/i,
  );
  addPattern(
    findings,
    source,
    "refund-lure-reversed",
    "refund",
    18,
    "It asks for payment or sensitive information in connection with a refund or credit.",
    /\b(?:claim|receive|collect|release|process|verify|click|pay|transfer)[^\n]{0,55}\b(?:refund|cashback|cash back|overpayment|reversal|tax refund|chargeback|credit)\b/i,
  );

  // UPI collect requests and the false claim that a PIN receives money.
  addPattern(
    findings,
    source,
    "upi-collect",
    "upi",
    18,
    "It mentions a UPI or wallet collect request and asks you to approve, scan, or accept it.",
    /\b(?:upi|phonepe|google\s*pay|gpay|paytm|bhim)[^\n]{0,88}\b(?:collect|approve|accept|scan|qr|pin|receive|refund|cashback|credit)\b/i,
  );
  addPattern(
    findings,
    source,
    "upi-pin-to-receive",
    "upi",
    32,
    "It says you need a UPI PIN or QR scan to receive money; a PIN authorizes sending money, not receiving it.",
    /\b(?:upi\s*(?:pin|collect)|collect\s+request|request\s+to\s+collect|qr\s+code)\b[^\n]{0,75}\b(?:receive|refund|cashback|money|credit|payment|approve|accept|enter)\b/i,
  );
  addPattern(
    findings,
    source,
    "upi-pin-to-receive-reversed",
    "upi",
    32,
    "It asks you to enter a PIN in order to receive a refund or payment.",
    /\b(?:enter|share|tell|use|provide)[^\n]{0,24}\b(?:upi\s*)?pin\b[^\n]{0,48}\b(?:receive|refund|credit|money|cashback)\b/i,
  );
  addPattern(
    findings,
    source,
    "upi-approve-request",
    "upi",
    26,
    "It tells you to approve an unexpected UPI collect or payment request.",
    /\b(?:approve|accept|click|open)[^\n]{0,22}\b(?:upi\s*)?(?:collect|payment)\s+request\b/i,
  );
  addPattern(
    findings,
    source,
    "upi-qr-receive",
    "upi",
    28,
    "It asks you to scan a QR code to receive money; scanning can authorize a payment instead.",
    /\b(?:scan|use)[^\n]{0,20}\bqr\s*(?:code)?\b[^\n]{0,55}\b(?:receive|refund|cash|money)\b/i,
  );

  // Courier, parcel, customs, and redelivery fee lures.
  addPattern(
    findings,
    source,
    "courier-fee",
    "courier",
    22,
    "It demands a delivery, courier, customs, or redelivery fee to release a parcel.",
    /\b(?:courier|parcel|package|shipment|delivery|customs)[^\n]{0,82}\b(?:fee|charge|pay|payment|redelivery|clearance|insurance|release|address|hold)\b/i,
  );
  addPattern(
    findings,
    source,
    "courier-fee-reversed",
    "courier",
    20,
    "It asks for a payment in connection with a parcel or delivery message.",
    /\b(?:pay|payment|fee|charge)[^\n]{0,35}\b(?:courier|parcel|package|shipment|delivery|customs|redelivery)\b/i,
  );

  // Advance fees, inheritance, lottery, grants, and beneficiary claims.
  addPattern(
    findings,
    source,
    "advance-fee-inheritance",
    "advance-fee",
    30,
    "It promises an inheritance, grant, prize, or fund but asks for an upfront release, tax, or processing fee.",
    /\b(?:inheritance|estate|beneficiary|lottery|prize|grant|donation|compensation|unclaimed\s+funds?)\b[^\n]{0,90}\b(?:fee|tax|charge|release|processing|upfront|clearance|pay|send|transfer)\b/i,
  );
  addPattern(
    findings,
    source,
    "advance-fee-payment",
    "advance-fee",
    24,
    "It asks for an advance, processing, registration, insurance, or release fee before money is delivered.",
    /\b(?:pay|send|transfer)[^\n]{0,45}\b(?:processing|release|administrative|registration|insurance|clearance|upfront|advance)[^\n]{0,22}\bfee\b/i,
  );
  addPattern(
    findings,
    source,
    "advance-fee-funds",
    "advance-fee",
    18,
    "It combines a large or unexpected fund with beneficiary or claim language.",
    /\b(?:million|large sum|huge amount|unclaimed funds?)\b[^\n]{0,65}\b(?:beneficiary|inheritance|claim|release)\b/i,
  );

  // Jobs, loans, investments, and crypto promises.
  addPattern(
    findings,
    source,
    "job-fee",
    "jobs-loans-investment",
    24,
    "It offers a job or easy task but requires a registration, training, activation, or security fee.",
    /\b(?:job|work\s+from\s+home|employment|hiring|recruit(?:ment)?|task|online\s+work)[^\n]{0,82}\b(?:registration|training|activation|security|processing|deposit|fee|pay|commission)\b/i,
  );
  addPattern(
    findings,
    source,
    "loan-fee",
    "jobs-loans-investment",
    30,
    "It says a loan is approved or guaranteed but asks for an insurance, processing, deposit, or transfer fee.",
    /\b(?:loan|credit)[^\n]{0,78}\b(?:approved|sanctioned|offer|guaranteed|release)[^\n]{0,48}\b(?:fee|insurance|deposit|pay|otp|pin|transfer)\b/i,
  );
  addPattern(
    findings,
    source,
    "investment-guarantee",
    "jobs-loans-investment",
    28,
    "It promises guaranteed, doubled, or risk-free investment returns and asks for money or a wallet transfer.",
    /\b(?:invest(?:ment)?|forex|trading|crypto|bitcoin|usdt|ethereum|wallet)[^\n]{0,82}\b(?:guaranteed|double|profit|returns?|deposit|send|transfer|unlock|recovery|fee|risk[- ]free)\b/i,
  );
  addPattern(
    findings,
    source,
    "easy-money-promise",
    "jobs-loans-investment",
    14,
    "It promises unusually easy, quick, or guaranteed income or profit.",
    /\b(?:guaranteed|double|quick|easy|risk[- ]free)[^\n]{0,38}\b(?:income|salary|profit|money|returns?|earnings?)\b/i,
  );

  // Impersonation and "digital arrest" scripts.
  addPattern(
    findings,
    source,
    "digital-arrest",
    "impersonation",
    34,
    "It uses a so-called digital arrest, investigation, or warrant to frighten you into complying.",
    /\b(?:digital\s+arrest|cyber\s+arrest|video\s+call\s+from\s+(?:the\s+)?police|under\s+investigation|money\s+laundering\s+case)\b/i,
  );
  addPattern(
    findings,
    source,
    "authority-impersonation",
    "impersonation",
    28,
    "It claims to be a bank, police, government, or enforcement officer while demanding payment, access, or personal details.",
    /\b(?:police|cbi|enforcement directorate|ed|efcc|fbi|customs|immigration|central bank|cbn|bank officer|rbi|government|tax authority|court)\b[^\n]{0,88}\b(?:pay|transfer|share|verify|install|remote|arrest|warrant|fine|bail|comply)\b/i,
  );
  addPattern(
    findings,
    source,
    "criminal-accusation",
    "impersonation",
    22,
    "It accuses you or your account of illegal activity to make a payment or disclosure feel compulsory.",
    /\b(?:your\s+(?:account|number|sim|parcel)|you)\b[^\n]{0,80}\b(?:illegal|criminal|money\s+laundering|drug|arrest|case|warrant)\b/i,
  );

  // WhatsApp verification-code and takeover attempts.
  addPattern(
    findings,
    source,
    "whatsapp-takeover",
    "whatsapp",
    26,
    "It links WhatsApp verification, a linked device, or a six-digit code to a request for access.",
    /\b(?:whatsapp|whats\s*app)[^\n]{0,78}\b(?:verification|security|login|six[- ]digit|6[- ]digit|code|linked\s+device|takeover|hack|blocked|closed)\b/i,
  );
  addPattern(
    findings,
    source,
    "whatsapp-code-request",
    "whatsapp",
    30,
    "It asks for a WhatsApp or verification code that must stay private.",
    /\b(?:send|share|forward|tell|read|provide)[^\n]{0,30}\b(?:whatsapp|verification|six[- ]digit|6[- ]digit)[^\n]{0,30}\b(?:code|otp|pin)\b/i,
  );
  addPattern(
    findings,
    source,
    "whatsapp-threat",
    "whatsapp",
    18,
    "It threatens to block or hack WhatsApp unless you respond or provide a code.",
    /\b(?:your\s+)?whatsapp\b[^\n]{0,48}\b(?:will be|has been|is)\b[^\n]{0,20}\b(?:blocked|hacked|closed|disabled)\b/i,
  );
}

function scanLinkPatterns(source: ScanSource, findings: Finding[]): void {
  const urlPattern = /(?:https?:\/\/|www\.)[^\s<>"']+|\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|cutt\.ly|is\.gd|rb\.gy|rebrand\.ly|lnkd\.in|ow\.ly)\/[^\s<>"']+/gi;
  const shortenedPattern = /\b(?:https?:\/\/)?(?:www\.)?(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|cutt\.ly|is\.gd|rb\.gy|rebrand\.ly|lnkd\.in|ow\.ly)\/[^\s<>"']+/i;

  addPattern(
    findings,
    source,
    "short-link",
    "link",
    28,
    "It uses a shortened link, which hides the destination and deserves independent verification.",
    shortenedPattern,
  );
  addPattern(
    findings,
    source,
    "punycode-link",
    "link",
    30,
    "The link uses an encoded/punycode domain, a common lookalike-domain tactic.",
    /\b(?:https?:\/\/|www\.)[^\s/?#]*xn--[^\s/?#]+/i,
  );
  addPattern(
    findings,
    source,
    "ip-link",
    "link",
    30,
    "The link points to a raw IP address rather than a recognizable service domain.",
    /\bhttps?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/[^\s<>"']*)?/i,
  );
  addPattern(
    findings,
    source,
    "userinfo-link",
    "link",
    28,
    "The link contains an @ sign before its destination, which can disguise the real host.",
    /\bhttps?:\/\/[^\s/?#]+@[^\s/?#]+/i,
  );
  addPattern(
    findings,
    source,
    "lookalike-brand-link",
    "link",
    28,
    "The link uses a brand-like name with a login, verification, or secure suffix that may be a lookalike.",
    /\b(?:https?:\/\/|www\.)[^\s/]*(?:sbi|hdfc|icici|axis|paypal|amazon|whatsapp|npci|cbn|gtbank|uba|opay|palmpay)[^\s/]*(?:-secure|-verify|-login|-support|-update|-account)[^\s/]*\.[a-z]{2,}(?:\/[^\s<>"']*)?/i,
  );
  addPattern(
    findings,
    source,
    "suspicious-tld-link",
    "link",
    28,
    "The link uses a high-risk or uncommon domain ending; verify the destination through an official app or bookmark.",
    /\bhttps?:\/\/[^\s/]+\.(?:top|click|xyz|icu|support|site|online|info|live|buzz|shop|pro)(?:\/[^\s<>"']*)?/i,
  );
  addPattern(
    findings,
    source,
    "link-action",
    "link",
    14,
    "It combines a link with a request to click, log in, verify, claim, pay, or update an account.",
    /\b(?:click|open|tap|visit|follow|verify|update|claim|pay|login|log\s+in|sign\s+in|confirm)[^.!?\n]{0,80}(?:https?:\/\/|www\.|\b(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly)\/)/i,
  );
  // A plain HTTP link is not automatically a scam, but an urgent or account
  // action around it is a meaningful extra signal.
  addPattern(
    findings,
    source,
    "http-action-link",
    "link",
    8,
    "It asks you to use a non-HTTPS link for an account or payment action.",
    /\b(?:click|open|tap|visit|verify|update|claim|pay|login|log\s+in|sign\s+in)[^.!?\n]{0,55}\bhttp:\/\//i,
  );

  // Use the URL matches to attach a small, contextual signal when a link is
  // surrounded by action words, while leaving ordinary official links alone.
  eachMatch(source.text, urlPattern, (phrase, start, end) => {
    const context = source.text
      .slice(Math.max(0, start - 65), Math.min(source.text.length, end + 65))
      .toLowerCase();
    const suspiciousDestination =
      /(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|cutt\.ly|is\.gd|rb\.gy|rebrand\.ly|lnkd\.in|ow\.ly|xn--)/i.test(phrase) ||
      /\b(?:https?:\/\/)?(?:\d{1,3}\.){3}\d{1,3}\b/i.test(phrase) ||
      /@/.test(phrase) ||
      /\.(?:top|click|xyz|icu|support|site|online|info|live|buzz|shop|pro)(?:\/|$)/i.test(phrase);
    if (
      suspiciousDestination &&
      /\b(?:urgent|immediately|kyc|refund|account|verify|claim|payment|pay|otp|pin|blocked|suspended)\b/.test(
        context,
      ) &&
      !hasNegativeContext(source.text, start, end)
    ) {
      addFinding(
        findings,
        source,
        "contextual-link",
        "link",
        12,
        "The link appears alongside an urgent account, payment, verification, or sensitive-code request.",
        phrase,
        start,
        end,
      );
    }
  });
}

function scanBrandMismatch(
  text: string,
  optionalLink: string | undefined,
  findings: Finding[],
): void {
  if (!optionalLink) return;
  const host = extractHost(optionalLink);
  if (!host) return;
  const lowerText = text.toLowerCase();
  for (const brand of Object.keys(BRAND_HOSTS)) {
    const brandWord = new RegExp(`\\b${brand}\\b`, "i");
    if (brandWord.test(lowerText) && !BRAND_HOSTS[brand].test(host)) {
      const source: ScanSource = { source: "link", text: optionalLink };
      addFinding(
        findings,
        source,
        "brand-domain-mismatch",
        "link",
        28,
        `It mentions ${brand.toUpperCase()} but the supplied link does not use that service's official domain.`,
        optionalLink,
        0,
        optionalLink.length,
      );
      return;
    }
  }
}

function scoreFindings(findings: Finding[]): number {
  const byCategory = new Map<ScamCategory, number[]>();
  for (const finding of findings) {
    const values = byCategory.get(finding.category) || [];
    values.push(finding.weight);
    byCategory.set(finding.category, values);
  }

  let score = 0;
  for (const [category, values] of byCategory.entries()) {
    values.sort((left, right) => right - left);
    let categoryScore = 0;
    // Two or three independent phrases in one category are useful, but a
    // repeated keyword should not by itself reach the scam threshold.
    for (const weight of values.slice(0, 3)) categoryScore += weight;
    score += Math.min(CATEGORY_CAPS[category], categoryScore);
  }

  const has = (category: ScamCategory): boolean => byCategory.has(category);
  if (has("credentials") && (has("urgency") || has("link") || has("kyc") || has("impersonation"))) score += 12;
  if (has("upi") && (has("credentials") || has("urgency") || has("link"))) score += 10;
  if (has("whatsapp") && (has("credentials") || has("urgency") || has("link"))) score += 12;
  if (has("jobs-loans-investment") && (has("urgency") || has("link"))) score += 6;
  if (has("impersonation") && has("urgency")) score += 8;
  if (has("advance-fee") && (has("urgency") || has("link"))) score += 7;
  if (has("refund") && (has("credentials") || has("link") || has("urgency"))) score += 7;

  // A direct request for a secret, a UPI PIN-to-receive instruction, a
  // WhatsApp verification code, or the phrase "digital arrest" is already a
  // high-confidence event even when the sender omits an explicit deadline.
  if (
    findings.some((finding) =>
      [
        "credential-request",
        "credential-request-reversed",
        "upi-pin-to-receive",
        "upi-pin-to-receive-reversed",
        "whatsapp-code-request",
        "digital-arrest",
        "already-shared-secret",
      ].includes(finding.id),
    )
  ) {
    score = Math.max(score, 56);
  }

  return Math.max(0, Math.min(100, Math.round(score)));
}

function makeReporting(country: Country): ReportingGuidance {
  const recommended = country === "India" ? INDIA_REPORTING : country === "Nigeria" ? NIGERIA_REPORTING : [...INDIA_REPORTING, ...NIGERIA_REPORTING];
  return {
    country,
    recommended: [...recommended],
    india: [...INDIA_REPORTING],
    nigeria: [...NIGERIA_REPORTING],
  };
}

function makeActions(
  verdict: Verdict,
  findings: Finding[],
  country: Country,
  score: number,
): { actions: string[]; actionIds: string[] } {
  const hasCategory = (category: ScamCategory): boolean => findings.some((finding) => finding.category === category);
  const actions: string[] = [
    "Never share OTPs, PINs, BVN, NIN, Aadhaar numbers, CVVs, passwords, or screen access—even with someone claiming to be your bank.",
    "Contact your bank or wallet provider using the number on your card, statement, or official app/site; do not use a number in the message.",
  ];
  const actionIds = ["never-share-otp", "contact-bank-officially"];

  if (hasCategory("credentials")) {
    actions.push("Stop replying and do not read out, enter, forward, or upload any verification code or identity detail.");
    actionIds.push("stop-credential-sharing");
    actions.push("If you already shared a secret, contact the institution through a known channel now, change or revoke access from a trusted device, and ask the provider to secure the account.");
    actionIds.push("contain-shared-secret");
  }
  if (hasCategory("upi")) {
    actions.push("A UPI PIN is used to send money, not receive it; decline unexpected collect requests and never scan a QR code to get paid.");
    actionIds.push("decline-upi-collect");
  }
  if (hasCategory("link")) {
    actions.push("Do not open the link. Open the official app or type the institution's known website yourself instead.");
    actionIds.push("avoid-suspicious-link");
  }
  if (verdict !== "LIKELY SAFE") {
    actions.push("Block and report the sender, save screenshots and transaction details, and tell a trusted person before taking any further step.");
    actionIds.push("block-preserve-evidence");
  } else {
    actions.push("If the message was unexpected, verify it independently before paying or sharing any information.");
    actionIds.push("verify-independently");
  }
  if (score >= 28) {
    if (country === "India") {
      actions.push("India: if you lost money or shared banking details, call 1930 promptly and report at cybercrime.gov.in.");
      actionIds.push("report-india-1930");
    } else if (country === "Nigeria") {
      actions.push("Nigeria: alert your bank, then report the fraud to the EFCC and the Nigeria Police Force cybercrime unit; keep your evidence.");
      actionIds.push("report-nigeria-channels");
    } else {
      actions.push("If you lost money, contact your bank immediately; India users can call 1930/cybercrime.gov.in and Nigeria users can contact the EFCC or Police cybercrime unit.");
      actionIds.push("report-country-channel");
    }
  }
  return { actions, actionIds };
}

function makeFamilyWarning(verdict: Verdict, score: number, reasons: string[], country: Country): string {
  if (verdict === "LIKELY SAFE") {
    return "Safety note to share with family: no strong scam signals were found here, but never share an OTP or PIN and verify unexpected requests through an official bank or service channel.";
  }
  const lead = reasons[0] || "the request uses common scam signals";
  const countryNote = country === "India" ? " In India, call 1930 quickly if money was lost." : country === "Nigeria" ? " In Nigeria, alert your bank and report to the EFCC or Police cybercrime unit." : " Contact your bank immediately if money or details were shared.";
  return `Warning to share with family: this message looks ${verdict.toLowerCase()} (score ${score}/100) because ${lead.toLowerCase()} Do not click, pay, or share an OTP/PIN; verify through an official channel.${countryNote}`;
}

/**
 * Analyze a message and, optionally, a separately supplied URL.
 *
 * Scores are intentionally explainable rather than probabilistic.  A single
 * ordinary word such as "urgent" stays below the suspicious threshold, while
 * combinations such as a credential request plus a threat or risky link rise
 * to SCAM.
 */
export function analyzeScam(text: string, optionalLink?: string): ScamAnalysis {
  // Keep direct engine calls bounded as well as UI calls. This prevents a
  // pasted log or repeated Unicode string from causing slow scans or giant
  // local highlights, while retaining enough text for an SMS/WhatsApp message.
  const message = (typeof text === "string" ? text : String(text ?? "")).slice(0, 8000);
  const link = typeof optionalLink === "string" && optionalLink.trim() ? optionalLink.trim().slice(0, 2000) : undefined;
  const findings: Finding[] = [];
  const textSource: ScanSource = { source: "text", text: message };

  if (message) {
    scanMessagePatterns(textSource, findings);
    scanLinkPatterns(textSource, findings);
  }
  if (link) scanLinkPatterns({ source: "link", text: link }, findings);
  scanBrandMismatch(message, link, findings);

  // Stable ordering makes highlighting and snapshots deterministic even when
  // two rules have the same weight.
  findings.sort((left, right) => {
    if (right.weight !== left.weight) return right.weight - left.weight;
    if (left.source !== right.source) return left.source === "text" ? -1 : 1;
    if (left.start !== right.start) return left.start - right.start;
    return left.id.localeCompare(right.id);
  });

  const score = scoreFindings(findings);
  const verdict: Verdict = score >= 55 ? "SCAM" : score >= 28 ? "SUSPICIOUS" : "LIKELY SAFE";
  const reasons: string[] = [];
  for (const finding of findings) {
    if (!reasons.includes(finding.reason)) reasons.push(finding.reason);
    if (reasons.length >= 4) break;
  }
  if (reasons.length === 0) reasons.push("No strong scam signals were found. Treat unexpected requests cautiously.");

  const matches = findings.map(({ key: _key, ...finding }) => finding);
  const matchedPhrases = Array.from(new Set(matches.map((match) => match.phrase)));
  const country = inferCountry(message, link);
  const reportingGuidance = makeReporting(country);
  const { actions, actionIds } = makeActions(verdict, findings, country, score);
  const warnFamilyMessage = makeFamilyWarning(verdict, score, reasons, country);
  const categories = Array.from(new Set(findings.map((finding) => finding.category)));
  const risk: RiskLevel = verdict === "SCAM" ? "high" : verdict === "SUSPICIOUS" ? "medium" : "low";

  return {
    verdict,
    risk,
    score,
    reasons,
    topReasons: reasons,
    matchedPhrases,
    matches,
    matchedSpans: matches,
    matchedPhraseSpans: matches,
    actions,
    actionIds,
    safetyActions: actions,
    reportingGuidance,
    reporting: reportingGuidance,
    warnFamilyMessage,
    familyWarning: warnFamilyMessage,
    advice: actions[0],
    detail: reasons.join(" "),
    country,
    categories,
  };
}

export default analyzeScam;
