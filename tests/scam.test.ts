import { describe, expect, it } from "vitest";
import fixtureData from "../src/data/scam-fixtures.json";
import {
  LOCALE_OPTIONS,
  localeMessages,
  speechLanguage,
  t,
  type Locale,
} from "../src/i18n";
import { analyzeScam, type ScamAnalysis, type ScamCategory, type Verdict } from "../src/scam";

interface ScamFixture {
  id: string;
  country: "India" | "Nigeria";
  label: Verdict;
  category?: ScamCategory;
  text: string;
  link?: string;
}

const fixtures = fixtureData as ScamFixture[];

function analyseFixture(fixture: ScamFixture): ScamAnalysis {
  return analyzeScam(fixture.text, fixture.link);
}

describe("SafeHands deterministic Scam Shield", () => {
  it("ships a balanced labelled corpus for India, Nigeria, and safe messages", () => {
    expect(fixtures.length).toBeGreaterThanOrEqual(60);
    expect(fixtures.filter((fixture) => fixture.country === "India").length).toBeGreaterThanOrEqual(20);
    expect(fixtures.filter((fixture) => fixture.country === "Nigeria").length).toBeGreaterThanOrEqual(20);
    expect(fixtures.filter((fixture) => fixture.label === "SCAM").length).toBeGreaterThanOrEqual(35);
    expect(fixtures.filter((fixture) => fixture.label === "LIKELY SAFE").length).toBeGreaterThanOrEqual(12);
    expect(new Set(fixtures.map((fixture) => fixture.id)).size).toBe(fixtures.length);
  });

  it("keeps the language picker and synchronous message maps aligned", () => {
    const expectedCodes: Locale[] = ["en", "pcm", "hi", "yo", "ha", "ar", "bn", "fr", "pt", "es", "sw"];
    const englishKeys = Object.keys(localeMessages.en).sort();
    expect(LOCALE_OPTIONS.map((option) => option.code)).toEqual(expectedCodes);
    expect(new Set(LOCALE_OPTIONS.map((option) => option.nativeName)).size).toBe(expectedCodes.length);

    for (const locale of expectedCodes) {
      expect(Object.keys(localeMessages[locale]).sort(), locale).toEqual(englishKeys);
      expect(speechLanguage(locale), locale).toContain("-");
    }

    for (const locale of ["ar", "bn", "fr", "pt", "es", "sw"] as const) {
      expect(t(locale, "app.machineDraft"), locale).toMatch(/machine-drafted/i);
      expect(t(locale, "app.machineDraft"), locale).toMatch(/native speaker review/i);
      expect(t(locale, "scam.title"), locale).not.toBe(t("en", "scam.title"));
    }
  });

  it("covers the expanded scam categories with plain-language reasons and actions", () => {
    const expectedCategories: ScamCategory[] = [
      "phishing",
      "courier",
      "qr-payment",
      "social-media",
      "voice-call",
      "fake-support",
      "jobs-loans-investment",
      "giveaway-prize-charity",
      "family-emergency",
    ];

    for (const category of expectedCategories) {
      const fixture = fixtures.find((candidate) => candidate.category === category);
      expect(fixture, `fixture for ${category}`).toBeDefined();
      const result = analyseFixture(fixture!);
      expect(result.categories, category).toContain(category);
      expect(result.reasons.join(" "), category).toMatch(/(?:asks|uses|pretends|promises|looks|mentions|connects|claims|puts|combines)/i);
      expect(result.actions.join(" "), category).toMatch(/(?:do not|don't|never|check|call|hang up|verify|official|trusted|pause)/i);
    }

    const olderPerson = analyzeScam("Your grandson is in hospital. Send money to this new number now and do not tell the family.");
    expect(olderPerson.verdict).toBe("SCAM");
    expect(olderPerson.reasons.join(" ")).toMatch(/family|friend|emergency|money|call/i);
    expect(olderPerson.actions.join(" ")).toMatch(/known number|family|do not keep|verify/i);
  });

  it("returns stable, explainable output and exact highlighting spans", () => {
    const message = "Urgent: send the OTP to update your KYC or your account will be blocked.";
    const first = analyzeScam(message);
    const second = analyzeScam(message);

    expect(first).toEqual(second);
    expect(first.verdict).toBe("SCAM");
    expect(first.score).toBeGreaterThanOrEqual(55);
    expect(first.score).toBeLessThanOrEqual(100);
    expect(first.reasons.length).toBeGreaterThan(0);
    expect(first.reasons.length).toBeLessThanOrEqual(4);
    expect(first.topReasons).toEqual(first.reasons);
    expect(first.matchedPhrases.some((phrase) => /otp|kyc|blocked/i.test(phrase))).toBe(true);
    expect(first.matches.length).toBeGreaterThan(0);
    for (const match of first.matches) {
      const source = match.source === "text" ? message : "";
      expect(source.slice(match.start, match.end)).toBe(match.phrase);
      expect(match.end).toBeGreaterThan(match.start);
    }
    expect(first.warnFamilyMessage.toLowerCase()).toContain("family");
    expect(first.actions.some((action) => /never share otp/i.test(action))).toBe(true);
    expect(first.actions.some((action) => /contact your bank/i.test(action))).toBe(true);
  });

  it("meets useful precision and recall thresholds on the labelled fixtures", () => {
    const results = fixtures.map((fixture) => ({ fixture, result: analyseFixture(fixture) }));
    const actualRisk = (fixture: ScamFixture): boolean => fixture.label !== "LIKELY SAFE";
    const predictedRisk = (result: ScamAnalysis): boolean => result.verdict !== "LIKELY SAFE";
    const truePositives = results.filter(({ fixture, result }) => actualRisk(fixture) && predictedRisk(result)).length;
    const predictedPositives = results.filter(({ result }) => predictedRisk(result)).length;
    const actualPositives = results.filter(({ fixture }) => actualRisk(fixture)).length;
    const precision = truePositives / Math.max(1, predictedPositives);
    const recall = truePositives / Math.max(1, actualPositives);

    // These thresholds tolerate a few intentionally ambiguous notices while
    // ensuring the local rules are useful as a first-pass shield.
    expect(precision).toBeGreaterThanOrEqual(0.8);
    expect(recall).toBeGreaterThanOrEqual(0.8);
  });

  it("gives country-specific reporting routes and non-negotiable safety actions", () => {
    const india = analyzeScam("Urgent UPI refund: enter your UPI PIN to receive the money now.");
    expect(india.country).toBe("India");
    expect(india.reportingGuidance.india.some((line) => line.includes("1930"))).toBe(true);
    expect(india.reportingGuidance.india.some((line) => line.includes("cybercrime.gov.in"))).toBe(true);
    expect(india.actions.some((action) => action.includes("1930"))).toBe(true);
    expect(india.actionIds).toContain("never-share-otp");
    expect(india.actionIds).toContain("contact-bank-officially");

    const nigeria = analyzeScam("CBN officer says your BVN is blocked. Send the OTP and transfer the fee now.");
    expect(nigeria.country).toBe("Nigeria");
    expect(nigeria.reportingGuidance.nigeria.some((line) => /EFCC/i.test(line))).toBe(true);
    expect(nigeria.reportingGuidance.nigeria.some((line) => /Nigeria Police/i.test(line))).toBe(true);
    expect(nigeria.actions.some((action) => /EFCC/i.test(action))).toBe(true);
  });

  it("catches UPI receive-money, takeover, link, and impersonation combinations", () => {
    const upi = analyzeScam("Approve this UPI collect request and enter your PIN to receive a refund.");
    expect(upi.verdict).toBe("SCAM");
    expect(upi.categories).toContain("upi");
    expect(upi.matchedPhrases.some((phrase) => /upi|collect|pin/i.test(phrase))).toBe(true);
    expect(upi.actions.some((action) => /PIN is used to send money/i.test(action))).toBe(true);

    const takeover = analyzeScam("Your WhatsApp will be closed. Forward the six-digit verification code immediately.");
    expect(takeover.verdict).toBe("SCAM");
    expect(takeover.categories).toContain("whatsapp");

    const lookalike = analyzeScam("Verify your SBI account now", "https://sbi-secure-login.top/verify");
    expect(lookalike.verdict).toBe("SUSPICIOUS");
    expect(lookalike.categories).toContain("link");
    expect(lookalike.matchedSpans.some((match) => match.source === "link")).toBe(true);

    const arrest = analyzeScam("Police digital arrest: transfer the security deposit now or you will be jailed.");
    expect(arrest.verdict).toBe("SCAM");
    expect(arrest.categories).toContain("impersonation");
  });

  it("does not punish common safety warnings or ordinary benign messages", () => {
    const adversarial = [
      "Never share your OTP. Your bank will never ask for it by phone.",
      "UPI PIN is not needed to receive money; decline unknown collect requests.",
      "Warning: digital arrest scams are fake. Police do not demand transfers on video calls.",
      "The refund was credited in the official app; no PIN or OTP was needed.",
      "Your refund has been processed automatically; no action is required.",
      "Our urgent team meeting starts at 10; please bring the agenda.",
      "Safety tip: phishing emails are fake. Never click a login link or share your password.",
      "Security warning: a QR code can send money. Do not scan one to receive a refund.",
      "Family warning: scammers may pretend to be your child. Call a known number before sending money.",
      "Educational guide: real support will not ask for remote access or a password on an unexpected call.",
      "Safety reminder: social media recovery codes are private. Never forward them.",
    ];

    for (const message of adversarial) {
      const result = analyzeScam(message);
      expect(result.verdict, message).toBe("LIKELY SAFE");
      expect(result.score, message).toBeLessThan(28);
    }

    const official = analyzeScam("Use the official SBI website to review your account: https://sbi.co.in");
    expect(official.verdict).toBe("LIKELY SAFE");
    expect(official.categories).not.toContain("link");
  });

  it("red-teams obfuscation, remote access, and already-shared secrets", () => {
    const obfuscated = analyzeScam("g1ft c4rd / crypto / wire transfer now");
    expect(obfuscated.verdict).not.toBe("LIKELY SAFE");

    const remote = analyzeScam("IT support says install remote-control software and do not tell anyone.");
    expect(remote.verdict).not.toBe("LIKELY SAFE");
    expect(remote.actions.some((action) => /do not|never|official/i.test(action))).toBe(true);

    const disclosed = analyzeScam("I already sent my password and OTP");
    expect(disclosed.verdict).toBe("SCAM");
    expect(disclosed.actions.some((action) => /already shared|change|secure the account/i.test(action))).toBe(true);

    const zeroWidth = analyzeScam("verify at bank\u200bdot\u200bexample\u200bdot\u200bcom");
    expect(zeroWidth.verdict).not.toBe("LIKELY SAFE");

    const question = analyzeScam('Is this a scam? The message says “verify your password”.');
    expect(question.verdict).toBe("SUSPICIOUS");
    expect(question.reasons.join(" ")).toMatch(/password|verification/i);
  });

  it("bounds oversized input while keeping output deterministic", () => {
    const longMessage = `send OTP ${"urgent ".repeat(20000)}`;
    const first = analyzeScam(longMessage);
    const second = analyzeScam(longMessage);
    expect(first).toEqual(second);
    expect(first.score).toBeLessThanOrEqual(100);
    expect(first.verdict).toBe("SCAM");
  });
});
