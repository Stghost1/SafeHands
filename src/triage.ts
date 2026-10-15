import protocolJson from "./data/triage-protocol.json";
import facilitiesJson from "./data/facilities.json";

/** The four user-facing urgency levels used by the deterministic engine. */
export type Urgency = "emergency" | "urgent" | "routine" | "self-care";

export type TriageConfidence = "high" | "moderate" | "low";

export type AgeGroup =
  | "newborn"
  | "infant"
  | "child"
  | "teen"
  | "adult"
  | "older-adult"
  | string;

export interface TriageContext {
  /** Age in years unless ageUnit is set to "months". */
  age?: number;
  ageUnit?: "years" | "months";
  ageMonths?: number;
  ageGroup?: AgeGroup;
  pregnant?: boolean;
  /** An alias accepted for integrations that use a pregnancy field. */
  pregnancy?: boolean | string;
  pregnancyStatus?: string;
  postpartum?: boolean;
  country?: string;
  countryCode?: string;
  city?: string;
  /** A string such as "Akure, Nigeria" or a structured location. */
  location?: string | LocationContext;
  /** Lets an organization supply its own verified emergency numbers. */
  emergencyCallNumbers?: string[];
}

/** Object-shaped input accepted by the existing UI adapter as well as text input. */
export interface TriageInput {
  symptoms?: string[];
  description?: string;
  context?: TriageContext;
}

export interface LocationContext {
  city?: string;
  country?: string;
  countryCode?: string;
}

export interface Facility {
  id: string;
  name: string;
  city: string;
  state?: string;
  country: string;
  countryCode: string;
  type: string;
  address: string;
  phone?: string | null;
  latitude?: number;
  longitude?: number;
  emergencyCallNumbers: string[];
  label: string;
  dataStatus: "seed" | "sample" | string;
  isSample: boolean;
  notes?: string;
}

interface ProtocolDefault {
  urgency: Urgency;
  label: string;
  icon: string;
  reasons: string[];
  actionSteps: string[];
  doNotDo: string[];
  escalation: string[];
}

interface ProtocolRule {
  id: string;
  phrases?: string[];
  keywords?: string[];
  reason?: string;
  reasons?: string[];
  urgency?: Urgency;
  label?: string;
  icon?: string;
  actionSteps?: string[];
  doNotDo?: string[];
  escalation?: string[];
  requiresPregnancyContext?: boolean;
  pregnancySensitive?: boolean;
  infantUnderThreeMonthsUrgency?: Urgency;
}

export interface TriageProtocol {
  version: string;
  disclaimer: string;
  emergencyCallNumbers: Record<string, string[]>;
  default: ProtocolDefault;
  hardRedFlags: ProtocolRule[];
  presentations: ProtocolRule[];
}

export interface NormalizedTriageContext extends TriageContext {
  ageYears?: number;
  normalizedAgeMonths?: number;
  city?: string;
  country?: string;
  countryCode?: string;
  pregnant: boolean;
  postpartum: boolean;
}

export interface TriageResult {
  urgency: Urgency;
  /** Alias for consumers that call urgency severity. */
  severity: Urgency;
  /** Compatibility aliases for the UI's compact triage card. */
  level: "emergency" | "urgent" | "routine" | "monitor";
  advice: string;
  detail: string;
  label: string;
  icon: string;
  reasons: string[];
  actionSteps: string[];
  doNotDo: string[];
  escalation: string[];
  emergencyCallNumbers: string[];
  disclaimer: string;
  shareSummary: string;
  facilities: Facility[];
  /** The selected protocol presentation, or null when the input is uncertain. */
  presentation: string | null;
  matchedPresentations: string[];
  matchedRedFlags: string[];
  uncertainty: boolean;
  confidence: TriageConfidence;
  context: NormalizedTriageContext;
  /** Hyphenated aliases make the result convenient for data-driven UI renderers. */
  "action-steps": string[];
  "do-not-do": string[];
  "emergency-call-numbers": string[];
  "share-summary": string;
}

export const protocol: TriageProtocol = protocolJson as unknown as TriageProtocol;
export const protocolData = protocol;
export const triageProtocol = protocol;
export const TRIAGE_PROTOCOL = protocol;
export const hardRedFlags = protocol.hardRedFlags;
export const presentations = protocol.presentations;

export const facilities: Facility[] = facilitiesJson as unknown as Facility[];
export const facilityData = facilities;
export const FACILITIES = facilities;
export const facilitySeeds = facilities;
export const TRIAGE_FACILITIES = facilities;
export const akureFacilities = facilities.filter((facility) => facility.city.toLowerCase() === "akure");
export const sampleIndianFacilities = facilities.filter(
  (facility) => facility.countryCode === "IN" && facility.isSample
);

const URGENCY_RANK: Record<Urgency, number> = {
  "self-care": 1,
  routine: 2,
  urgent: 3,
  emergency: 4
};

const URGENCY_ICONS: Record<Urgency, string> = {
  "self-care": "🌿",
  routine: "ℹ️",
  urgent: "⚠️",
  emergency: "🚨"
};

const PREGNANCY_TERMS = [
  "pregnant",
  "pregnancy",
  "postpartum",
  "after giving birth",
  "fetal movement",
  "baby is not moving",
  "baby not moving",
  "eclampsia"
];

const PREGNANCY_EMERGENCY_PRESENTATIONS = new Set([
  "chest-pain",
  "breathing-difficulty",
  "stroke-symptoms",
  "severe-bleeding",
  "abdominal-pain",
  "headache",
  "pregnancy-warning-signs"
]);

const COUNTRY_CODES: Record<string, string> = {
  ng: "NG",
  nga: "NG",
  nigeria: "NG",
  nigerian: "NG",
  in: "IN",
  ind: "IN",
  india: "IN",
  indian: "IN"
};

function normalize(value: unknown): string {
  return String(value ?? "")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
    .replace(/\s+/g, " ");
}

function unique(items: string[]): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const item of items) {
    const value = String(item ?? "").trim();
    if (value && !seen.has(value)) {
      seen.add(value);
      result.push(value);
    }
  }
  return result;
}

function containsTerm(text: string, term: string): boolean {
  const normalizedTerm = normalize(term);
  if (!normalizedTerm) return false;
  let searchFrom = 0;
  while (searchFrom <= text.length) {
    const index = text.indexOf(normalizedTerm, searchFrom);
    if (index < 0) return false;
    const before = index === 0 || text[index - 1] === " ";
    const after = index + normalizedTerm.length === text.length || text[index + normalizedTerm.length] === " ";
    if (before && after) {
      // Phrases that explicitly describe an absent danger sign remain useful
      // red flags (for example, "not breathing"). Other symptom phrases are
      // ignored when the user clearly negates them ("no chest pain").
      const phraseIsPositiveNegation = /^(?:not|cannot|can't|won't|will not)\b/.test(normalizedTerm);
      const prefix = text.slice(Math.max(0, index - 48), index).trim();
      const negated = /(?:^|\s)(?:no|not|without|never|denies|denied|do not|dont|don't)(?:\s+(?:have|has|having|feel|feeling|any|a|the|my|your|their|this|that))?\s*$/.test(prefix);
      if (phraseIsPositiveNegation || !negated) return true;
    }
    searchFrom = index + Math.max(1, normalizedTerm.length);
  }
  return false;
}

function scoreRule(text: string, rule: ProtocolRule): { score: number; matchedTerms: string[] } {
  const phrases = (rule.phrases ?? []).filter(Boolean);
  const keywords = (rule.keywords ?? []).filter(Boolean);
  const matchedPhrases = phrases.filter((term) => containsTerm(text, term));
  const matchedKeywords = keywords.filter((term) => containsTerm(text, term));
  const matchedTerms = unique([...matchedPhrases, ...matchedKeywords]);
  return {
    // A phrase is stronger evidence than a lone keyword. This keeps broad
    // terms such as "chest" useful without allowing them to beat a clear flag.
    score: matchedPhrases.length * 3 + matchedKeywords.length,
    matchedTerms
  };
}

function asFiniteNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

function countryCodeFrom(value: unknown): string | undefined {
  const raw = String(value ?? "").trim();
  if (!raw) return undefined;
  const upper = raw.toUpperCase().replace(/[^A-Z]/g, "");
  if (upper.length === 2 && COUNTRY_CODES[upper.toLowerCase()]) {
    return COUNTRY_CODES[upper.toLowerCase()];
  }
  const normalized = normalize(raw);
  return COUNTRY_CODES[normalized];
}

function titleCaseLocation(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  if (!trimmed) return undefined;
  return trimmed;
}

function readLocation(context?: TriageContext): LocationContext {
  const location = context?.location;
  if (location && typeof location === "object") {
    return {
      city: location.city,
      country: location.country,
      countryCode: location.countryCode
    };
  }

  if (typeof location === "string" && location.trim()) {
    const parts = location
      .split(",")
      .map((part) => part.trim())
      .filter(Boolean);
    const locationText = normalize(location);
    const locationCountry = Object.keys(COUNTRY_CODES).find((name) =>
      containsTerm(locationText, name)
    );
    return {
      city: parts.length > 1 ? parts[0] : undefined,
      country: parts.length > 1 ? parts[parts.length - 1] : locationCountry,
      countryCode: locationCountry ? COUNTRY_CODES[locationCountry] : undefined
    };
  }

  return {};
}

function isPregnancyContext(text: string, context: TriageContext | undefined): boolean {
  const pregnancyValue = context?.pregnant ?? context?.pregnancy ?? context?.pregnancyStatus;
  const pregnancyState = normalize(pregnancyValue);
  return (
    pregnancyValue === true ||
    pregnancyState === "yes" ||
    pregnancyState === "pregnant" ||
    pregnancyState === "postpartum" ||
    context?.postpartum === true ||
    PREGNANCY_TERMS.some((term) => containsTerm(text, term))
  );
}

function normalizedContext(text: string, context: TriageContext = {}): NormalizedTriageContext {
  const location = readLocation(context);
  const city = titleCaseLocation(context.city ?? location.city);
  const country = titleCaseLocation(context.country ?? location.country);
  const countryCode =
    countryCodeFrom(context.countryCode) ?? countryCodeFrom(country) ?? countryCodeFrom(location.countryCode);

  const rawAge = asFiniteNumber(context.age);
  const explicitAgeMonths = asFiniteNumber(context.ageMonths);
  const ageUnit = context.ageUnit ?? "years";
  let ageYears = ageUnit === "months" && rawAge !== undefined ? rawAge / 12 : rawAge;
  let normalizedAgeMonths = explicitAgeMonths;
  const ageGroup = normalize(context.ageGroup);

  if (normalizedAgeMonths === undefined && ageUnit === "months" && rawAge !== undefined) {
    normalizedAgeMonths = rawAge;
  }
  if (ageYears === undefined) {
    if (ageGroup === "newborn" || ageGroup === "infant" || ageGroup === "baby") ageYears = 0;
    else if (ageGroup === "toddler") ageYears = 2;
    else if (ageGroup === "child") ageYears = 8;
    else if (ageGroup === "teen" || ageGroup === "adolescent") ageYears = 15;
    else if (ageGroup === "older adult" || ageGroup === "older-adult") ageYears = 65;
  }

  return {
    ...context,
    city,
    country,
    countryCode,
    ageYears,
    normalizedAgeMonths,
    pregnant: isPregnancyContext(text, context),
    postpartum:
      context.postpartum === true ||
      normalize(context.pregnancyStatus) === "postpartum" ||
      containsTerm(text, "postpartum") ||
      containsTerm(text, "after giving birth")
  };
}

function locationMatches(facility: Facility, context: NormalizedTriageContext): boolean {
  const requestedCity = normalize(context.city);
  const requestedCountry = normalize(context.country);
  const requestedCode = context.countryCode;
  const cityMatches = !requestedCity || normalize(facility.city) === requestedCity;
  const countryNameMatches = !requestedCountry || normalize(facility.country) === requestedCountry;
  const countryCodeMatches =
    !requestedCode || facility.countryCode.toUpperCase() === requestedCode.toUpperCase();
  const countryMatches = countryNameMatches && countryCodeMatches;
  return cityMatches && countryMatches;
}

/** Return local directory seeds when a city or country is present in context. */
export function getFacilities(context?: TriageContext): Facility[] {
  const normalized = normalizedContext("", context ?? {});
  if (!normalized.city && !normalized.country && !normalized.countryCode) return [];

  const exactMatches = facilities.filter((facility) => locationMatches(facility, normalized));
  if (exactMatches.length > 0) return exactMatches;

  // A city may be supplied without a country. If it is not in the seed list,
  // returning an empty list is safer than displaying a facility in another city.
  if (normalized.city) return [];

  return facilities.filter((facility) => {
    if (normalized.countryCode) return facility.countryCode.toUpperCase() === normalized.countryCode;
    return normalize(facility.country) === normalize(normalized.country);
  });
}

/** Resolve emergency numbers without making a network lookup. */
export function getEmergencyCallNumbers(context?: TriageContext): string[] {
  const source = context ?? {};
  const explicit = source.emergencyCallNumbers ?? [];
  if (explicit.length > 0) return unique(explicit);

  const normalized = normalizedContext("", source);
  const byCountry = normalized.countryCode
    ? protocol.emergencyCallNumbers[normalized.countryCode]
    : undefined;
  return unique(byCountry ?? protocol.emergencyCallNumbers.DEFAULT ?? ["112"]);
}

interface ScoredRule {
  rule: ProtocolRule;
  score: number;
  matchedTerms: string[];
}

function matchedRules(text: string, rules: ProtocolRule[], context: NormalizedTriageContext): ScoredRule[] {
  return rules
    .filter((rule) => !rule.requiresPregnancyContext || context.pregnant || context.postpartum)
    .map((rule) => {
      const match = scoreRule(text, rule);
      return { rule, ...match };
    })
    .filter((match) => match.score > 0);
}

function raiseUrgency(current: Urgency, target: Urgency): Urgency {
  return URGENCY_RANK[target] > URGENCY_RANK[current] ? target : current;
}

function isInfantUnderThreeMonths(context: NormalizedTriageContext): boolean {
  const ageGroup = normalize(context.ageGroup);
  return (
    (context.normalizedAgeMonths !== undefined && context.normalizedAgeMonths <= 3) ||
    (context.ageYears !== undefined && context.ageYears <= 0.25) ||
    ageGroup === "newborn" ||
    ageGroup === "young infant" ||
    ageGroup === "under 3 months"
  );
}

function contextEscalation(
  baseUrgency: Urgency,
  selected: ProtocolRule | undefined,
  context: NormalizedTriageContext
): { urgency: Urgency; reasons: string[]; uncertainty: boolean } {
  let urgency = baseUrgency;
  const reasons: string[] = [];
  let uncertainty = false;
  const presentationId = selected?.id;

  if (isInfantUnderThreeMonths(context) && presentationId === "fever") {
    urgency = raiseUrgency(urgency, selected?.infantUnderThreeMonthsUrgency ?? "emergency");
    reasons.push("Fever in a baby under three months needs emergency assessment.");
  } else if (
    isInfantUnderThreeMonths(context) &&
    selected &&
    (presentationId === "breathing-difficulty" || presentationId === "vomiting-or-diarrhea")
  ) {
    urgency = raiseUrgency(urgency, "emergency");
    reasons.push("Very young babies can worsen quickly, so the threshold for emergency assessment is lower.");
  }

  if (
    selected &&
    context.ageYears !== undefined &&
    (context.ageYears < 5 || context.ageYears >= 65) &&
    URGENCY_RANK[urgency] <= URGENCY_RANK.routine
  ) {
    urgency = raiseUrgency(urgency, "urgent");
    reasons.push("Young children and older adults can worsen with less warning, so prompt assessment is safer.");
  }

  if (context.pregnant || context.postpartum) {
    if (selected?.pregnancySensitive) {
      const saferUrgency = presentationId && PREGNANCY_EMERGENCY_PRESENTATIONS.has(presentationId)
        ? "emergency"
        : "urgent";
      const before = urgency;
      urgency = raiseUrgency(urgency, saferUrgency);
      if (urgency !== before || selected.urgency !== urgency || context.pregnant || context.postpartum) {
        reasons.push("Pregnancy or postpartum context lowers the threshold for prompt assessment.");
      }
    }
  }

  if (selected && selected.urgency && URGENCY_RANK[urgency] > URGENCY_RANK[selected.urgency]) {
    uncertainty = true;
  }

  return { urgency, reasons, uncertainty };
}

function fallbackPresentation(): ProtocolDefault {
  return protocol.default;
}

function ruleReasons(rule: ProtocolRule | undefined): string[] {
  if (!rule) return [];
  return unique([...(rule.reasons ?? []), ...(rule.reason ? [rule.reason] : [])]);
}

function ruleActions(rule: ProtocolRule | undefined, fallback: ProtocolDefault): string[] {
  return unique(rule?.actionSteps ?? fallback.actionSteps);
}

function ruleDoNotDo(rule: ProtocolRule | undefined, fallback: ProtocolDefault): string[] {
  return unique(rule?.doNotDo ?? fallback.doNotDo);
}

function ruleEscalation(rule: ProtocolRule | undefined, fallback: ProtocolDefault): string[] {
  return unique(rule?.escalation ?? fallback.escalation);
}

function urgencyLabel(urgency: Urgency, currentLabel: string): string {
  if (urgency === "emergency" && !/emergency/i.test(currentLabel)) return "Emergency assessment recommended";
  if (urgency === "urgent" && /self[- ]care|medical review soon/i.test(currentLabel)) {
    return "Prompt assessment recommended";
  }
  return currentLabel;
}

function buildShareSummary(input: {
  urgency: Urgency;
  label: string;
  reasons: string[];
  actionSteps: string[];
  emergencyCallNumbers: string[];
  context: NormalizedTriageContext;
}): string {
  const location = input.context.city
    ? ` Location: ${input.context.city}${input.context.country ? `, ${input.context.country}` : ""}.`
    : "";
  const numberText = input.emergencyCallNumbers.length
    ? input.emergencyCallNumbers.join(", ")
    : "local emergency services";
  return [
    "SafeHands triage summary",
    `Urgency: ${input.label} (${input.urgency}).`,
    `Why: ${input.reasons[0] ?? "The message needs a clinician's assessment."}`,
    `Next step: ${input.actionSteps[0] ?? "Arrange medical assessment."}`,
    `Emergency numbers: ${numberText}.${location}`,
    "Navigation guidance only — this is not a diagnosis."
  ].join("\n");
}

function textFromInput(input: TriageInput): string {
  const symptomText: Record<string, string> = {
    breathing: "difficulty breathing",
    chestPain: "chest pain",
    bleeding: "heavy bleeding",
    unconscious: "unresponsive",
    severePain: "severe pain",
    fever: "fever",
    pregnancy: "pregnant",
    other: ""
  };
  const selectedSymptoms = (input.symptoms ?? [])
    .map((symptom) => symptomText[symptom] ?? symptom)
    .filter(Boolean);
  return [...selectedSymptoms, input.description ?? ""].filter(Boolean).join(". ");
}

/**
 * Deterministically route a free-text symptom description to the safest
 * supported pathway. This function never calls a network service and never
 * attempts to diagnose a condition.
 */
export function triage(text: string, context?: TriageContext): TriageResult;
export function triage(input: TriageInput, context?: TriageContext): TriageResult;
export function triage(textOrInput: string | TriageInput, context: TriageContext = {}): TriageResult {
  const inputContext = typeof textOrInput === "string" ? context : { ...context, ...(textOrInput.context ?? {}) };
  const text = typeof textOrInput === "string" ? textOrInput : textFromInput(textOrInput);
  const normalizedText = normalize(text);
  const normalized = normalizedContext(normalizedText, inputContext);
  const fallback = fallbackPresentation();
  const emergencyCallNumbers = getEmergencyCallNumbers(normalized);
  const selectedFacilities = getFacilities(normalized);

  const redFlagMatches = matchedRules(normalizedText, protocol.hardRedFlags, normalized);
  const presentationMatches = matchedRules(normalizedText, protocol.presentations, normalized);

  let selected: ProtocolRule | undefined;
  let baseUrgency: Urgency;
  let reasons: string[];
  let actionSteps: string[];
  let doNotDo: string[];
  let escalation: string[];
  let matchedRedFlags: string[];
  let matchedPresentations: string[];
  let uncertainty: boolean;
  let confidence: TriageConfidence;

  if (redFlagMatches.length > 0) {
    // Hard red flags are deliberately resolved before presentation matching.
    // A reassuring word elsewhere in the message can never lower this result.
    baseUrgency = "emergency";
    matchedRedFlags = redFlagMatches.map(({ rule }) => rule.id);
    matchedPresentations = presentationMatches.map(({ rule }) => rule.id);
    reasons = unique(redFlagMatches.flatMap(({ rule }) => ruleReasons(rule)));
    actionSteps = unique(redFlagMatches.flatMap(({ rule }) => ruleActions(rule, fallback)));
    doNotDo = unique(redFlagMatches.flatMap(({ rule }) => ruleDoNotDo(rule, fallback)));
    escalation = unique(redFlagMatches.flatMap(({ rule }) => ruleEscalation(rule, fallback)));
    uncertainty = false;
    confidence = "high";
  } else if (presentationMatches.length > 0) {
    const sorted = [...presentationMatches].sort((left, right) => {
      const urgencyDifference =
        URGENCY_RANK[right.rule.urgency ?? "urgent"] - URGENCY_RANK[left.rule.urgency ?? "urgent"];
      return urgencyDifference || right.score - left.score;
    });
    const best = sorted[0]!;
    selected = best.rule;
    baseUrgency = best.rule.urgency ?? "urgent";
    matchedRedFlags = [];
    matchedPresentations = sorted.map(({ rule }) => rule.id);
    const hasConflictingUrgency = sorted.some(
      ({ rule }) => (rule.urgency ?? "urgent") !== baseUrgency
    );
    // A single broad keyword is not enough evidence for a low-urgency path.
    uncertainty = hasConflictingUrgency || best.score < 3;
    if (uncertainty && URGENCY_RANK[baseUrgency] < URGENCY_RANK.urgent) {
      baseUrgency = "urgent";
    }
    reasons = ruleReasons(best.rule);
    if (hasConflictingUrgency) {
      reasons.push("More than one presentation may fit the wording, so the safer higher-urgency pathway is shown.");
    }
    if (best.score < 3) {
      reasons.push("The wording is limited, so this result is intentionally cautious.");
    }
    actionSteps = ruleActions(best.rule, fallback);
    doNotDo = ruleDoNotDo(best.rule, fallback);
    escalation = ruleEscalation(best.rule, fallback);
    confidence = uncertainty ? "low" : best.score >= 4 ? "high" : "moderate";
  } else {
    // Unknown input is never labelled self-care. It is escalated to same-day
    // assessment and carries explicit emergency return precautions.
    baseUrgency = fallback.urgency;
    reasons = [...fallback.reasons];
    actionSteps = [...fallback.actionSteps];
    doNotDo = [...fallback.doNotDo];
    escalation = [...fallback.escalation];
    matchedRedFlags = [];
    matchedPresentations = [];
    uncertainty = true;
    confidence = "low";
  }

  const contextResult = contextEscalation(baseUrgency, selected, normalized);
  let urgency = contextResult.urgency;
  uncertainty = uncertainty || contextResult.uncertainty;
  if (contextResult.uncertainty) confidence = "low";
  reasons = unique([...reasons, ...contextResult.reasons]);

  if (uncertainty && URGENCY_RANK[urgency] < URGENCY_RANK.urgent) {
    urgency = "urgent";
    reasons.push("Because the information is uncertain, a lower-urgency pathway is not safe.");
  }

  const baseLabel = selected?.label ?? fallback.label;
  const label = urgencyLabel(urgency, baseLabel);
  const icon = urgency === baseUrgency && selected?.icon ? selected.icon : URGENCY_ICONS[urgency];
  const finalReasons = unique(reasons);
  const finalActionSteps = unique(actionSteps);
  const finalDoNotDo = unique(doNotDo);
  const finalEscalation = unique(escalation);
  const shareSummary = buildShareSummary({
    urgency,
    label,
    reasons: finalReasons,
    actionSteps: finalActionSteps,
    emergencyCallNumbers,
    context: normalized
  });

  return {
    urgency,
    severity: urgency,
    level: urgency === "self-care" ? "monitor" : urgency,
    advice: `${label}. ${finalActionSteps.join(" ")}`,
    detail: finalReasons.join(" "),
    label,
    icon,
    reasons: finalReasons,
    actionSteps: finalActionSteps,
    doNotDo: finalDoNotDo,
    escalation: finalEscalation,
    emergencyCallNumbers,
    disclaimer: protocol.disclaimer,
    shareSummary,
    facilities: selectedFacilities,
    presentation: selected?.id ?? null,
    matchedPresentations,
    matchedRedFlags,
    uncertainty,
    confidence,
    context: normalized,
    "action-steps": finalActionSteps,
    "do-not-do": finalDoNotDo,
    "emergency-call-numbers": emergencyCallNumbers,
    "share-summary": shareSummary
  };
}

export default triage;
