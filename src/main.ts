import "./styles.css";
import { analyzeScam as analyzeScamEngine, type ScamAnalysis } from "./scam";
import {
  facilities as seededFacilities,
  getFacilities,
  triage as triageEngine,
  type Facility,
  type TriageResult as EngineTriageResult,
} from "./triage";
import { readLocalSetting, saveLocalSetting } from "./storage";
import {
  buildSosPayload,
  climateRisk,
  fetchOpenMeteoTelemetry,
  getAuthorityRoute,
  getAuthorityRoutes,
  makeRiskRadar,
  makeHydrationPlan,
  safeZoneSearchUrl,
  type ActivityLevel,
  type ClimateRisk,
  type ClimateTelemetry,
  type HydrationPlan,
  type VulnerableProfile,
} from "./climate";
import climateProtocols from "./data/climate-protocols.json";
import {
  LOCALE_OPTIONS,
  type Locale,
  type MessageKey,
  getSavedLocale,
  isLocale,
  localeMessages,
  saveLocale,
  speechLanguage,
  t,
} from "./i18n";

type Screen = "home" | "triage" | "scam" | "climate" | "facilities" | "reminders" | "settings";
type TriageLevel = "emergency" | "urgent" | "routine" | "monitor";
type ScamRisk = "high" | "medium" | "low" | "unknown";

interface TriageResult {
  level: TriageLevel;
  urgency?: string;
  label?: string;
  icon?: string;
  advice: string;
  detail?: string;
  reasons: string[];
  actionSteps: string[];
  doNotDo: string[];
  escalation: string[];
  waitingCare: string[];
  emergencyCallNumbers: string[];
  disclaimer: string;
  shareSummary: string;
  matchedPresentations: string[];
  matchedRedFlags: string[];
}

interface ScamResult {
  risk: ScamRisk;
  verdict?: "SCAM" | "SUSPICIOUS" | "LIKELY SAFE";
  score?: number;
  advice: string;
  detail?: string;
  reasons: string[];
  matchedPhrases: string[];
  matches: Array<{ phrase: string; start: number; end: number; source: "text" | "link" }>;
  actions: string[];
  reporting: string[];
  warnFamilyMessage: string;
}

interface Reminder {
  id: string;
  label: string;
  when: string;
}

interface Preferences {
  easyMode: boolean;
  highContrast: boolean;
  darkMode: boolean;
  reducedMotion: boolean;
  dyslexia: boolean;
  textSize: "small" | "medium" | "large";
  speechRate: number;
}

interface AppState {
  locale: Locale | null;
  screen: Screen;
  triageSymptoms: string[];
  triageDescription: string;
  triageResult: TriageResult | null;
  triagePending: boolean;
  triageError: string;
  scamSignals: string[];
  scamText: string;
  scamLink: string;
  scamResult: ScamResult | null;
  scamPending: boolean;
  scamError: string;
  reminders: Reminder[];
  preferences: Preferences;
  liveMessage: string;
  offlineReady: boolean;
  online: boolean;
  navOpen: boolean;
  facilityCity: string;
  facilityLocation: { latitude: number; longitude: number } | null;
  facilityLocationMessage: string;
  climateTelemetry: ClimateTelemetry | null;
  climateRisk: ClimateRisk | null;
  climateError: string;
  climateLoading: boolean;
  climateActivity: ActivityLevel;
  climateProfiles: VulnerableProfile[];
  climateAnnouncementMinutes: number;
  climateAnnouncementsEnabled: boolean;
  hydrationPlan: HydrationPlan | null;
  hydrationReminderNumber: number;
  climateProtocolId: string | null;
  climateProtocolStep: number;
  climateCountryCode: string;
  climateSosType: string;
  climateSosPeople: number;
  climateSosContact: string;
  climateBatteryPercent: number | null;
  climateLowBatteryMode: boolean;
  climateBeaconActive: boolean;
}

interface OptionalModule {
  [key: string]: unknown;
}

interface SpeechRecognitionResultLike {
  transcript: string;
}

interface SpeechRecognitionEventLike {
  results?: ArrayLike<ArrayLike<SpeechRecognitionResultLike>>;
}

interface SpeechRecognitionLike {
  lang: string;
  continuous: boolean;
  interimResults: boolean;
  onresult: ((event: SpeechRecognitionEventLike) => void) | null;
  onerror: (() => void) | null;
  onend: (() => void) | null;
  start: () => void;
  stop: () => void;
}

type SpeechRecognitionConstructor = new () => SpeechRecognitionLike;

interface BrowserWindow extends Window {
  SpeechRecognition?: SpeechRecognitionConstructor;
  webkitSpeechRecognition?: SpeechRecognitionConstructor;
  getBattery?: () => Promise<BatteryLike>;
  AudioContext?: typeof AudioContext;
  webkitAudioContext?: typeof AudioContext;
}

interface BatteryLike extends EventTarget {
  level: number;
  addEventListener(type: "levelchange", listener: () => void): void;
}

const preferencesStorageKey = "safehands.preferences";
const remindersStorageKey = "safehands.reminders";
const climatePreferencesStorageKey = "safehands.climate.preferences";
const climateTelemetryStorageKey = "safehands.climate.telemetry";

const symptomOptions: Array<{ value: string; label: MessageKey }> = [
  { value: "breathing", label: "triage.symptomBreathing" },
  { value: "chestPain", label: "triage.symptomChestPain" },
  { value: "bleeding", label: "triage.symptomBleeding" },
  { value: "unconscious", label: "triage.symptomUnconscious" },
  { value: "severePain", label: "triage.symptomSeverePain" },
  { value: "fever", label: "triage.symptomFever" },
  { value: "pregnancy", label: "triage.symptomPregnancy" },
  { value: "other", label: "triage.symptomOther" },
];

const scamSignalOptions: Array<{ value: string; label: MessageKey }> = [
  { value: "urgency", label: "scam.signalUrgency" },
  { value: "otp", label: "scam.signalOtp" },
  { value: "payment", label: "scam.signalPayment" },
  { value: "impersonation", label: "scam.signalImpersonation" },
];

const defaultPreferences: Preferences = {
  easyMode: false,
  highContrast: false,
  darkMode: false,
  reducedMotion: false,
  dyslexia: false,
  textSize: "medium",
  speechRate: 1,
};

const emergencySymptoms = new Set(["breathing", "chestPain", "bleeding", "unconscious"]);

let mountedRoot: HTMLElement | null = null;
let globalEventsInstalled = false;
// Kept for backwards-compatible host shells that may still call the optional
// module loader; the MVP itself uses the bundled deterministic engines below.
let triageModulePromise: Promise<OptionalModule | null> | null = null;
let scamModulePromise: Promise<OptionalModule | null> | null = null;
let activeRecognition: SpeechRecognitionLike | null = null;
const reminderTimers = new Map<string, number>();
let climateAnnouncementTimer: number | null = null;
let hydrationTimer: number | null = null;
let climateBeaconTimer: number | null = null;
let climateAudioContext: AudioContext | null = null;
let climateBatteryManager: BatteryLike | null = null;

let state: AppState = createInitialState();

function createInitialState(): AppState {
  const locale = getSavedLocale();
  const shareTarget = readShareTarget();
  const climatePreferences = readClimatePreferences();
  return {
    locale,
    screen: locale && shareTarget ? "scam" : "home",
    triageSymptoms: [],
    triageDescription: "",
    triageResult: null,
    triagePending: false,
    triageError: "",
    scamSignals: [],
    scamText: shareTarget?.text ?? "",
    scamLink: shareTarget?.link ?? "",
    scamResult: null,
    scamPending: false,
    scamError: "",
    reminders: readReminders(),
    preferences: readPreferences(),
    liveMessage: "",
    offlineReady: false,
    online: typeof navigator === "undefined" || navigator.onLine !== false,
    navOpen: false,
    facilityCity: "Akure",
    facilityLocation: null,
    facilityLocationMessage: "",
    climateTelemetry: null,
    climateRisk: null,
    climateError: "",
    climateLoading: false,
    climateActivity: climatePreferences.activity,
    climateProfiles: climatePreferences.profiles,
    climateAnnouncementMinutes: climatePreferences.announcementMinutes,
    climateAnnouncementsEnabled: false,
    hydrationPlan: null,
    hydrationReminderNumber: 0,
    climateProtocolId: null,
    climateProtocolStep: 0,
    climateCountryCode: climatePreferences.countryCode,
    climateSosType: "Medical emergency",
    climateSosPeople: 1,
    climateSosContact: "",
    climateBatteryPercent: null,
    climateLowBatteryMode: false,
    climateBeaconActive: false,
  };
}

function readClimatePreferences(): {
  activity: ActivityLevel;
  profiles: VulnerableProfile[];
  announcementMinutes: number;
  countryCode: string;
} {
  const fallback = { activity: "light" as ActivityLevel, profiles: [] as VulnerableProfile[], announcementMinutes: 120, countryCode: "NG" };
  try {
    const saved = JSON.parse(globalThis.localStorage?.getItem(climatePreferencesStorageKey) ?? "null") as Partial<typeof fallback> | null;
    const profiles = Array.isArray(saved?.profiles) ? saved.profiles.filter((profile): profile is VulnerableProfile => ["pregnant", "infant", "elderly", "outdoor-worker"].includes(String(profile))) : [];
    const activity = ["rest", "light", "moderate", "heavy"].includes(String(saved?.activity)) ? saved?.activity as ActivityLevel : fallback.activity;
    const announcementMinutes = typeof saved?.announcementMinutes === "number" && Number.isFinite(saved.announcementMinutes)
      ? Math.min(240, Math.max(15, saved.announcementMinutes))
      : fallback.announcementMinutes;
    return { activity, profiles, announcementMinutes, countryCode: typeof saved?.countryCode === "string" && saved.countryCode ? saved.countryCode : fallback.countryCode };
  } catch {
    return fallback;
  }
}

function readShareTarget(): { text: string; link: string } | null {
  if (typeof globalThis.location === "undefined") return null;
  try {
    const params = new URLSearchParams(globalThis.location.search);
    const text = [params.get("title") ?? "", params.get("text") ?? ""].filter(Boolean).join("\n").trim();
    const link = (params.get("url") ?? "").trim();
    return text || link ? { text, link } : null;
  } catch {
    return null;
  }
}

function message(key: MessageKey): string {
  return t(state.locale ?? "en", key);
}

function escapeHtml(value: unknown): string {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function escapeAttribute(value: unknown): string {
  return escapeHtml(value);
}

function readPreferences(): Preferences {
  try {
    const saved = JSON.parse(globalThis.localStorage?.getItem(preferencesStorageKey) ?? "null") as Partial<Preferences> | null;
    const savedTextSize = saved?.textSize;
    return {
      ...defaultPreferences,
      ...(saved ?? {}),
      textSize: savedTextSize === "small" || savedTextSize === "large" ? savedTextSize : "medium",
      speechRate: typeof saved?.speechRate === "number" && Number.isFinite(saved.speechRate)
        ? Math.min(1.5, Math.max(0.6, saved.speechRate))
        : 1,
    };
  } catch {
    return { ...defaultPreferences };
  }
}

function savePreferences(): void {
  try {
    globalThis.localStorage?.setItem(preferencesStorageKey, JSON.stringify(state.preferences));
  } catch {
    // The interface remains usable when storage is disabled.
  }
  void saveLocalSetting(preferencesStorageKey, state.preferences);
}

function readReminders(): Reminder[] {
  try {
    const saved = JSON.parse(globalThis.localStorage?.getItem(remindersStorageKey) ?? "[]") as unknown;
    if (!Array.isArray(saved)) return [];
    return saved.filter(
      (item): item is Reminder =>
        Boolean(item) && typeof item === "object" && typeof item.id === "string" && typeof item.label === "string" && typeof item.when === "string",
    );
  } catch {
    return [];
  }
}

function saveReminders(): void {
  try {
    globalThis.localStorage?.setItem(remindersStorageKey, JSON.stringify(state.reminders));
  } catch {
    // The reminder is still visible for this session.
  }
  void saveLocalSetting(remindersStorageKey, state.reminders);
}

function getReminderId(): string {
  const cryptoObject = globalThis.crypto as Crypto | undefined;
  if (cryptoObject && "randomUUID" in cryptoObject && typeof cryptoObject.randomUUID === "function") {
    return cryptoObject.randomUUID();
  }
  return `reminder-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function setDocumentLanguage(): void {
  if (typeof document !== "undefined") {
    document.documentElement.lang = state.locale ?? "en";
  }
}

function applyPreferences(): void {
  if (!mountedRoot) return;
  const root = mountedRoot;
  root.classList.toggle("easy-mode", state.preferences.easyMode);
  root.classList.toggle("high-contrast", state.preferences.highContrast);
  root.classList.toggle("dark-mode", state.preferences.darkMode);
  root.classList.toggle("reduce-motion", state.preferences.reducedMotion);
  root.classList.toggle("dyslexia-friendly", state.preferences.dyslexia);
  root.classList.toggle("text-small", state.preferences.textSize === "small");
  root.classList.toggle("text-large", state.preferences.textSize === "large");
  root.classList.toggle("low-battery-mode", state.climateLowBatteryMode);
  setDocumentLanguage();
}

function getLocaleName(locale: Locale): string {
  return LOCALE_OPTIONS.find((option) => option.code === locale)?.nativeName ?? locale;
}

function renderLanguagePicker(): string {
  const options = LOCALE_OPTIONS.map(
    (option) => `
      <button class="language-card" type="button" data-action="choose-locale" data-locale="${escapeAttribute(option.code)}" data-speak="${escapeAttribute(option.nativeName)}">
        <span>
          <strong lang="${escapeAttribute(option.code)}">${escapeHtml(option.nativeName)}</strong>
          <small>${escapeHtml(option.englishName)}</small>
        </span>
        <span class="language-check" aria-hidden="true">›</span>
      </button>`,
  ).join("");

  return `
    <div class="language-screen" data-screen="language-picker">
      <a class="skip-link" href="#main-content">${escapeHtml(message("app.skipToContent"))}</a>
      <main id="main-content" class="language-panel" tabindex="-1">
        <div class="language-intro">
          <span class="brand-mark" aria-hidden="true">✋</span>
          <div>
            <p class="eyebrow">SafeHands</p>
            <h1>${escapeHtml(message("app.chooseLanguage"))}</h1>
            <p>${escapeHtml(message("app.chooseLanguageHint"))}</p>
          </div>
        </div>
        <fieldset class="language-options" aria-label="${escapeAttribute(message("app.chooseLanguage"))}">
          <legend class="live-region">${escapeHtml(message("app.chooseLanguage"))}</legend>
          ${options}
        </fieldset>
        <p class="field-help">${escapeHtml(message("app.machineDraft"))}</p>
      </main>
    </div>`;
}

function renderHeader(): string {
  const navItems: Array<{ screen: Screen; label: MessageKey; icon: string }> = [
    { screen: "home", label: "app.home", icon: "⌂" },
    { screen: "triage", label: "app.triage", icon: "♥" },
    { screen: "scam", label: "app.scamShield", icon: "盾" },
    { screen: "climate", label: "app.name", icon: "☀" },
    { screen: "facilities", label: "app.facilities", icon: "⌖" },
    { screen: "reminders", label: "app.reminders", icon: "◷" },
    { screen: "settings", label: "app.settings", icon: "⚙" },
  ];
  const nav = navItems
    .map(
      (item) => `
        <li>
          <button type="button" data-action="navigate" data-screen="${item.screen}" aria-current="${state.screen === item.screen ? "page" : "false"}">
            <span aria-hidden="true">${item.icon}</span> ${escapeHtml(item.screen === "climate" ? "Climate" : message(item.label))}
          </button>
        </li>`,
    )
    .join("");

  return `
    <header class="app-header">
      <button class="brand-button" type="button" data-action="navigate" data-screen="home" aria-label="${escapeAttribute(message("app.home"))}">
        <span class="brand-mark" aria-hidden="true">✋</span>
        <span class="brand-copy"><strong>SafeHands</strong><small>${escapeHtml(message("app.tagline"))}</small></span>
      </button>
      <span class="offline-status" data-ready="${state.offlineReady}" role="status">
        ${escapeHtml(state.offlineReady ? message("app.offlineReady") : message("app.offlinePending"))}
      </span>
      <nav class="primary-nav" data-open="${state.navOpen}" aria-label="${escapeAttribute(message("nav.main"))}">
        <button class="nav-toggle" type="button" data-action="toggle-nav" aria-expanded="${state.navOpen}">
          <span aria-hidden="true">☰</span> ${escapeHtml(message("app.menu"))}
        </button>
        <ul class="nav-list">${nav}</ul>
      </nav>
    </header>`;
}

function renderPageHeading(title: MessageKey, subtitle: MessageKey, back = true): string {
  return `
    <div class="page-heading">
      <div>
        <h1>${escapeHtml(message(title))}</h1>
        <p>${escapeHtml(message(subtitle))}</p>
      </div>
      <div class="heading-actions">
        <button class="button button-quiet button-icon" type="button" data-action="speak" data-speak="${escapeAttribute(`${message(title)}. ${message(subtitle)}`)}">🔊 ${escapeHtml(message("app.speak"))}</button>
        ${back ? `<button class="back-link" type="button" data-action="navigate" data-screen="home">← ${escapeHtml(message("app.back"))}</button>` : ""}
      </div>
    </div>`;
}

function renderEmergencyBanner(): string {
  return `
    <section class="emergency-banner" aria-labelledby="emergency-title">
      <div>
        <h2 id="emergency-title">${escapeHtml(message("app.emergencyTitle"))}</h2>
        <p>${escapeHtml(message("app.safetyText"))}</p>
      </div>
      <div class="emergency-actions">
        <a class="button button-danger button-icon" href="tel:112">☎ ${escapeHtml(message("app.emergencyCall112"))}</a>
        <a class="button button-quiet button-icon" href="tel:108">☎ ${escapeHtml(message("app.emergencyCall108"))}</a>
      </div>
    </section>`;
}

function renderHome(): string {
  return `
    <div class="page-wrap">
      <section class="card-grid" aria-labelledby="home-title">
        <article class="card hero-card">
          <div>
            <p class="eyebrow">${escapeHtml(message("app.name"))}</p>
            <h1 id="home-title">${escapeHtml(message("home.welcome"))}</h1>
            <p>${escapeHtml(message("app.tagline"))}</p>
            <div class="action-row">
              <button class="button button-primary" type="button" data-action="navigate" data-screen="triage">${escapeHtml(message("home.startTriage"))}</button>
              <button class="button button-secondary" type="button" data-action="navigate" data-screen="scam">${escapeHtml(message("home.checkScam"))}</button>
              <button class="button button-quiet button-icon" type="button" data-action="speak" data-speak="${escapeAttribute(`${message("home.welcome")}. ${message("app.tagline")}. ${message("app.safetyText")}`)}">🔊 ${escapeHtml(message("app.speak"))}</button>
            </div>
          </div>
          <span class="hero-illustration" aria-hidden="true">✚</span>
        </article>
        <button class="action-card" type="button" data-action="navigate" data-screen="triage">
          <span class="action-icon" aria-hidden="true">♥</span>
          <h2>${escapeHtml(message("home.startTriage"))}</h2>
          <p>${escapeHtml(message("triage.subtitle"))}</p>
        </button>
        <button class="action-card" type="button" data-action="navigate" data-screen="scam">
          <span class="action-icon" aria-hidden="true">盾</span>
          <h2>${escapeHtml(message("home.checkScam"))}</h2>
          <p>${escapeHtml(message("scam.subtitle"))}</p>
        </button>
        <button class="action-card" type="button" data-action="navigate" data-screen="facilities">
          <span class="action-icon" aria-hidden="true">⌖</span>
          <h2>${escapeHtml(message("home.findCare"))}</h2>
          <p>${escapeHtml(message("facilities.subtitle"))}</p>
        </button>
        <button class="action-card" type="button" data-action="navigate" data-screen="reminders">
          <span class="action-icon" aria-hidden="true">◷</span>
          <h2>${escapeHtml(message("home.setReminder"))}</h2>
          <p>${escapeHtml(message("reminders.subtitle"))}</p>
        </button>
      </section>
      ${renderEmergencyBanner()}
      <section class="card" aria-label="Home safety tip" style="margin-top: 1rem">
        <h2 id="tip-title">${escapeHtml(message("app.safety"))}</h2>
        <p>${escapeHtml(message("home.tip"))}</p>
      </section>
    </div>`;
}

function renderItems(title: string, items: string[], ordered = false): string {
  if (!items.length) return "";
  const tag = ordered ? "ol" : "ul";
  return `<section class="result-block" aria-label="${escapeAttribute(title)}"><h3>${escapeHtml(title)}</h3><${tag}>${items
    .map((item) => `<li>${escapeHtml(item)}</li>`)
    .join("")}</${tag}></section>`;
}

function highlightMessage(text: string, matches: ScamResult["matches"]): string {
  const spans = matches
    .filter((match) => match.source === "text" && match.end > match.start)
    .map((match) => ({ start: Math.max(0, match.start), end: Math.min(text.length, match.end) }))
    .sort((left, right) => left.start - right.start || right.end - left.end);
  const pieces: string[] = [];
  let cursor = 0;
  for (const span of spans) {
    if (span.start < cursor) continue;
    pieces.push(escapeHtml(text.slice(cursor, span.start)));
    pieces.push(`<mark>${escapeHtml(text.slice(span.start, span.end))}</mark>`);
    cursor = span.end;
  }
  pieces.push(escapeHtml(text.slice(cursor)));
  return pieces.join("") || escapeHtml(text);
}

function renderTriageResult(): string {
  if (state.triagePending) {
    return `<div class="loading-note" role="status">${escapeHtml(message("triage.check"))}…</div>`;
  }
  if (!state.triageResult) return "";
  const result = state.triageResult;
  const labelKey: Record<TriageLevel, MessageKey> = {
    emergency: "triage.emergency",
    urgent: "triage.urgent",
    routine: "triage.routine",
    monitor: "triage.monitor",
  };
  const adviceKey: Record<TriageLevel, MessageKey> = {
    emergency: "triage.emergencyAdvice",
    urgent: "triage.urgentAdvice",
    routine: "triage.routineAdvice",
    monitor: "triage.monitorAdvice",
  };
  const label = result.label || message(labelKey[result.level]);
  const advice = result.advice || message(adviceKey[result.level]);
  const speechText = [
    `${message("triage.resultTitle")}: ${label}.`,
    advice,
    ...result.actionSteps,
    ...result.waitingCare,
    result.disclaimer,
  ].join(" ");
  const numbers = result.emergencyCallNumbers.length ? result.emergencyCallNumbers : ["112"];
  const callButtons = result.level === "emergency"
    ? numbers.map((number) => `<a class="button button-danger button-icon" href="tel:${escapeAttribute(number)}">☎ ${escapeHtml(message("app.call"))} ${escapeHtml(number)}</a>`).join("")
    : "";
  return `
    <section class="result-card" data-level="${escapeAttribute(result.level)}" aria-labelledby="triage-result-title" tabindex="-1">
      <div class="result-heading">
        <div>
          <p class="eyebrow">${escapeHtml(message("triage.resultTitle"))}</p>
          <h2 id="triage-result-title" tabindex="-1">${escapeHtml(result.icon ?? "")} ${escapeHtml(label)}</h2>
        </div>
        <span class="level-badge">${escapeHtml(label)}</span>
      </div>
      <p class="result-advice">${escapeHtml(advice)}</p>
      ${renderItems(message("app.why"), result.reasons)}
      ${renderItems(message("app.actionSteps"), result.actionSteps, true)}
      ${result.waitingCare.length ? renderItems("While waiting for emergency help", result.waitingCare) : ""}
      ${renderItems(message("app.doNotDo"), result.doNotDo)}
      ${renderItems(message("app.escalation"), result.escalation)}
      <p class="disclaimer"><strong>${escapeHtml(message("app.disclaimer"))}:</strong> ${escapeHtml(result.disclaimer)}</p>
      <div class="share-row">
        <button class="button button-secondary button-icon" type="button" data-action="speak" data-speak="${escapeAttribute(speechText)}">🔊 ${escapeHtml(message("app.speak"))}</button>
        <button class="button button-quiet button-icon" type="button" data-action="stop-speaking">⏹ ${escapeHtml(message("app.stopSpeaking"))}</button>
        <button class="button button-quiet" type="button" data-action="share-summary">${escapeHtml(message("share.shareSummary"))}</button>
        <button class="button button-quiet" type="button" data-action="copy-summary">${escapeHtml(message("share.copySummary"))}</button>
        ${callButtons}
        <button class="button button-quiet" type="button" data-action="new-triage">${escapeHtml(message("triage.newCheck"))}</button>
      </div>
    </section>`;
}

function renderTriage(): string {
  const symptomInputs = symptomOptions
    .map(
      (option) => `
        <label class="chip">
          <input type="checkbox" name="symptoms" value="${escapeAttribute(option.value)}" ${state.triageSymptoms.includes(option.value) ? "checked" : ""} />
          <span>${escapeHtml(message(option.label))}</span>
        </label>`,
    )
    .join("");

  return `
    <div class="page-wrap">
      ${renderPageHeading("triage.title", "triage.subtitle")}
      <form id="triage-form" class="card form-stack" novalidate>
        <fieldset class="form-stack" style="border: 0; margin: 0; padding: 0">
          <legend class="field-label">${escapeHtml(message("triage.symptoms"))}</legend>
          <p class="field-help">${escapeHtml(message("triage.tapToChoose"))}</p>
          <div class="chip-list">${symptomInputs}</div>
        </fieldset>
        <div>
          <label for="triage-description">${escapeHtml(message("triage.describe"))}</label>
          <textarea id="triage-description" name="description" data-field="triageDescription" maxlength="4000" aria-describedby="triage-voice-hint${state.triageError ? " triage-error" : ""}" placeholder="${escapeAttribute(message("triage.describePlaceholder"))}">${escapeHtml(state.triageDescription.slice(0, 4000))}</textarea>
          <div class="voice-row">
            <button class="button button-secondary button-icon" type="button" data-action="voice-input">🎙 ${escapeHtml(message("app.voiceInput"))}</button>
            <span id="triage-voice-hint" class="voice-status" data-voice-status>${escapeHtml(message("app.voiceHint"))}</span>
          </div>
        </div>
        ${state.triageError ? `<p id="triage-error" class="field-help" role="alert">${escapeHtml(state.triageError)}</p>` : ""}
        <div class="action-row">
          <button class="button button-primary" type="submit" ${state.triagePending ? "disabled" : ""}>${escapeHtml(message("triage.check"))}</button>
          <button class="button button-quiet" type="button" data-action="navigate" data-screen="settings">${escapeHtml(message("app.settings"))}</button>
        </div>
      </form>
      ${renderTriageResult()}
      ${renderEmergencyBanner()}
    </div>`;
}

function renderScamResult(): string {
  if (state.scamPending) {
    return `<div class="loading-note" role="status">${escapeHtml(message("scam.analyze"))}…</div>`;
  }
  if (!state.scamResult) return "";
  const result = state.scamResult;
  const labelKey: Record<ScamRisk, MessageKey> = {
    high: "scam.high",
    medium: "scam.medium",
    low: "scam.low",
    unknown: "scam.unknown",
  };
  const adviceKey: Record<ScamRisk, MessageKey> = {
    high: "scam.highAdvice",
    medium: "scam.mediumAdvice",
    low: "scam.lowAdvice",
    unknown: "scam.unknownAdvice",
  };
  const verdict = result.verdict ?? (result.risk === "high" ? "SCAM" : result.risk === "medium" ? "SUSPICIOUS" : "LIKELY SAFE");
  const advice = result.advice || message(adviceKey[result.risk]);
  const speechText = [`${message("scam.resultTitle")}: ${verdict}.`, advice, ...result.reasons, ...result.actions].join(" ");
  return `
    <section class="result-card" data-risk="${escapeAttribute(result.risk)}" aria-labelledby="scam-result-title" tabindex="-1">
      <div class="result-heading">
        <div>
          <p class="eyebrow">${escapeHtml(message("scam.resultTitle"))}</p>
          <h2 id="scam-result-title" tabindex="-1">${escapeHtml(verdict)}</h2>
        </div>
        <span class="level-badge">${escapeHtml(verdict)}${typeof result.score === "number" ? ` · ${escapeHtml(String(result.score))}/100` : ""}</span>
      </div>
      <p class="result-advice">${escapeHtml(advice)}</p>
      ${state.scamText ? `<section class="message-preview" aria-label="${escapeAttribute(message("app.matches"))}"><h3>${escapeHtml(message("app.matches"))}</h3><p>${highlightMessage(state.scamText, result.matches)}</p></section>` : ""}
      ${renderItems(message("app.reasons"), result.reasons)}
      ${renderItems(message("app.actions"), result.actions, true)}
      ${renderItems(message("app.reporting"), result.reporting)}
      <section class="family-warning" aria-label="${escapeAttribute(message("app.familyWarning"))}">
        <h3>${escapeHtml(message("app.familyWarning"))}</h3>
        <p>${escapeHtml(result.warnFamilyMessage)}</p>
      </section>
      <div class="share-row">
        <button class="button button-secondary button-icon" type="button" data-action="speak" data-speak="${escapeAttribute(speechText)}">🔊 ${escapeHtml(message("app.speak"))}</button>
        <button class="button button-quiet button-icon" type="button" data-action="stop-speaking">⏹ ${escapeHtml(message("app.stopSpeaking"))}</button>
        <button class="button button-quiet" type="button" data-action="share-summary">${escapeHtml(message("share.shareSummary"))}</button>
        <button class="button button-quiet" type="button" data-action="copy-summary">${escapeHtml(message("share.copySummary"))}</button>
        <button class="button button-quiet" type="button" data-action="new-scam">${escapeHtml(message("scam.newCheck"))}</button>
      </div>
    </section>`;
}

function renderScam(): string {
  const signals = scamSignalOptions
    .map(
      (option) => `
        <label class="chip">
          <input type="checkbox" name="signals" value="${escapeAttribute(option.value)}" ${state.scamSignals.includes(option.value) ? "checked" : ""} />
          <span>${escapeHtml(message(option.label))}</span>
        </label>`,
    )
    .join("");
  return `
    <div class="page-wrap">
      ${renderPageHeading("scam.title", "scam.subtitle")}
      <form id="scam-form" class="card form-stack" novalidate>
        <div>
          <label for="scam-message">${escapeHtml(message("scam.messageLabel"))}</label>
          <textarea id="scam-message" name="message" maxlength="8000" data-field="scamText" aria-describedby="scam-message-hint${state.scamError ? " scam-error" : ""}" placeholder="${escapeAttribute(message("scam.messagePlaceholder"))}">${escapeHtml(state.scamText.slice(0, 8000))}</textarea>
          <p id="scam-message-hint" class="field-help">${escapeHtml(message("app.voiceHint"))}</p>
        </div>
        <div>
          <label for="scam-link">${escapeHtml(message("scam.linkLabel"))}</label>
          <input id="scam-link" name="link" type="url" maxlength="2000" data-field="scamLink" value="${escapeAttribute(state.scamLink.slice(0, 2000))}" placeholder="${escapeAttribute(message("scam.linkPlaceholder"))}" />
        </div>
        <fieldset class="form-stack" style="border: 0; margin: 0; padding: 0">
          <legend class="field-label">${escapeHtml(message("scam.signalPrompt"))}</legend>
          <div class="chip-list">${signals}</div>
        </fieldset>
        ${state.scamError ? `<p id="scam-error" class="field-help" role="alert">${escapeHtml(state.scamError)}</p>` : ""}
        <div class="action-row">
          <button class="button button-primary" type="submit" ${state.scamPending ? "disabled" : ""}>${escapeHtml(message("scam.analyze"))}</button>
          <button class="button button-quiet" type="button" data-action="navigate" data-screen="settings">${escapeHtml(message("app.settings"))}</button>
        </div>
      </form>
      ${renderScamResult()}
      <section class="card" style="margin-top: 1rem" aria-label="Scam safety reminder">
        <h2 id="scam-safety-title">${escapeHtml(message("app.safety"))}</h2>
        <p>${escapeHtml(message("scam.highAdvice"))}</p>
      </section>
    </div>`;
}

function climateMetric(label: string, value: string, detail = ""): string {
  return `<article class="climate-metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong>${detail ? `<small>${escapeHtml(detail)}</small>` : ""}</article>`;
}

function renderClimateProtocol(): string {
  if (!state.climateProtocolId) return "";
  const protocol = climateProtocols.find((item) => item.id === state.climateProtocolId);
  if (!protocol) return "";
  const total = protocol.steps.length;
  const index = Math.min(state.climateProtocolStep, total - 1);
  const currentStep = protocol.steps[index] ?? protocol.steps[0];
  const speech = `${protocol.title}. Step ${index + 1} of ${total}. ${currentStep}`;
  return `
    <section class="card protocol-card" aria-labelledby="protocol-title">
      <div class="result-heading">
        <div><p class="eyebrow">Interactive emergency protocol</p><h2 id="protocol-title">${escapeHtml(protocol.title)}</h2></div>
        <span class="level-badge">Step ${index + 1}/${total}</span>
      </div>
      <p>${escapeHtml(protocol.summary)}</p>
      <div class="protocol-step" aria-live="polite"><strong>${escapeHtml(currentStep)}</strong></div>
      <div class="action-row">
        <button class="button button-secondary button-icon" type="button" data-action="speak" data-speak="${escapeAttribute(speech)}">🔊 Read this step</button>
        <button class="button button-primary" type="button" data-action="protocol-next" ${index >= total - 1 ? "disabled" : ""}>Next step</button>
        <button class="button button-quiet" type="button" data-action="protocol-close">Close protocol</button>
      </div>
      <div class="protocol-progress" role="progressbar" aria-label="Protocol progress" aria-valuemin="1" aria-valuemax="${total}" aria-valuenow="${index + 1}"><span style="width:${((index + 1) / total) * 100}%"></span></div>
      <section class="result-block"><h3>What not to do</h3><ul>${protocol.doNotDo.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul></section>
    </section>`;
}

function renderClimate(): string {
  const telemetry = state.climateTelemetry;
  const risk = state.climateRisk;
  const radar = telemetry ? makeRiskRadar(telemetry, state.climateProfiles) : [];
  const routes = getAuthorityRoutes().filter((route) => route.countryCode !== "DEFAULT");
  const profileOptions: Array<[VulnerableProfile, string]> = [
    ["pregnant", "Pregnant person"],
    ["infant", "Infant or young child"],
    ["elderly", "Older adult"],
    ["outdoor-worker", "Outdoor worker or driver"],
  ];
  const sosText = buildSosPayload({
    crisisType: state.climateSosType,
    people: state.climateSosPeople,
    vulnerable: state.climateProfiles,
    latitude: telemetry?.latitude,
    longitude: telemetry?.longitude,
    batteryPercent: state.climateBatteryPercent ?? undefined,
    temperatureC: telemetry?.temperatureC,
    countryCode: state.climateCountryCode,
    contact: state.climateSosContact,
  });
  const authority = getAuthorityRoute(state.climateCountryCode);
  const protocolButtons = climateProtocols.map((protocol) => `
    <button class="protocol-launch" type="button" data-action="protocol-open" data-protocol-id="${escapeAttribute(protocol.id)}">
      <strong>${escapeHtml(protocol.title)}</strong><span>${escapeHtml(protocol.summary)}</span>
    </button>`).join("");
  return `
    <div class="page-wrap climate-page">
      <div class="page-heading"><div><h1>Climate & crisis safety</h1><p>Heat, flood, smoke, hydration, first aid, and SOS tools that keep working when connectivity fails.</p></div><button class="button button-quiet button-icon" type="button" data-action="speak" data-speak="Climate and crisis safety. Heat, flood, smoke, hydration, first aid, and SOS tools.">🔊 Read aloud</button></div>
      <section class="card climate-hero ${risk?.heatRisk ?? "normal"}" aria-live="polite">
        <div>
          <p class="eyebrow">Proactive ambient safety</p>
          <h2>${escapeHtml(risk?.label ?? "No live telemetry yet")}</h2>
          <p>${escapeHtml(risk?.alerts[0] ?? "Load a local reading or request an Open-Meteo reading. Climate data is advisory and can be delayed.")}</p>
        </div>
        <div class="action-row">
          <button class="button button-primary" type="button" data-action="refresh-climate" ${state.climateLoading ? "disabled" : ""}>${state.climateLoading ? "Loading…" : "Update local weather"}</button>
          <button class="button button-secondary" type="button" data-action="sample-climate">Use sample heat alert</button>
        </div>
      </section>

      <section class="climate-grid" aria-label="Climate telemetry">
        ${climateMetric("Temperature", telemetry ? `${telemetry.temperatureC.toFixed(1)}°C` : "—", telemetry ? "Air temperature" : "No reading")}
        ${climateMetric("Feels like", risk ? `${risk.apparentTemperatureC.toFixed(1)}°C` : "—", "Apparent temperature")}
        ${climateMetric("Wet-bulb estimate", risk ? `${risk.wetBulbC.toFixed(1)}°C` : "—", "Screening estimate")}
        ${climateMetric("Humidity", telemetry ? `${Math.round(telemetry.relativeHumidity)}%` : "—")}
        ${climateMetric("PM2.5", telemetry?.pm25 !== undefined ? `${telemetry.pm25.toFixed(0)} µg/m³` : "—", "Air quality")}
        ${climateMetric("US AQI", telemetry?.usAqi !== undefined ? `${telemetry.usAqi.toFixed(0)}` : "—", "Air-quality index")}
        ${climateMetric("Pressure", telemetry?.pressureHpa !== undefined ? `${telemetry.pressureHpa.toFixed(0)} hPa` : "—", telemetry?.pressureChangeHpa !== undefined ? `${telemetry.pressureChangeHpa.toFixed(1)} hPa change` : "Sea-level pressure")}
        ${climateMetric("UV index", telemetry?.uvIndex !== undefined ? telemetry.uvIndex.toFixed(1) : "—", "Sun exposure input")}
        ${climateMetric("Soil moisture", telemetry?.soilMoisture !== undefined ? `${Math.round(telemetry.soilMoisture * 100)}%` : "—", "Ground saturation input")}
        ${climateMetric("Rain last 48h", telemetry?.precipitation48hMm !== undefined ? `${telemetry.precipitation48hMm.toFixed(0)} mm` : "—", "Recent rainfall")}
        ${climateMetric("Rain next 48h", telemetry?.precipitationNext48hMm !== undefined ? `${telemetry.precipitationNext48hMm.toFixed(0)} mm` : "—", "Flood watch input")}
      </section>
      <p class="field-help climate-attribution">Live weather and air-quality readings, when requested, use Open-Meteo and CAMS data. Manual, sample, and cached readings remain available when the service or network is unavailable.</p>

      ${telemetry ? `<section class="card" aria-labelledby="risk-radar-title"><div class="result-heading"><div><h2 id="risk-radar-title">Regional risk radar</h2><p class="field-help">A local screening view from the selected reading. It is not an official warning or a landslide forecast.</p></div><a class="button button-quiet" href="${escapeAttribute(safeZoneSearchUrl(telemetry.city ?? state.facilityCity))}" target="_blank" rel="noreferrer">Find a safer place on OpenStreetMap</a></div><div class="radar-grid">${radar.map((signal) => `<article class="radar-signal ${signal.level}"><span class="radar-icon" aria-hidden="true">${signal.level === "high" ? "!" : signal.level === "watch" ? "△" : "✓"}</span><div><strong>${escapeHtml(signal.label)}</strong><span class="radar-level">${signal.level === "high" ? "High" : signal.level === "watch" ? "Watch" : "Normal"}</span><p>${escapeHtml(signal.detail)}</p></div></article>`).join("")}</div><p class="field-help">Use official local evacuation, weather, and air-quality warnings. Verify any shelter, hospital, or community centre before travelling.</p></section>` : ""}

      <section class="settings-grid">
        <section class="card" aria-labelledby="climate-settings-title">
          <h2 id="climate-settings-title">Personal safety settings</h2>
          <label for="climate-activity">Activity level</label>
          <select id="climate-activity" data-climate-setting="activity">
            <option value="rest" ${state.climateActivity === "rest" ? "selected" : ""}>Resting</option>
            <option value="light" ${state.climateActivity === "light" ? "selected" : ""}>Light activity</option>
            <option value="moderate" ${state.climateActivity === "moderate" ? "selected" : ""}>Moderate activity</option>
            <option value="heavy" ${state.climateActivity === "heavy" ? "selected" : ""}>Heavy work or driving</option>
          </select>
          <fieldset class="climate-profiles"><legend>Protect a higher-risk person</legend>${profileOptions.map(([value, label]) => `<label class="chip"><input type="checkbox" data-profile="${value}" ${state.climateProfiles.includes(value) ? "checked" : ""}><span>${label}</span></label>`).join("")}</fieldset>
          <div class="action-row">
            <button class="button button-secondary" type="button" data-action="start-hydration">Start adaptive hydration</button>
            <button class="button button-quiet" type="button" data-action="toggle-ambient">${state.climateAnnouncementsEnabled ? "Stop ambient announcements" : "Start ambient announcements"}</button>
          </div>
          <p class="field-help">Hydration uses a conservative interval from the reading, humidity, activity, and profile. Background alerts depend on browser notification permission and may be delayed when the OS suspends a tab.</p>
          ${state.hydrationPlan ? `<p class="climate-status" role="status">Next hydration reminder in ${state.hydrationPlan.intervalMinutes} minutes. ${escapeHtml(state.hydrationPlan.message)}</p>` : ""}
        </section>
        <section class="card" aria-labelledby="climate-manual-title">
          <h2 id="climate-manual-title">Offline manual reading</h2>
          <form id="climate-manual-form" class="form-stack">
            <label for="climate-temperature">Temperature °C</label><input id="climate-temperature" name="temperature" type="number" step="0.1" min="-30" max="60" value="${escapeAttribute(telemetry?.temperatureC ?? 35)}" required>
            <label for="climate-humidity">Relative humidity %</label><input id="climate-humidity" name="humidity" type="number" step="1" min="1" max="100" value="${escapeAttribute(telemetry?.relativeHumidity ?? 70)}" required>
            <label for="climate-wind">Wind km/h</label><input id="climate-wind" name="wind" type="number" step="0.1" min="0" max="200" value="${escapeAttribute(telemetry?.windSpeedKmh ?? 5)}">
            <button class="button button-primary" type="submit">Calculate heat risk offline</button>
          </form>
        </section>
      </section>

      ${risk?.alerts.length ? `<section class="card climate-alerts" aria-labelledby="climate-alert-title"><h2 id="climate-alert-title">Active warnings</h2><ul>${risk.alerts.map((alert) => `<li>${escapeHtml(alert)}</li>`).join("")}</ul><p><strong>First aid prompt:</strong> ${escapeHtml(risk.firstAidPrompt)}</p></section>` : ""}

      ${renderClimateProtocol()}
      <section class="card" aria-labelledby="protocol-list-title"><h2 id="protocol-list-title">Offline emergency action protocols</h2><p class="field-help">These steps open instantly from the bundled app. Call emergency services first for immediate danger.</p><div class="protocol-list">${protocolButtons}</div></section>

      <section class="settings-grid">
        <section class="card" aria-labelledby="sos-title">
          <h2 id="sos-title">Community SOS dispatch</h2>
          <label for="sos-type">Crisis type</label><select id="sos-type" data-climate-setting="sosType"><option ${state.climateSosType === "Medical emergency" ? "selected" : ""}>Medical emergency</option><option ${state.climateSosType === "Heatstroke" ? "selected" : ""}>Heatstroke</option><option ${state.climateSosType === "Flood trapped" ? "selected" : ""}>Flood trapped</option><option ${state.climateSosType === "Wildfire smoke" ? "selected" : ""}>Wildfire smoke</option><option ${state.climateSosType === "Structural collapse" ? "selected" : ""}>Structural collapse</option></select>
          <label for="sos-people">People needing help</label><input id="sos-people" type="number" min="1" max="100" value="${escapeAttribute(state.climateSosPeople)}" data-climate-setting="sosPeople">
          <label for="sos-contact">Emergency contact number (optional)</label><input id="sos-contact" type="tel" value="${escapeAttribute(state.climateSosContact)}" data-climate-setting="sosContact" placeholder="+234…">
          <p class="field-help">${escapeHtml(authority.notes)} Battery: ${state.climateBatteryPercent === null ? "unknown" : `${Math.round(state.climateBatteryPercent)}%`}.</p>
          <div class="action-row"><a class="button button-danger" href="tel:${escapeAttribute(authority.emergencyNumbers[0])}">Call ${escapeHtml(authority.emergencyNumbers[0])}</a><a class="button button-secondary" href="${escapeAttribute(`sms:${state.climateSosContact}?body=${encodeURIComponent(sosText)}`)}">Send SOS SMS</a><a class="button button-quiet" href="${escapeAttribute(`whatsapp://send?text=${encodeURIComponent(sosText)}`)}">Share to WhatsApp</a></div>
          <details><summary>Show SOS text</summary><pre class="sos-preview">${escapeHtml(sosText)}</pre></details>
        </section>
        <section class="card" aria-labelledby="beacon-title">
          <h2 id="beacon-title">Rescue beacon</h2>
          <p>Starts a visible non-flashing high-contrast beacon and a short 3000 Hz intermittent tone. Browser volume and device restrictions apply. Stop if it harms hearing or triggers discomfort.</p>
          <div class="beacon-preview ${state.climateBeaconActive ? "active" : ""}" aria-live="polite">${state.climateBeaconActive ? "BEACON ACTIVE" : "Beacon ready"}</div>
          <div class="action-row"><button class="button button-danger" type="button" data-action="toggle-beacon">${state.climateBeaconActive ? "Stop beacon" : "Start beacon"}</button><select data-climate-setting="country" aria-label="Emergency country">${routes.map((route) => `<option value="${route.countryCode}" ${state.climateCountryCode === route.countryCode ? "selected" : ""}>${escapeHtml(route.countryName)}</option>`).join("")}</select></div>
        </section>
      </section>

      ${state.climateError ? `<p class="field-help" role="alert">${escapeHtml(state.climateError)}</p>` : ""}
      ${state.climateLowBatteryMode ? `<section class="card low-battery-notice" role="status"><h2>Low-battery mode</h2><p>Animations and nonessential ambient checks are reduced. Keep this screen open for the emergency protocols, call controls, and SOS text.</p></section>` : ""}
    </div>`;
}

function renderFacilities(): string {
  const cityOptions = Array.from(new Map(seededFacilities.map((facility) => [facility.city, `${facility.city}, ${facility.country}`])).entries());
  const localFacilities = state.facilityLocation
    ? seededFacilities
      .filter((facility) => typeof facility.latitude === "number" && typeof facility.longitude === "number")
      .slice()
      .sort((left, right) => distanceKm(state.facilityLocation!, left) - distanceKm(state.facilityLocation!, right))
    : getFacilities({ city: state.facilityCity });
  const mapUrl = (facility: Facility): string => `https://www.openstreetmap.org/search?query=${encodeURIComponent(facility.address)}`;
  return `
    <div class="page-wrap">
      ${renderPageHeading("facilities.title", "facilities.subtitle")}
      <section class="card" aria-labelledby="facilities-list-title">
        <h2 id="facilities-list-title">${escapeHtml(message("facilities.nearest"))}</h2>
        <p class="field-help">${escapeHtml(message("facilities.offlineNote"))}</p>
        <label for="facility-city">${escapeHtml(message("app.city"))}</label>
        <select id="facility-city" data-setting="facilityCity">
          ${cityOptions.map(([city, label]) => `<option value="${escapeAttribute(city)}" ${city === state.facilityCity ? "selected" : ""}>${escapeHtml(label)}</option>`).join("")}
        </select>
        <button class="button button-secondary button-icon" type="button" data-action="use-location">⌖ ${escapeHtml(message("facilities.useLocation"))}</button>
        <p class="field-help" role="status">${escapeHtml(state.facilityLocationMessage || message("facilities.locationStatus"))}</p>
        <ul class="facility-list">
          ${localFacilities.length ? localFacilities
            .map(
              (facility: Facility) => `
                <li class="facility-item">
                  <div>
                    <p class="eyebrow">${escapeHtml(facility.label)}</p>
                    <h3>${escapeHtml(facility.name)}</h3>
                    <p>${escapeHtml(facility.address)}</p>
                    <p class="small-text muted">${escapeHtml(facility.notes ?? "")}</p>
                    <div class="facility-meta"><span>${escapeHtml(message("facilities.call"))}: ${escapeHtml(facility.phone ?? `Emergency ${facility.emergencyCallNumbers.join(" / ")}`)}</span><span>${escapeHtml(facility.dataStatus === "sample" ? "Sample directory data" : "Seed directory data")}</span>${state.facilityLocation ? `<span>≈ ${escapeHtml(distanceKm(state.facilityLocation, facility).toFixed(1))} km</span>` : ""}</div>
                  </div>
                  <div class="action-row">
                    <a class="button button-secondary" href="${escapeAttribute(facility.phone ? `tel:${facility.phone}` : `tel:${facility.emergencyCallNumbers[0] ?? "112"}`)}">☎ ${escapeHtml(message("facilities.call"))}</a>
                    <a class="button button-quiet" href="${escapeAttribute(mapUrl(facility))}" target="_blank" rel="noreferrer">⌖ ${escapeHtml(message("app.map"))}</a>
                  </div>
                </li>`,
            )
            .join("") : `<li class="facility-item"><p>${escapeHtml(message("facilities.offlineNote"))}</p></li>`}
        </ul>
      </section>
      ${renderEmergencyBanner()}
    </div>`;
}

function distanceKm(point: { latitude: number; longitude: number }, facility: Facility): number {
  if (typeof facility.latitude !== "number" || typeof facility.longitude !== "number") return Number.POSITIVE_INFINITY;
  const radians = (value: number): number => (value * Math.PI) / 180;
  const dLat = radians(facility.latitude - point.latitude);
  const dLon = radians(facility.longitude - point.longitude);
  const a = Math.sin(dLat / 2) ** 2
    + Math.cos(radians(point.latitude)) * Math.cos(radians(facility.latitude)) * Math.sin(dLon / 2) ** 2;
  return 6371 * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function formatReminder(when: string): string {
  const date = new Date(when);
  if (Number.isNaN(date.valueOf())) return when;
  try {
    return new Intl.DateTimeFormat(state.locale ?? "en", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "numeric",
      minute: "2-digit",
    }).format(date);
  } catch {
    return date.toLocaleString();
  }
}

function renderReminders(): string {
  const reminders = state.reminders
    .slice()
    .sort((a, b) => a.when.localeCompare(b.when))
    .map(
      (reminder) => `
        <li class="reminder-item">
          <div>
            <h3>${escapeHtml(reminder.label)}</h3>
            <p>${escapeHtml(formatReminder(reminder.when))}</p>
          </div>
          <button class="button button-quiet" type="button" data-action="remove-reminder" data-reminder-id="${escapeAttribute(reminder.id)}">${escapeHtml(message("reminders.remove"))}</button>
        </li>`,
    )
    .join("");
  return `
    <div class="page-wrap">
      ${renderPageHeading("reminders.title", "reminders.subtitle")}
      <div class="form-grid">
        <form id="reminder-form" class="card form-stack" novalidate>
          <div>
            <label for="reminder-label">${escapeHtml(message("reminders.label"))}</label>
            <input id="reminder-label" name="label" type="text" maxlength="120" required placeholder="${escapeAttribute(message("home.setReminder"))}" />
          </div>
          <div>
            <label for="reminder-when">${escapeHtml(message("reminders.when"))}</label>
            <input id="reminder-when" name="when" type="datetime-local" required />
          </div>
          <button class="button button-primary" type="submit">${escapeHtml(message("reminders.add"))}</button>
          <button class="button button-quiet" type="button" data-action="enable-notifications">🔔 ${escapeHtml(message("app.enableNotifications"))}</button>
        </form>
        <section class="card" aria-labelledby="reminders-list-title">
          <h2 id="reminders-list-title">${escapeHtml(message("reminders.title"))}</h2>
          ${reminders ? `<ul class="reminder-list">${reminders}</ul>` : `<p class="muted">${escapeHtml(message("reminders.empty"))}</p>`}
        </section>
      </div>
    </div>`;
}

function renderSettings(): string {
  const optionMarkup = LOCALE_OPTIONS.map(
    (option) => `<option value="${escapeAttribute(option.code)}" ${state.locale === option.code ? "selected" : ""}>${escapeHtml(option.nativeName)} · ${escapeHtml(option.englishName)}</option>`,
  ).join("");
  const toggle = (name: keyof Preferences, label: MessageKey): string => `
    <li class="setting-row">
      <label for="setting-${name}">${escapeHtml(message(label))}</label>
      <label class="toggle" for="setting-${name}">
        <input id="setting-${name}" type="checkbox" data-setting="${name}" ${state.preferences[name] === true ? "checked" : ""} />
        <span class="toggle-indicator" aria-hidden="true"></span>
      </label>
    </li>`;

  return `
    <div class="page-wrap">
      ${renderPageHeading("settings.title", "settings.subtitle")}
      <div class="settings-grid">
        <section class="card" aria-labelledby="settings-language-title">
          <h2 id="settings-language-title">${escapeHtml(message("settings.language"))}</h2>
          <label for="setting-language">${escapeHtml(message("settings.language"))}</label>
          <select id="setting-language" data-setting="language">${optionMarkup}</select>
          <p class="field-help">${escapeHtml(message("app.machineDraft"))}</p>
        </section>
        <section class="card" aria-labelledby="settings-appearance-title">
          <h2 id="settings-appearance-title">${escapeHtml(message("settings.appearance"))}</h2>
          <ul class="setting-list">
            ${toggle("easyMode", "app.easyMode")}
            ${toggle("darkMode", "app.darkMode")}
            ${toggle("highContrast", "app.highContrast")}
            ${toggle("reducedMotion", "app.reducedMotion")}
            ${toggle("dyslexia", "app.dyslexia")}
            <li class="setting-row">
              <label for="setting-textSize">${escapeHtml(message("app.textSize"))}</label>
              <select id="setting-textSize" data-setting="textSize">
                <option value="small" ${state.preferences.textSize === "small" ? "selected" : ""}>${escapeHtml(message("app.textSmall"))}</option>
                <option value="medium" ${state.preferences.textSize === "medium" ? "selected" : ""}>${escapeHtml(message("app.textMedium"))}</option>
                <option value="large" ${state.preferences.textSize === "large" ? "selected" : ""}>${escapeHtml(message("app.textLarge"))}</option>
              </select>
            </li>
            <li class="setting-row">
              <label for="setting-speechRate">${escapeHtml(message("app.speechRate"))}</label>
              <input id="setting-speechRate" type="range" min="0.6" max="1.5" step="0.1" value="${escapeAttribute(state.preferences.speechRate)}" data-setting="speechRate" aria-valuemin="0.6" aria-valuemax="1.5" aria-valuenow="${escapeAttribute(state.preferences.speechRate)}" />
            </li>
          </ul>
        </section>
        <section class="card" aria-labelledby="settings-about-title">
          <h2 id="settings-about-title">${escapeHtml(message("settings.about"))}</h2>
          <p>${escapeHtml(message("app.privacyText"))}</p>
          <p>${escapeHtml(message("app.safetyText"))}</p>
          <p class="small-text muted">${escapeHtml(message("settings.version"))}</p>
        </section>
        <section class="card" aria-label="Settings translation status">
          <h2 id="settings-translation-title">${escapeHtml(message("settings.translationStatus"))}</h2>
          <p>${escapeHtml(message("app.machineDraft"))}</p>
        </section>
      </div>
    </div>`;
}

function renderFooter(): string {
  return `
    <footer class="app-footer">
      <div class="footer-grid">
        <section aria-labelledby="privacy-title">
          <h2 id="privacy-title">${escapeHtml(message("app.privacy"))}</h2>
          <p>${escapeHtml(message("app.privacyText"))}</p>
        </section>
        <section aria-labelledby="safety-title">
          <h2 id="safety-title">${escapeHtml(message("app.safety"))}</h2>
          <p>${escapeHtml(message("app.safetyText"))}</p>
        </section>
        <section aria-labelledby="translation-title">
          <h2 id="translation-title">${escapeHtml(message("settings.translationStatus"))}</h2>
          <p>${escapeHtml(message("app.machineDraft"))}</p>
        </section>
      </div>
    </footer>`;
}

function renderCurrentScreen(): string {
  switch (state.screen) {
    case "triage":
      return renderTriage();
    case "scam":
      return renderScam();
    case "climate":
      return renderClimate();
    case "facilities":
      return renderFacilities();
    case "reminders":
      return renderReminders();
    case "settings":
      return renderSettings();
    case "home":
    default:
      return renderHome();
  }
}

export function renderApp(target?: HTMLElement): HTMLElement | null {
  const root = target ?? mountedRoot ?? (typeof document !== "undefined" ? document.getElementById("app") : null);
  if (!root) return null;
  mountedRoot = root;
  installEvents(root);
  if (!state.locale) {
    root.innerHTML = renderLanguagePicker();
  } else {
    root.innerHTML = `
      <div class="app-shell">
        <a class="skip-link" href="#main-content">${escapeHtml(message("app.skipToContent"))}</a>
        ${renderHeader()}
        <main id="main-content" tabindex="-1" data-screen="${escapeAttribute(state.screen)}">
          <div class="live-region" role="status" aria-live="polite" aria-atomic="true">${escapeHtml(state.liveMessage || message("live.ready"))}</div>
          ${renderCurrentScreen()}
        </main>
        ${renderFooter()}
      </div>`;
  }
  applyPreferences();
  scheduleAllReminders();
  return root;
}

function installEvents(root: HTMLElement): void {
  if (root.dataset.eventsBound === "true") return;
  root.dataset.eventsBound = "true";
  root.addEventListener("click", (event) => handleClick(event, root));
  root.addEventListener("submit", (event) => handleSubmit(event as SubmitEvent, root));
  root.addEventListener("input", (event) => handleInput(event));
  root.addEventListener("change", (event) => handleChange(event, root));
}

function announce(text: string): void {
  state.liveMessage = text;
  const live = mountedRoot?.querySelector<HTMLElement>(".live-region[role='status']");
  if (live) live.textContent = text;
}

function navigate(screen: Screen): void {
  state.screen = screen;
  state.navOpen = false;
  state.liveMessage = message("live.ready");
  renderApp();
  mountedRoot?.querySelector<HTMLElement>("#main-content")?.focus({ preventScroll: true });
}

function handleClick(event: Event, root: HTMLElement): void {
  const target = event.target as HTMLElement | null;
  const control = target?.closest<HTMLElement>("[data-action]");
  if (!control || !root.contains(control)) return;
  const action = control.dataset.action;
  switch (action) {
    case "choose-locale": {
      const locale = control.dataset.locale;
      if (!isLocale(locale)) return;
      state.locale = locale;
      saveLocale(locale);
      state.screen = state.scamText || state.scamLink ? "scam" : "home";
      state.liveMessage = t(locale, "live.languageChanged");
      renderApp();
      speakText(control.dataset.speak ?? getLocaleName(locale));
      mountedRoot?.querySelector<HTMLElement>("#main-content")?.focus({ preventScroll: true });
      break;
    }
    case "navigate": {
      const screen = control.dataset.screen;
      if (screen === "home" || screen === "triage" || screen === "scam" || screen === "climate" || screen === "facilities" || screen === "reminders" || screen === "settings") {
        navigate(screen);
      }
      break;
    }
    case "toggle-nav":
      state.navOpen = !state.navOpen;
      renderApp();
      break;
    case "voice-input":
      startVoiceInput();
      break;
    case "speak":
      speakText(control.dataset.speak ?? "");
      break;
    case "stop-speaking":
      stopSpeaking();
      break;
    case "enable-notifications":
      void enableNotifications();
      break;
    case "use-location":
      requestFacilityLocation();
      break;
    case "refresh-climate":
      void refreshClimateTelemetry();
      break;
    case "sample-climate":
      setSampleClimateTelemetry();
      break;
    case "start-hydration":
      startHydrationPlan();
      break;
    case "toggle-ambient":
      toggleAmbientAnnouncements();
      break;
    case "protocol-open":
      state.climateProtocolId = control.dataset.protocolId ?? null;
      state.climateProtocolStep = 0;
      renderApp();
      break;
    case "protocol-next":
      state.climateProtocolStep += 1;
      renderApp();
      break;
    case "protocol-close":
      state.climateProtocolId = null;
      state.climateProtocolStep = 0;
      renderApp();
      break;
    case "toggle-beacon":
      toggleRescueBeacon();
      break;
    case "share-summary":
      void shareSummary();
      break;
    case "copy-summary":
      void copySummary();
      break;
    case "new-triage":
      state.triageResult = null;
      state.triageError = "";
      state.triageSymptoms = [];
      state.triageDescription = "";
      renderApp();
      break;
    case "new-scam":
      state.scamResult = null;
      state.scamError = "";
      state.scamSignals = [];
      state.scamText = "";
      state.scamLink = "";
      renderApp();
      break;
    case "remove-reminder": {
      const id = control.dataset.reminderId;
      if (!id) return;
      state.reminders = state.reminders.filter((reminder) => reminder.id !== id);
      const timer = reminderTimers.get(id);
      if (timer !== undefined && typeof window !== "undefined") window.clearTimeout(timer);
      reminderTimers.delete(id);
      saveReminders();
      state.liveMessage = message("live.ready");
      renderApp();
      break;
    }
    default:
      break;
  }
}

function handleInput(event: Event): void {
  const target = event.target as HTMLInputElement | HTMLTextAreaElement | null;
  if (!target) return;
  if (target.dataset.field === "triageDescription") state.triageDescription = target.value.slice(0, 4000);
  if (target.dataset.field === "scamText") state.scamText = target.value.slice(0, 8000);
  if (target.dataset.field === "scamLink") state.scamLink = target.value.slice(0, 2000);
  if (target.dataset.climateSetting === "sosContact") state.climateSosContact = target.value.slice(0, 80);
  if (target.dataset.climateSetting === "sosPeople") state.climateSosPeople = Math.max(1, Number(target.value) || 1);
}

function handleChange(event: Event, root: HTMLElement): void {
  const target = event.target as HTMLInputElement | HTMLSelectElement | null;
  if (!target) return;
  if (target.name === "symptoms" && target instanceof HTMLInputElement) {
    state.triageSymptoms = Array.from(root.querySelectorAll<HTMLInputElement>("input[name='symptoms']:checked")).map((input) => input.value);
    return;
  }
  if (target.name === "signals" && target instanceof HTMLInputElement) {
    state.scamSignals = Array.from(root.querySelectorAll<HTMLInputElement>("input[name='signals']:checked")).map((input) => input.value);
    return;
  }
  if (target.dataset.profile && target instanceof HTMLInputElement) {
    const profile = target.dataset.profile as VulnerableProfile;
    state.climateProfiles = target.checked
      ? Array.from(new Set([...state.climateProfiles, profile]))
      : state.climateProfiles.filter((item) => item !== profile);
    if (state.climateTelemetry) state.climateRisk = calculateClimateRisk(state.climateTelemetry);
    saveClimatePreferences();
    renderApp();
    return;
  }
  const climateSetting = target.dataset.climateSetting;
  if (climateSetting) {
    if (climateSetting === "activity" && ["rest", "light", "moderate", "heavy"].includes(target.value)) state.climateActivity = target.value as ActivityLevel;
    if (climateSetting === "country") state.climateCountryCode = target.value;
    if (climateSetting === "sosType") state.climateSosType = target.value;
    if (climateSetting === "sosPeople") state.climateSosPeople = Math.max(1, Number(target.value) || 1);
    if (climateSetting === "sosContact") state.climateSosContact = target.value.slice(0, 80);
    if (state.climateTelemetry) state.hydrationPlan = makeHydrationPlan({ now: new Date(), temperatureC: state.climateTelemetry.temperatureC, relativeHumidity: state.climateTelemetry.relativeHumidity, activity: state.climateActivity, vulnerableProfiles: state.climateProfiles, reminderNumber: Math.max(1, state.hydrationReminderNumber) });
    saveClimatePreferences();
    renderApp();
    return;
  }
  const setting = target.dataset.setting as keyof Preferences | "language" | "facilityCity" | undefined;
  if (!setting) return;
  if (setting === "facilityCity" && target instanceof HTMLSelectElement) {
    state.facilityCity = target.value;
    state.facilityLocation = null;
    state.facilityLocationMessage = "";
    renderApp();
    return;
  }
  if (setting === "language" && isLocale(target.value)) {
    state.locale = target.value;
    saveLocale(target.value);
    state.liveMessage = message("live.languageChanged");
    renderApp();
    return;
  }
  if (setting === "textSize" && (target.value === "small" || target.value === "medium" || target.value === "large")) {
    state.preferences.textSize = target.value;
  } else if (setting === "speechRate" && target instanceof HTMLInputElement) {
    const rate = Number(target.value);
    state.preferences.speechRate = Number.isFinite(rate) ? Math.min(1.5, Math.max(0.6, rate)) : 1;
  } else if (setting in state.preferences && target instanceof HTMLInputElement) {
    const preference = setting as "easyMode" | "highContrast" | "darkMode" | "reducedMotion" | "dyslexia";
    state.preferences[preference] = target.checked;
  }
  savePreferences();
  applyPreferences();
  announce(message("live.ready"));
}

function handleSubmit(event: SubmitEvent, root: HTMLElement): void {
  const form = event.target as HTMLFormElement | null;
  if (!form) return;
  if (form.id === "triage-form") {
    event.preventDefault();
    void submitTriage(form);
  } else if (form.id === "scam-form") {
    event.preventDefault();
    void submitScam(form);
  } else if (form.id === "reminder-form") {
    event.preventDefault();
    submitReminder(form, root);
  } else if (form.id === "climate-manual-form") {
    event.preventDefault();
    applyManualClimateReading(form);
  }
}

async function submitTriage(form: HTMLFormElement): Promise<void> {
  const formData = new FormData(form);
  state.triageSymptoms = formData.getAll("symptoms").map(String);
  state.triageDescription = String(formData.get("description") ?? "").trim().slice(0, 4000);
  state.triageError = "";
  if (state.triageSymptoms.length === 0 && !state.triageDescription) {
    state.triageError = message("triage.noSymptoms");
    state.liveMessage = state.triageError;
    renderApp();
    return;
  }
  state.triagePending = true;
  state.triageResult = null;
  renderApp();
  const result = await evaluateTriage({
    symptoms: state.triageSymptoms,
    description: state.triageDescription,
    locale: state.locale ?? "en",
  });
  if (state.screen !== "triage") return;
  state.triagePending = false;
  state.triageResult = result;
  state.liveMessage = `${message("triage.resultTitle")}: ${result.advice}`;
  renderApp();
  if (result.level === "emergency") {
    if (typeof navigator !== "undefined" && "vibrate" in navigator) navigator.vibrate?.([220, 100, 220]);
    if (state.preferences.easyMode) speakText(`${result.label ?? message("triage.emergency")}. ${result.advice} ${result.disclaimer}`);
  }
  mountedRoot?.querySelector<HTMLElement>("#triage-result-title")?.focus({ preventScroll: true });
}

async function submitScam(form: HTMLFormElement): Promise<void> {
  const formData = new FormData(form);
  state.scamSignals = formData.getAll("signals").map(String);
  state.scamText = String(formData.get("message") ?? "").trim().slice(0, 8000);
  state.scamLink = String(formData.get("link") ?? "").trim().slice(0, 2000);
  state.scamError = "";
  if (state.scamSignals.length === 0 && !state.scamText && !state.scamLink) {
    state.scamError = message("scam.subtitle");
    state.liveMessage = state.scamError;
    renderApp();
    return;
  }
  state.scamPending = true;
  state.scamResult = null;
  renderApp();
  const result = await evaluateScam({
    text: state.scamText,
    link: state.scamLink,
    signals: state.scamSignals,
    locale: state.locale ?? "en",
  });
  if (state.screen !== "scam") return;
  state.scamPending = false;
  state.scamResult = result;
  state.liveMessage = `${message("scam.resultTitle")}: ${result.advice}`;
  renderApp();
  mountedRoot?.querySelector<HTMLElement>("#scam-result-title")?.focus({ preventScroll: true });
}

function submitReminder(form: HTMLFormElement, root: HTMLElement): void {
  const formData = new FormData(form);
  const label = String(formData.get("label") ?? "").trim();
  const when = String(formData.get("when") ?? "").trim();
  if (!label || !when || Number.isNaN(new Date(when).valueOf())) {
    announce(message("error.generic"));
    return;
  }
  state.reminders = [...state.reminders, { id: getReminderId(), label, when }];
  saveReminders();
  state.liveMessage = message("live.reminderAdded");
  renderApp(root);
}

async function loadOptionalModule(path: string, cache: "triage" | "scam"): Promise<OptionalModule | null> {
  const existing = cache === "triage" ? triageModulePromise : scamModulePromise;
  if (existing) return existing;
  const promise = import(/* @vite-ignore */ path)
    .then((module) => module as OptionalModule)
    .catch(() => null);
  if (cache === "triage") triageModulePromise = promise;
  else scamModulePromise = promise;
  return promise;
}

function findFunction(module: OptionalModule | null, names: string[]): ((...args: any[]) => unknown) | null {
  if (!module) return null;
  for (const name of names) {
    const candidate = module[name];
    if (typeof candidate === "function") return candidate as (...args: any[]) => unknown;
  }
  const defaultExport = module.default;
  if (typeof defaultExport === "function") return defaultExport as (...args: any[]) => unknown;
  if (defaultExport && typeof defaultExport === "object") {
    for (const name of names) {
      const candidate = (defaultExport as Record<string, unknown>)[name];
      if (typeof candidate === "function") return candidate as (...args: any[]) => unknown;
    }
  }
  return null;
}

function pickString(value: unknown, keys: string[]): string {
  if (!value || typeof value !== "object") return "";
  const object = value as Record<string, unknown>;
  for (const key of keys) {
    if (typeof object[key] === "string" && object[key]) return object[key] as string;
  }
  return "";
}

function pickStringList(value: unknown, keys: string[]): string {
  if (!value || typeof value !== "object") return "";
  const object = value as Record<string, unknown>;
  for (const key of keys) {
    if (Array.isArray(object[key])) {
      const items = object[key].filter((item): item is string => typeof item === "string" && item.trim().length > 0);
      if (items.length) return items.slice(0, 2).join(" ");
    }
  }
  return "";
}

function pickLevel(value: unknown): TriageLevel | null {
  const raw = typeof value === "string" ? value : pickString(value, ["level", "urgency", "priority", "severity", "category"]);
  const normalized = raw.toLowerCase();
  if (normalized.includes("emerg") || normalized.includes("critical") || normalized.includes("immediate")) return "emergency";
  if (normalized.includes("urgent") || normalized.includes("soon") || normalized.includes("high")) return "urgent";
  if (normalized.includes("routine") || normalized.includes("clinic") || normalized.includes("moderate")) return "routine";
  if (normalized.includes("monitor") || normalized.includes("home") || normalized.includes("low")) return "monitor";
  return null;
}

function pickRisk(value: unknown): ScamRisk | null {
  const raw = typeof value === "string" ? value : pickString(value, ["risk", "level", "severity", "verdict", "category"]);
  const normalized = raw.toLowerCase();
  if (normalized.includes("high") || normalized.includes("critical") || normalized.includes("scam") || normalized.includes("likely")) return "high";
  if (normalized.includes("medium") || normalized.includes("possible") || normalized.includes("suspicious")) return "medium";
  if (normalized.includes("low") || normalized.includes("safe")) return "low";
  if (normalized.includes("unknown") || normalized.includes("uncertain")) return "unknown";
  if (typeof value === "object" && value) {
    const score = (value as Record<string, unknown>).score;
    if (typeof score === "number") {
      if (score >= 0.7) return "high";
      if (score >= 0.35) return "medium";
      return "low";
    }
  }
  return null;
}

function adviceForTriage(level: TriageLevel): string {
  const keys: Record<TriageLevel, MessageKey> = {
    emergency: "triage.emergencyAdvice",
    urgent: "triage.urgentAdvice",
    routine: "triage.routineAdvice",
    monitor: "triage.monitorAdvice",
  };
  return message(keys[level]);
}

function adviceForRisk(risk: ScamRisk): string {
  const keys: Record<ScamRisk, MessageKey> = {
    high: "scam.highAdvice",
    medium: "scam.mediumAdvice",
    low: "scam.lowAdvice",
    unknown: "scam.unknownAdvice",
  };
  return message(keys[risk]);
}

function fallbackTriage(symptoms: string[], description: string): TriageResult {
  const symptomSet = new Set(symptoms);
  const words = description.toLowerCase();
  const activeChestPain = /chest\s+pain/.test(words) && !/(?:no|not|don't|do\s+not|without)\s+(?:have\s+)?chest\s+pain/.test(words);
  const textEmergency = activeChestPain || /cannot\s+breathe|can't\s+breathe|trouble\s+breathing|shortness?\s+of\s+breath|heavy\s+bleed|not\s+respond|unconscious|fainted|stroke|blue\s+(?:lips?|face)/.test(words);
  const textUrgent = /severe\s+pain|high\s+fever|stiff\s+neck|pregnan|allerg|vomit|confus/.test(words);
  let level: TriageLevel = "monitor";
  if ([...emergencySymptoms].some((symptom) => symptomSet.has(symptom)) || textEmergency) level = "emergency";
  else if (symptomSet.has("severePain") || symptomSet.has("fever") || symptomSet.has("pregnancy") || textUrgent) level = "urgent";
  else if (symptomSet.has("other") || description) level = "routine";
  return {
    level,
    advice: adviceForTriage(level),
    reasons: ["This is a conservative local fallback."],
    actionSteps: [adviceForTriage(level)],
    doNotDo: ["Do not use this result to rule out a serious problem."],
    escalation: ["Call local emergency services for worsening or dangerous symptoms."],
    waitingCare: [],
    emergencyCallNumbers: ["112"],
    disclaimer: "SafeHands is a guide, not a diagnosis.",
    shareSummary: `SafeHands triage: ${level}. ${adviceForTriage(level)}`,
    matchedPresentations: [],
    matchedRedFlags: [],
  };
}

function higherTriage(left: TriageLevel, right: TriageLevel): TriageLevel {
  const rank: Record<TriageLevel, number> = { emergency: 3, urgent: 2, routine: 1, monitor: 0 };
  return rank[left] >= rank[right] ? left : right;
}

async function evaluateTriage(input: { symptoms: string[]; description: string; locale: Locale }): Promise<TriageResult> {
  const countryCode = input.locale === "hi" ? "IN" : input.locale === "pcm" || input.locale === "yo" || input.locale === "ha" ? "NG" : undefined;
  const output: EngineTriageResult = triageEngine(
    { symptoms: input.symptoms, description: input.description },
    countryCode ? { countryCode } : {},
  );
  const level: TriageLevel = output.urgency === "self-care" ? "monitor" : output.urgency;
  return {
    level,
    urgency: output.urgency,
    label: output.label,
    icon: output.icon,
    advice: output.advice,
    detail: output.detail,
    reasons: output.reasons,
    actionSteps: output.actionSteps,
    doNotDo: output.doNotDo,
    escalation: output.escalation,
    waitingCare: output.waitingCare,
    emergencyCallNumbers: output.emergencyCallNumbers,
    disclaimer: output.disclaimer,
    shareSummary: output.shareSummary,
    matchedPresentations: output.matchedPresentations,
    matchedRedFlags: output.matchedRedFlags,
  };
}

function fallbackScam(text: string, signals: string[]): ScamResult {
  const haystack = text.toLowerCase();
  const detected = new Set(signals);
  if (/one[- ]?time|otp|pin|password|code/.test(haystack)) detected.add("otp");
  if (/send|pay|transfer|money|fee|account/.test(haystack)) detected.add("payment");
  if (/urgent|now|immediately|last chance|expire/.test(haystack)) detected.add("urgency");
  const risk: ScamRisk = detected.size >= 3 || (detected.has("otp") && detected.has("payment"))
    ? "high"
    : detected.size >= 1
      ? "medium"
      : text.trim()
        ? "low"
        : "unknown";
  return {
    risk,
    verdict: risk === "high" ? "SCAM" : risk === "medium" ? "SUSPICIOUS" : "LIKELY SAFE",
    score: risk === "high" ? 70 : risk === "medium" ? 35 : 0,
    advice: adviceForRisk(risk),
    reasons: ["This is a conservative local fallback."],
    matchedPhrases: [],
    matches: [],
    actions: ["Do not share secrets or pay until you verify the sender independently."],
    reporting: [],
    warnFamilyMessage: "Warn a trusted person and verify through an official channel.",
  };
}

function higherRisk(left: ScamRisk, right: ScamRisk): ScamRisk {
  const rank: Record<ScamRisk, number> = { high: 3, medium: 2, low: 1, unknown: 0 };
  return rank[left] >= rank[right] ? left : right;
}

async function evaluateScam(input: { text: string; link: string; signals: string[]; locale: Locale }): Promise<ScamResult> {
  const analysisText = input.text || input.signals.map((signal) => `${signal} signal selected`).join(". ");
  const output: ScamAnalysis = analyzeScamEngine(analysisText, input.link || undefined);
  const risk: ScamRisk = output.verdict === "SCAM" ? "high" : output.verdict === "SUSPICIOUS" ? "medium" : "low";
  return {
    risk,
    verdict: output.verdict,
    score: output.score,
    advice: output.advice,
    detail: output.detail,
    reasons: output.reasons,
    matchedPhrases: output.matchedPhrases,
    matches: output.matches,
    actions: output.actions,
    reporting: output.reportingGuidance.recommended,
    warnFamilyMessage: output.warnFamilyMessage,
  };
}

function buildSummary(): string {
  const lines = [message("share.summary"), `${message("settings.language")}: ${getLocaleName(state.locale ?? "en")}`];
  if (state.triageResult) {
    const labelKey: Record<TriageLevel, MessageKey> = {
      emergency: "triage.emergency",
      urgent: "triage.urgent",
      routine: "triage.routine",
      monitor: "triage.monitor",
    };
    lines.push(`${message("triage.resultTitle")}: ${state.triageResult.label ?? message(labelKey[state.triageResult.level])}`);
    lines.push(state.triageResult.shareSummary || state.triageResult.advice);
  }
  if (state.scamResult) {
    lines.push(`${message("scam.resultTitle")}: ${state.scamResult.verdict ?? state.scamResult.risk}`);
    lines.push(state.scamResult.warnFamilyMessage || state.scamResult.advice);
  }
  lines.push(message("app.safetyText"));
  return lines.join("\n");
}

async function copySummary(): Promise<void> {
  const summary = buildSummary();
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(summary);
    } else {
      const textarea = document.createElement("textarea");
      textarea.value = summary;
      textarea.setAttribute("readonly", "true");
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      textarea.remove();
    }
    announce(message("app.copied"));
  } catch {
    announce(message("error.generic"));
  }
}

async function shareSummary(): Promise<void> {
  const share = (navigator as Navigator & { share?: (data: ShareData) => Promise<void> }).share;
  if (typeof share === "function") {
    try {
      await share.call(navigator, { title: message("share.summary"), text: buildSummary() });
      announce(message("app.share"));
      return;
    } catch {
      // The user may cancel the share sheet; copying is a useful local fallback.
    }
  }
  await copySummary();
}

function speakText(text: string): void {
  if (!text) return;
  const speech = globalThis.speechSynthesis;
  const Utterance = globalThis.SpeechSynthesisUtterance;
  if (!speech || !Utterance) {
    announce(message("app.voiceUnavailable"));
    return;
  }
  speech.cancel();
  const utterance = new Utterance(text);
  const requestedLanguage = speechLanguage(state.locale ?? "en");
  utterance.lang = requestedLanguage;
  const voices = speech.getVoices?.() ?? [];
  const requestedPrefix = requestedLanguage.split("-")[0].toLowerCase();
  const matchingVoice = voices.find((voice) => voice.lang.toLowerCase().startsWith(requestedPrefix));
  if (voices.length > 0 && !matchingVoice) {
    const fallbackVoice = voices.find((voice) => /^en-(?:ng|in|us)/i.test(voice.lang)) ?? voices.find((voice) => /^en/i.test(voice.lang));
    if (fallbackVoice) {
      utterance.voice = fallbackVoice;
      utterance.lang = fallbackVoice.lang;
      announce(message("app.voiceFallback"));
    }
  }
  utterance.rate = state.preferences.speechRate;
  speech.speak(utterance);
  announce(message("app.speak"));
}

function stopSpeaking(): void {
  globalThis.speechSynthesis?.cancel();
  announce(message("app.stopSpeaking"));
}

async function enableNotifications(): Promise<void> {
  if (typeof Notification === "undefined") {
    announce("Local notifications are not supported here. The reminder will stay visible on this device.");
    return;
  }
  try {
    const permission = await Notification.requestPermission();
    announce(permission === "granted" ? "Local notifications enabled." : "Notifications were not enabled; reminders stay visible on this device.");
  } catch {
    announce("Notifications were not enabled; reminders stay visible on this device.");
  }
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function isClimateTelemetry(value: unknown): value is ClimateTelemetry {
  if (!value || typeof value !== "object") return false;
  const telemetry = value as Partial<ClimateTelemetry>;
  const temperatureC = telemetry.temperatureC;
  const relativeHumidity = telemetry.relativeHumidity;
  const windSpeedKmh = telemetry.windSpeedKmh;
  return typeof telemetry.observedAt === "string"
    && isFiniteNumber(temperatureC)
    && temperatureC >= -90
    && temperatureC <= 70
    && isFiniteNumber(relativeHumidity)
    && relativeHumidity >= 0
    && relativeHumidity <= 100
    && isFiniteNumber(windSpeedKmh)
    && windSpeedKmh >= 0;
}

function readClimateCache(): ClimateTelemetry | null {
  try {
    const raw = globalThis.localStorage?.getItem(climateTelemetryStorageKey);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as unknown;
    return isClimateTelemetry(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function saveClimateCache(telemetry: ClimateTelemetry): void {
  try {
    globalThis.localStorage?.setItem(climateTelemetryStorageKey, JSON.stringify(telemetry));
  } catch {
    // IndexedDB remains the best-effort cache when localStorage is unavailable.
  }
  void saveLocalSetting(climateTelemetryStorageKey, telemetry);
}

function saveClimatePreferences(): void {
  const preferences = {
    activity: state.climateActivity,
    profiles: state.climateProfiles,
    announcementMinutes: state.climateAnnouncementMinutes,
    announcementsEnabled: state.climateAnnouncementsEnabled,
    countryCode: state.climateCountryCode,
  };
  try {
    globalThis.localStorage?.setItem(climatePreferencesStorageKey, JSON.stringify(preferences));
  } catch {
    // The controls remain usable for this session.
  }
  void saveLocalSetting(climatePreferencesStorageKey, preferences);
}

function calculateClimateRisk(telemetry: ClimateTelemetry): ClimateRisk {
  return climateRisk({
    temperatureC: telemetry.temperatureC,
    relativeHumidity: telemetry.relativeHumidity,
    windSpeedKmh: telemetry.windSpeedKmh,
    pm25: telemetry.pm25,
    precipitationNext48hMm: telemetry.precipitationNext48hMm,
    pressureChangeHpa: telemetry.pressureChangeHpa,
    vulnerableProfiles: state.climateProfiles,
  });
}

function updateClimateTelemetry(telemetry: ClimateTelemetry, announcement = "Climate reading updated."): void {
  state.climateTelemetry = telemetry;
  state.climateRisk = calculateClimateRisk(telemetry);
  state.climateError = "";
  if (state.hydrationPlan) {
    state.hydrationPlan = makeHydrationPlan({
      now: new Date(),
      temperatureC: telemetry.temperatureC,
      relativeHumidity: telemetry.relativeHumidity,
      activity: state.climateActivity,
      vulnerableProfiles: state.climateProfiles,
      reminderNumber: Math.max(1, state.hydrationReminderNumber),
    });
    scheduleHydrationReminder();
  }
  saveClimateCache(telemetry);
  announce(announcement);
  renderApp();
}

function setSampleClimateTelemetry(): void {
  const location = state.facilityLocation;
  updateClimateTelemetry({
    observedAt: new Date().toISOString(),
    latitude: location?.latitude,
    longitude: location?.longitude,
    city: "Sample heat alert",
    countryCode: state.climateCountryCode,
    temperatureC: 40.2,
    relativeHumidity: 72,
    windSpeedKmh: 6,
    pressureHpa: 1001,
    pressureChangeHpa: -8,
    precipitation48hMm: 82,
    precipitationNext48hMm: 118,
    soilMoisture: 0.32,
    uvIndex: 9,
    pm25: 64,
    usAqi: 118,
    source: "manual",
  }, "Sample heat, air-quality, and flood-watch reading loaded.");
}

function climateCoordinates(): Promise<{ latitude: number; longitude: number }> {
  if (state.facilityLocation) return Promise.resolve(state.facilityLocation);
  const cachedLocation = state.climateTelemetry;
  if (cachedLocation && isFiniteNumber(cachedLocation.latitude) && isFiniteNumber(cachedLocation.longitude)) {
    return Promise.resolve({ latitude: cachedLocation.latitude, longitude: cachedLocation.longitude });
  }
  if (typeof navigator === "undefined" || !navigator.geolocation) {
    return Promise.reject(new Error("Location is unavailable. Use the offline manual reading."));
  }
  return new Promise((resolve, reject) => {
    navigator.geolocation.getCurrentPosition(
      (position) => resolve({ latitude: position.coords.latitude, longitude: position.coords.longitude }),
      () => reject(new Error("Location was not shared. Use the offline manual reading.")),
      { enableHighAccuracy: false, maximumAge: 300000, timeout: 8000 },
    );
  });
}

async function refreshClimateTelemetry(): Promise<void> {
  if (state.climateLoading) return;
  if (typeof navigator !== "undefined" && navigator.onLine === false) {
    const cached = readClimateCache();
    if (cached) {
      updateClimateTelemetry({ ...cached, source: "cached" }, "Showing the last cached climate reading. You are offline.");
    } else {
      state.climateError = "You are offline. Enter a manual reading or load the sample alert.";
      announce(state.climateError);
      renderApp();
    }
    return;
  }
  state.climateLoading = true;
  state.climateError = "";
  renderApp();
  const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
  const timeout = typeof window !== "undefined" ? window.setTimeout(() => controller?.abort(), 10000) : null;
  try {
    const coordinates = await climateCoordinates();
    const telemetry = await fetchOpenMeteoTelemetry(coordinates.latitude, coordinates.longitude, controller?.signal);
    if (!isClimateTelemetry(telemetry)) throw new Error("Telemetry response was incomplete");
    updateClimateTelemetry({ ...telemetry, countryCode: state.climateCountryCode }, "Live climate reading updated.");
  } catch {
    const cached = readClimateCache();
    if (cached) {
      updateClimateTelemetry({ ...cached, source: "cached" }, "Live reading failed. Showing the last cached climate reading.");
    } else {
      state.climateError = "Live weather was unavailable. Use the offline manual reading or sample alert; no data was sent elsewhere by SafeHands.";
      announce(state.climateError);
      renderApp();
    }
  } finally {
    if (timeout !== null && typeof window !== "undefined") window.clearTimeout(timeout);
    state.climateLoading = false;
    renderApp();
  }
}

function notifyClimate(title: string, body: string): void {
  if (typeof Notification === "undefined" || Notification.permission !== "granted") return;
  try {
    new Notification(title, { body, tag: "safehands-climate" });
  } catch {
    // The visible in-app live region remains the fallback.
  }
}

function scheduleHydrationReminder(): void {
  if (typeof window === "undefined" || !state.hydrationPlan) return;
  if (hydrationTimer !== null) window.clearTimeout(hydrationTimer);
  const delay = Math.max(1000, new Date(state.hydrationPlan.nextReminderAt).valueOf() - Date.now());
  hydrationTimer = window.setTimeout(() => {
    hydrationTimer = null;
    if (!state.climateTelemetry) return;
    state.hydrationReminderNumber += 1;
    state.hydrationPlan = makeHydrationPlan({
      now: new Date(),
      temperatureC: state.climateTelemetry.temperatureC,
      relativeHumidity: state.climateTelemetry.relativeHumidity,
      activity: state.climateActivity,
      vulnerableProfiles: state.climateProfiles,
      reminderNumber: state.hydrationReminderNumber,
    });
    const reminder = state.hydrationPlan.message;
    announce(reminder);
    notifyClimate("SafeHands hydration reminder", reminder);
    if (state.climateAnnouncementsEnabled) speakText(reminder);
    if (typeof navigator !== "undefined") navigator.vibrate?.([120, 80, 120]);
    renderApp();
    scheduleHydrationReminder();
  }, Math.min(delay, 2_147_000_000));
}

function startHydrationPlan(): void {
  const telemetry = state.climateTelemetry;
  if (!telemetry) {
    state.climateError = "Load or enter a climate reading before starting adaptive hydration.";
    announce(state.climateError);
    renderApp();
    return;
  }
  state.hydrationReminderNumber = Math.max(1, state.hydrationReminderNumber + 1);
  state.hydrationPlan = makeHydrationPlan({
    now: new Date(),
    temperatureC: telemetry.temperatureC,
    relativeHumidity: telemetry.relativeHumidity,
    activity: state.climateActivity,
    vulnerableProfiles: state.climateProfiles,
    reminderNumber: state.hydrationReminderNumber,
  });
  scheduleHydrationReminder();
  announce(`Adaptive hydration started. Next reminder in ${state.hydrationPlan.intervalMinutes} minutes.`);
  renderApp();
}

function scheduleClimateAnnouncement(): void {
  if (typeof window === "undefined" || !state.climateAnnouncementsEnabled || !state.climateRisk) return;
  if (climateAnnouncementTimer !== null) window.clearTimeout(climateAnnouncementTimer);
  const delay = Math.max(60_000, state.climateAnnouncementMinutes * 60_000);
  climateAnnouncementTimer = window.setTimeout(() => {
    climateAnnouncementTimer = null;
    if (!state.climateAnnouncementsEnabled || !state.climateRisk) return;
    const text = state.climateRisk.alerts[0] ?? state.climateRisk.label;
    announce(text);
    notifyClimate("SafeHands climate alert", text);
    speakText(text);
    scheduleClimateAnnouncement();
  }, Math.min(delay, 2_147_000_000));
}

function toggleAmbientAnnouncements(): void {
  state.climateAnnouncementsEnabled = !state.climateAnnouncementsEnabled;
  if (!state.climateAnnouncementsEnabled) {
    if (climateAnnouncementTimer !== null && typeof window !== "undefined") window.clearTimeout(climateAnnouncementTimer);
    climateAnnouncementTimer = null;
    announce("Ambient climate announcements stopped.");
  } else if (!state.climateRisk) {
    state.climateAnnouncementsEnabled = false;
    announce("Load or enter a climate reading before starting ambient announcements.");
  } else {
    if (typeof Notification !== "undefined" && Notification.permission === "default") void enableNotifications();
    scheduleClimateAnnouncement();
    announce("Ambient climate announcements started. The next check is scheduled in two hours.");
  }
  saveClimatePreferences();
  renderApp();
}

function toggleRescueBeacon(): void {
  if (state.climateBeaconActive) {
    if (climateBeaconTimer !== null && typeof window !== "undefined") window.clearInterval(climateBeaconTimer);
    climateBeaconTimer = null;
    if (climateAudioContext) {
      void climateAudioContext.close().catch(() => undefined);
      climateAudioContext = null;
    }
    state.climateBeaconActive = false;
    announce("Rescue beacon stopped.");
    renderApp();
    return;
  }

  const browserWindow = globalThis as unknown as BrowserWindow;
  const AudioContextConstructor = browserWindow.AudioContext ?? browserWindow.webkitAudioContext;
  const beep = (): void => {
    const context = climateAudioContext;
    if (!context) return;
    try {
      const oscillator = context.createOscillator();
      const gain = context.createGain();
      oscillator.frequency.value = 3000;
      gain.gain.value = 0.04;
      oscillator.connect(gain);
      gain.connect(context.destination);
      oscillator.start();
      oscillator.stop(context.currentTime + 0.18);
    } catch {
      // The visible beacon still works when audio is blocked.
    }
  };
  if (AudioContextConstructor) {
    try {
      const context = new AudioContextConstructor();
      climateAudioContext = context;
      void context.resume().catch(() => undefined);
      beep();
      if (typeof window !== "undefined") climateBeaconTimer = window.setInterval(beep, 1600);
    } catch {
      climateAudioContext = null;
    }
  }
  state.climateBeaconActive = true;
  announce(AudioContextConstructor ? "Rescue beacon started with visible and audio signals." : "Rescue beacon started with a visible signal. Audio is unavailable here.");
  renderApp();
}

function applyManualClimateReading(form: HTMLFormElement): void {
  const formData = new FormData(form);
  const temperatureC = Number(formData.get("temperature"));
  const relativeHumidity = Number(formData.get("humidity"));
  const windSpeedKmh = Number(formData.get("wind"));
  if (!Number.isFinite(temperatureC) || temperatureC < -30 || temperatureC > 60 || !Number.isFinite(relativeHumidity) || relativeHumidity < 1 || relativeHumidity > 100 || !Number.isFinite(windSpeedKmh) || windSpeedKmh < 0 || windSpeedKmh > 200) {
    state.climateError = "Enter a temperature from -30 to 60°C, humidity from 1 to 100%, and wind from 0 to 200 km/h.";
    announce(state.climateError);
    renderApp();
    return;
  }
  updateClimateTelemetry({
    observedAt: new Date().toISOString(),
    latitude: state.facilityLocation?.latitude ?? state.climateTelemetry?.latitude,
    longitude: state.facilityLocation?.longitude ?? state.climateTelemetry?.longitude,
    city: state.facilityCity,
    countryCode: state.climateCountryCode,
    temperatureC,
    relativeHumidity,
    windSpeedKmh,
    source: "manual",
  }, "Offline climate reading calculated.");
}

async function restoreClimateCache(): Promise<void> {
  const localCache = readClimateCache();
  if (localCache) {
    updateClimateTelemetry({ ...localCache, source: "cached" }, "Last cached climate reading restored.");
    return;
  }
  const indexedCache = await readLocalSetting<ClimateTelemetry>(climateTelemetryStorageKey);
  if (isClimateTelemetry(indexedCache)) updateClimateTelemetry({ ...indexedCache, source: "cached" }, "Last cached climate reading restored.");
}

function setupClimateBatteryMonitoring(): void {
  const browserWindow = globalThis as unknown as BrowserWindow;
  if (!browserWindow.getBattery) return;
  void browserWindow.getBattery().then((battery) => {
    climateBatteryManager = battery;
    const update = (): void => {
      const nextPercent = Math.round(battery.level * 100);
      const nextLowMode = battery.level <= 0.15;
      const changed = state.climateBatteryPercent !== nextPercent || state.climateLowBatteryMode !== nextLowMode;
      if (nextLowMode && !state.climateLowBatteryMode) {
        state.climateAnnouncementsEnabled = false;
        if (climateAnnouncementTimer !== null && typeof window !== "undefined") window.clearTimeout(climateAnnouncementTimer);
        climateAnnouncementTimer = null;
      }
      state.climateBatteryPercent = nextPercent;
      state.climateLowBatteryMode = nextLowMode;
      if (changed) {
        applyPreferences();
        renderApp();
      }
    };
    battery.addEventListener("levelchange", update);
    update();
  }).catch(() => undefined);
}

function requestFacilityLocation(): void {
  if (typeof navigator === "undefined" || !navigator.geolocation) {
    state.facilityLocationMessage = "Location is not available here. Choose a city manually; nothing is sent anywhere.";
    renderApp();
    return;
  }
  state.facilityLocationMessage = "Waiting for your optional location permission…";
  renderApp();
  navigator.geolocation.getCurrentPosition(
    (position) => {
      state.facilityLocation = {
        latitude: position.coords.latitude,
        longitude: position.coords.longitude,
      };
      state.facilityLocationMessage = "Sorted by approximate distance on this device. Your location is not saved or sent.";
      renderApp();
    },
    () => {
      state.facilityLocation = null;
      state.facilityLocationMessage = "Location was not shared. Choose a city manually; the app still works offline.";
      renderApp();
    },
    { enableHighAccuracy: false, maximumAge: 300000, timeout: 8000 },
  );
}

function startVoiceInput(): void {
  const browserWindow = globalThis as unknown as BrowserWindow;
  const Recognition = browserWindow.SpeechRecognition ?? browserWindow.webkitSpeechRecognition;
  const textarea = mountedRoot?.querySelector<HTMLTextAreaElement>("#triage-description");
  if (!Recognition || !textarea) {
    announce(message("app.voiceUnavailable"));
    return;
  }
  activeRecognition?.stop();
  const recognition = new Recognition();
  activeRecognition = recognition;
  recognition.lang = speechLanguage(state.locale ?? "en");
  recognition.continuous = false;
  recognition.interimResults = false;
  const status = mountedRoot?.querySelector<HTMLElement>("[data-voice-status]");
  if (status) status.textContent = message("app.voiceListening");
  announce(message("app.voiceListening"));
  recognition.onresult = (event) => {
    const transcript = event.results?.[0]?.[0]?.transcript?.trim() ?? "";
    if (transcript) {
      state.triageDescription = [state.triageDescription, transcript].filter(Boolean).join(" ").slice(0, 4000);
      textarea.value = state.triageDescription;
      announce(message("app.voiceInput"));
    }
  };
  recognition.onerror = () => {
    activeRecognition = null;
    announce(message("app.voiceUnavailable"));
  };
  recognition.onend = () => {
    activeRecognition = null;
    const currentStatus = mountedRoot?.querySelector<HTMLElement>("[data-voice-status]");
    if (currentStatus) currentStatus.textContent = message("app.voiceHint");
  };
  try {
    recognition.start();
  } catch {
    activeRecognition = null;
    announce(message("app.voiceUnavailable"));
  }
}

function scheduleReminder(reminder: Reminder): void {
  if (typeof window === "undefined") return;
  const when = new Date(reminder.when).valueOf();
  const delay = when - Date.now();
  if (!Number.isFinite(delay) || delay <= 0 || delay > 2_147_000_000 || reminderTimers.has(reminder.id)) return;
  const timer = window.setTimeout(() => {
    reminderTimers.delete(reminder.id);
    announce(`${reminder.label}: ${message("live.ready")}`);
    if (typeof Notification !== "undefined" && Notification.permission === "granted") {
      try {
        new Notification("SafeHands reminder", { body: reminder.label, tag: reminder.id });
      } catch {
        // The visible in-app announcement is the reliable fallback.
      }
    }
    if (typeof navigator !== "undefined" && "vibrate" in navigator) navigator.vibrate?.([120, 80, 120]);
  }, delay);
  reminderTimers.set(reminder.id, timer);
}

function scheduleAllReminders(): void {
  state.reminders.forEach(scheduleReminder);
}

async function registerServiceWorker(): Promise<void> {
  if (typeof navigator === "undefined" || !("serviceWorker" in navigator)) {
    state.offlineReady = true;
    renderApp();
    return;
  }
  try {
    await navigator.serviceWorker.register("./sw.js", { scope: "./" });
    state.offlineReady = true;
    announce(message("app.offlineReady"));
    renderApp();
  } catch {
    // The app still works without a service worker, with no remote dependency.
    state.offlineReady = false;
    renderApp();
  }
}

function installGlobalEvents(): void {
  if (globalEventsInstalled || typeof window === "undefined") return;
  globalEventsInstalled = true;
  window.addEventListener("online", () => {
    state.online = true;
    announce(message("app.offlineReady"));
  });
  window.addEventListener("offline", () => {
    state.online = false;
    announce(message("app.offlineReady"));
  });
}

export function mountApp(root?: HTMLElement): HTMLElement | null {
  const target = root ?? (typeof document !== "undefined" ? document.getElementById("app") : null);
  if (!target) return null;
  mountedRoot = target;
  installEvents(target);
  installGlobalEvents();
  renderApp(target);
  void registerServiceWorker();
  void restoreClimateCache();
  setupClimateBatteryMonitoring();
  return target;
}

/** Reset only the in-memory UI state; useful for jsdom integration tests. */
export function resetAppForTests(): void {
  activeRecognition?.stop();
  activeRecognition = null;
  reminderTimers.forEach((timer) => {
    if (typeof window !== "undefined") window.clearTimeout(timer);
  });
  reminderTimers.clear();
  if (typeof window !== "undefined") {
    if (climateAnnouncementTimer !== null) window.clearTimeout(climateAnnouncementTimer);
    if (hydrationTimer !== null) window.clearTimeout(hydrationTimer);
    if (climateBeaconTimer !== null) window.clearInterval(climateBeaconTimer);
  }
  climateAnnouncementTimer = null;
  hydrationTimer = null;
  climateBeaconTimer = null;
  if (climateAudioContext) {
    void climateAudioContext.close().catch(() => undefined);
    climateAudioContext = null;
  }
  climateBatteryManager = null;
  state = { ...createInitialState(), locale: null, reminders: [], preferences: { ...defaultPreferences } };
  if (mountedRoot) renderApp(mountedRoot);
}

export function getAppStateForTests(): Readonly<AppState> {
  return state;
}

if (typeof document !== "undefined") {
  const appRoot = document.getElementById("app");
  if (appRoot) mountApp(appRoot);
}

// Kept exported for tests and for host shells that want to use the bundled messages.
export { localeMessages };
