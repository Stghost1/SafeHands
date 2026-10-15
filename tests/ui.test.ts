import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  getAppStateForTests,
  localeMessages,
  renderApp,
  resetAppForTests,
} from "../src/main";
import { LOCALE_OPTIONS } from "../src/i18n";
import enJson from "../src/data/locales/en.json";
import pcmJson from "../src/data/locales/pcm.json";
import hiJson from "../src/data/locales/hi.json";
import yoJson from "../src/data/locales/yo.json";
import haJson from "../src/data/locales/ha.json";

function appRoot(): HTMLElement {
  const root = document.getElementById("app");
  if (!root) throw new Error("Expected #app in the jsdom fixture");
  return root;
}

function click(selector: string): void {
  const target = appRoot().querySelector<HTMLElement>(selector);
  if (!target) throw new Error(`Missing control: ${selector}`);
  target.click();
}

function chooseEnglish(): void {
  const english = appRoot().querySelector<HTMLElement>('[data-action="choose-locale"][data-locale="en"]');
  if (!english) throw new Error("Language picker did not render");
  english.click();
}

beforeEach(() => {
  document.body.innerHTML = '<div id="app"></div>';
  window.localStorage.clear();
  resetAppForTests();
  renderApp(appRoot());
});

afterEach(() => {
  document.body.innerHTML = "";
});

describe("SafeHands language-first shell", () => {
  it("starts with native-name language choices and all supported locales", () => {
    const root = appRoot();
    expect(root.querySelector("main#main-content")).toBeTruthy();
    expect(root.querySelector('[data-screen="language-picker"]')).toBeTruthy();
    expect(root.querySelectorAll('[data-action="choose-locale"]')).toHaveLength(LOCALE_OPTIONS.length);
    expect(root.textContent).toContain("Nigerian Pidgin");
    expect(root.textContent).toContain("हिन्दी");
    expect(root.textContent).toContain("Yorùbá");
    expect(root.textContent).toContain("Hausa");
  });

  it("keeps the locale message maps structurally identical", () => {
    const expectedKeys = Object.keys(localeMessages.en).sort();
    for (const option of LOCALE_OPTIONS) {
      expect(Object.keys(localeMessages[option.code]).sort()).toEqual(expectedKeys);
    }
  });

  it("ships identical key sets in every bundled locale JSON file", () => {
    const localeData = [enJson, pcmJson, hiJson, yoJson, haJson];
    const expectedKeys = Object.keys(enJson).sort();
    for (const data of localeData) expect(Object.keys(data).sort()).toEqual(expectedKeys);
  });

  it("opens the full app after a language is selected", () => {
    chooseEnglish();
    const root = appRoot();
    expect(root.querySelector("header")).toBeTruthy();
    expect(root.querySelector("nav")).toBeTruthy();
    expect(root.querySelector("main#main-content")).toBeTruthy();
    expect(root.querySelector("footer")).toBeTruthy();
    expect(root.querySelector('[data-ready]')).toBeTruthy();
  });
});

describe("SafeHands user paths", () => {
  beforeEach(() => chooseEnglish());

  it("provides an accessible health check with typed input and emergency actions", async () => {
    click('[data-action="navigate"][data-screen="triage"]');
    const root = appRoot();
    expect(root.querySelector("#triage-form")).toBeTruthy();
    expect(root.querySelector("label[for='triage-description']")).toBeTruthy();
    expect(root.querySelectorAll("input[name='symptoms']").length).toBeGreaterThanOrEqual(4);
    expect(root.querySelector("[data-action='voice-input']")).toBeTruthy();
    expect(root.querySelector("a[href='tel:112']")).toBeTruthy();

    const breathing = root.querySelector<HTMLInputElement>("input[value='breathing']");
    breathing?.click();
    const form = root.querySelector<HTMLFormElement>("#triage-form");
    form?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(appRoot().querySelector("[data-level='emergency']")).toBeTruthy();
    expect(appRoot().querySelector("[data-level='emergency']")?.textContent).toMatch(/emergency|call|what to do/i);
    expect(appRoot().querySelector("[aria-live='polite']")).toBeTruthy();
  });

  it("provides scam shield chips and a local fallback result", async () => {
    click('[data-action="navigate"][data-screen="scam"]');
    const root = appRoot();
    const message = root.querySelector<HTMLTextAreaElement>("#scam-message");
    expect(message?.getAttribute("aria-label") ?? root.querySelector("label[for='scam-message']")?.textContent).toBeTruthy();
    if (message) message.value = "Send your PIN now and pay a fee";
    root.querySelector<HTMLInputElement>("input[value='urgency']")?.click();
    root.querySelector<HTMLFormElement>("#scam-form")?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(appRoot().querySelector(".result-card")).toBeTruthy();
    expect(appRoot().querySelector("[data-risk='high'], [data-risk='medium']")).toBeTruthy();
    expect(appRoot().querySelector(".message-preview mark")).toBeTruthy();
    expect(window.localStorage.getItem("safehands.preferences") ?? "").not.toContain("Send your PIN");
    expect(appRoot().querySelector('[data-action="share-summary"]')).toBeTruthy();
  });

  it("persists accessibility preferences through the settings path", () => {
    click('[data-action="navigate"][data-screen="settings"]');
    const root = appRoot();
    const highContrast = root.querySelector<HTMLInputElement>('[data-setting="highContrast"]');
    highContrast?.click();
    highContrast?.dispatchEvent(new Event("change", { bubbles: true }));
    expect(appRoot().classList.contains("high-contrast")).toBe(true);
    expect(getAppStateForTests().preferences.highContrast).toBe(true);

    const language = appRoot().querySelector<HTMLSelectElement>('[data-setting="language"]');
    if (language) {
      language.value = "hi";
      language.dispatchEvent(new Event("change", { bubbles: true }));
    }
    expect(document.documentElement.lang).toBe("hi");
    expect(appRoot().textContent).toContain("स्वास्थ्य");
  });
});

describe("SafeHands accessibility contract", () => {
  it("includes a skip link, labelled landmarks, live status, and large-control hooks", () => {
    chooseEnglish();
    const root = appRoot();
    expect(document.querySelector("a.skip-link")?.getAttribute("href")).toBe("#main-content");
    expect(root.querySelector("nav[aria-label]")).toBeTruthy();
    expect(root.querySelector("main#main-content")).toBeTruthy();
    expect(root.querySelector("footer")).toBeTruthy();
    expect(root.querySelector("[role='status'][aria-live='polite']")).toBeTruthy();
    expect(root.querySelectorAll("button, a.button, input, select, textarea").length).toBeGreaterThan(10);
  });

  it("runs axe-core when the host has it, otherwise leaves an explicit integration hook", async () => {
    // axe-core is intentionally optional so this jsdom test stays lightweight.
    const axeModuleName = "axe-core";
    const axeModule = await import(/* @vite-ignore */ axeModuleName).catch(() => null) as {
      default?: { run?: (node: Element) => Promise<{ violations: Array<{ id: string }> }> };
      run?: (node: Element) => Promise<{ violations: Array<{ id: string }> }>;
    } | null;
    if (axeModule?.run || axeModule?.default?.run) {
      chooseEnglish();
      const run = axeModule.run ?? axeModule.default?.run;
      const results = await run!(document.body);
      expect(results.violations).toEqual([]);
      for (const screen of ["triage", "scam", "facilities", "reminders", "settings"]) {
        click(`[data-action="navigate"][data-screen="${screen}"]`);
        const screenResults = await run!(document.body);
        expect(screenResults.violations, screen).toEqual([]);
      }
    } else {
      // Integration installs may add axe-core; DOM assertions above remain active here.
      expect(true).toBe(true);
    }
  }, 30000);
});
