import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  apparentTemperatureC,
  buildSosPayload,
  climateRisk,
  getAuthorityRoute,
  hydrationIntervalMinutes,
  makeRiskRadar,
  makeHydrationPlan,
  safeZoneSearchUrl,
  wetBulbTemperatureC,
} from "../src/climate";
import { getAppStateForTests, renderApp, resetAppForTests } from "../src/main";

function root(): HTMLElement {
  const element = document.getElementById("app");
  if (!element) throw new Error("Expected #app in the jsdom fixture");
  return element;
}

function chooseEnglish(): void {
  root().querySelector<HTMLElement>('[data-action="choose-locale"][data-locale="en"]')?.click();
}

function openClimate(): void {
  root().querySelector<HTMLElement>('[data-action="navigate"][data-screen="climate"]')?.click();
}

beforeEach(() => {
  document.body.innerHTML = '<div id="app"></div>';
  window.localStorage.clear();
  resetAppForTests();
  renderApp(root());
  chooseEnglish();
});

describe("SafeHands climate calculations", () => {
  it("produces finite apparent and wet-bulb estimates", () => {
    expect(Number.isFinite(apparentTemperatureC(40, 70, 5))).toBe(true);
    expect(Number.isFinite(wetBulbTemperatureC(40, 70))).toBe(true);
  });

  it("raises red risk for extreme heat and adds environmental alerts", () => {
    const result = climateRisk({
      temperatureC: 40,
      relativeHumidity: 72,
      windSpeedKmh: 5,
      pm25: 65,
      precipitationNext48hMm: 120,
      pressureChangeHpa: -8,
    });
    expect(result.heatRisk).toBe("red");
    expect(result.alerts.join(" ")).toMatch(/heat|air quality|rainfall|pressure/i);
  });

  it("shortens hydration intervals for heavier activity and vulnerable profiles", () => {
    const rest = hydrationIntervalMinutes(35, 70, "rest");
    const heavy = hydrationIntervalMinutes(35, 70, "heavy", ["elderly"]);
    expect(heavy).toBeLessThan(rest);
    expect(makeHydrationPlan({ temperatureC: 35, relativeHumidity: 70, activity: "moderate", reminderNumber: 3 }).message).toMatch(/electrolyte/i);
  });

  it("builds a cautious local SOS message and authority route", () => {
    const payload = buildSosPayload({ crisisType: "Flood trapped", people: 2, vulnerable: ["infant"], batteryPercent: 14, temperatureC: 39 });
    expect(payload).toMatch(/SAFEHANDS SOS/);
    expect(payload).toMatch(/Location: Location unavailable/);
    expect(getAuthorityRoute("NG").emergencyNumbers).toContain("112");
  });

  it("returns explicit risk-radar levels and an inert map search URL", () => {
    const radar = makeRiskRadar({ temperatureC: 38, relativeHumidity: 70, windSpeedKmh: 4, pm25: 60, precipitationNext48hMm: 110, pressureChangeHpa: -8, uvIndex: 9, soilMoisture: 0.5 });
    expect(radar.find((signal) => signal.id === "heat")?.level).toBe("high");
    expect(radar.find((signal) => signal.id === "air")?.level).toBe("high");
    expect(radar.find((signal) => signal.id === "flood")?.level).toBe("high");
    expect(safeZoneSearchUrl("Akure")).toMatch(/^https:\/\/www\.openstreetmap\.org\/search\?query=/);
  });
});

describe("SafeHands climate user path", () => {
  it("loads a sample alert and opens an offline emergency protocol", () => {
    openClimate();
    root().querySelector<HTMLElement>('[data-action="sample-climate"]')?.click();
    expect(getAppStateForTests().climateRisk?.heatRisk).toBe("red");
    expect(root().textContent).toMatch(/Red crisis mode|Extreme heat/i);
    root().querySelector<HTMLElement>('[data-action="start-hydration"]')?.click();
    expect(getAppStateForTests().hydrationPlan?.intervalMinutes).toBeGreaterThan(0);

    root().querySelector<HTMLElement>('[data-action="protocol-open"][data-protocol-id="heatstroke"]')?.click();
    expect(root().querySelector(".protocol-step")?.textContent).toMatch(/Call local emergency services/i);
    root().querySelector<HTMLElement>('[data-action="protocol-next"]')?.click();
    expect(root().querySelector(".protocol-step")?.textContent).toMatch(/shade|cool/i);

    root().querySelector<HTMLElement>('[data-action="toggle-beacon"]')?.click();
    expect(getAppStateForTests().climateBeaconActive).toBe(true);
    root().querySelector<HTMLElement>('[data-action="toggle-beacon"]')?.click();
    expect(getAppStateForTests().climateBeaconActive).toBe(false);
  });

  it("calculates an offline manual reading without a network request", () => {
    openClimate();
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    try {
      const form = root().querySelector<HTMLFormElement>("#climate-manual-form");
      if (!form) throw new Error("Missing climate manual form");
      const temperature = form.querySelector<HTMLInputElement>("[name='temperature']");
      const humidity = form.querySelector<HTMLInputElement>("[name='humidity']");
      if (temperature) temperature.value = "38";
      if (humidity) humidity.value = "65";
      form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
      expect(getAppStateForTests().climateTelemetry?.source).toBe("manual");
      expect(getAppStateForTests().climateRisk?.heatRisk).toMatch(/amber|red/);
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      fetchSpy.mockRestore();
    }
  });
});
