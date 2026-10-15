import { describe, expect, it } from "vitest";
import { facilities, getFacilities, triage } from "../src/triage";

describe("SafeHands deterministic triage", () => {
  it("lets a hard red flag override otherwise reassuring wording", () => {
    const result = triage("It seems mild, but one side of my face is drooping and my speech is slurred", {
      country: "Nigeria"
    });

    expect(result.urgency).toBe("emergency");
    expect(result.matchedRedFlags).toContain("stroke-signs");
    expect(result.actionSteps.join(" ")).toMatch(/emergency services/i);
    expect(result.emergencyCallNumbers).toEqual(["112"]);
    expect(result.disclaimer).toMatch(/cannot diagnose/i);
  });

  it("escalates an unclear description instead of returning self-care", () => {
    const result = triage("I just feel strange");

    expect(result.urgency).toBe("urgent");
    expect(result.uncertainty).toBe(true);
    expect(result.confidence).toBe("low");
    expect(result.presentation).toBeNull();
    expect(result.escalation.length).toBeGreaterThan(0);
    expect(result.doNotDo.length).toBeGreaterThan(0);
  });

  it("routes common chest and breathing presentations to emergency guidance", () => {
    const chest = triage("new chest pain and pressure");
    const breathing = triage("I have difficulty breathing");

    expect(chest.urgency).toBe("emergency");
    expect(chest.presentation).toBe("chest-pain");
    expect(chest.reasons.length).toBeGreaterThan(0);
    expect(breathing.urgency).toBe("emergency");
    expect(breathing.presentation).toBe("breathing-difficulty");
  });

  it("accepts the UI's object-shaped symptom input", () => {
    const result = triage({ symptoms: ["breathing"], description: "getting worse" });

    expect(result.urgency).toBe("emergency");
    expect(result.level).toBe("emergency");
    expect(result.advice).toContain(result.label);
  });

  it("uses age and pregnancy context to lower the escalation threshold", () => {
    const infantFever = triage("fever", { ageMonths: 2 });
    const pregnancyBleeding = triage("I am pregnant and bleeding", { pregnant: true });

    expect(infantFever.urgency).toBe("emergency");
    expect(infantFever.reasons.join(" ")).toMatch(/under three months/i);
    expect(pregnancyBleeding.urgency).toBe("emergency");
    expect(pregnancyBleeding.matchedRedFlags).toContain("pregnancy-warning-signs");
  });

  it("exposes Akure seed facilities and clearly labels Indian sample data", () => {
    const akure = getFacilities({ city: "Akure", country: "Nigeria" });
    const india = getFacilities({ city: "Bengaluru", country: "India" });
    const routed = triage("fever", { city: "Akure", country: "Nigeria" });

    expect(akure.length).toBeGreaterThan(0);
    expect(akure.every((facility) => facility.city === "Akure")).toBe(true);
    expect(akure.every((facility) => facility.dataStatus === "seed" && !facility.isSample)).toBe(true);
    expect(india.length).toBeGreaterThan(0);
    expect(india.every((facility) => facility.isSample)).toBe(true);
    expect(india.every((facility) => /sample data/i.test(facility.label))).toBe(true);
    expect(routed.facilities.map((facility) => facility.id)).toEqual(akure.map((facility) => facility.id));
    expect(facilities.length).toBeGreaterThanOrEqual(4);
  });

  it("creates a concise share summary with action, urgency, and local call numbers", () => {
    const result = triage("crushing chest pain", { city: "Akure", country: "Nigeria" });

    expect(result.shareSummary).toContain("SafeHands triage summary");
    expect(result.shareSummary).toContain(result.label);
    expect(result.shareSummary).toContain("112");
    expect(result.shareSummary).toMatch(/not a diagnosis/i);
    expect(result["share-summary"]).toBe(result.shareSummary);
    expect(result["action-steps"]).toEqual(result.actionSteps);
    expect(result["do-not-do"]).toEqual(result.doNotDo);
  });

  it("keeps positive danger signs when a nearby symptom is negated", () => {
    const mixed = triage("No chest pain. I cannot breathe and my lips look blue.");
    const negated = triage("I do NOT have chest pain; just a mild headache.");

    expect(mixed.urgency).toBe("emergency");
    expect(mixed.matchedRedFlags).toContain("severe-breathing-distress");
    expect(negated.presentation).toBe("headache");
    expect(negated.urgency).toBe("urgent");
    expect(negated.matchedPresentations).not.toContain("chest-pain");
  });

  it("covers common emergency-first presentations from the buildathon matrix", () => {
    expect(triage("sEvErE aLlErGy!!!").urgency).toBe("emergency");
    expect(triage("headache, fever, stiff neck, and confusion").urgency).toBe("emergency");
    expect(triage("I was bitten by a snake").urgency).toBe("emergency");
    expect(triage("child cannot drink and is very sleepy").urgency).toBe("emergency");
    expect(triage("very thirsty and urinating often").presentation).toBe("high-blood-sugar-warning");
  });

  it("bounds long and malformed input without returning reassuring self-care", () => {
    const result = triage(`${"unknown ".repeat(20000)}\u200b🫥`);
    expect(result.urgency).toBe("urgent");
    expect(result.uncertainty).toBe(true);
  });
});
