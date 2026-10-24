import authorityDirectory from "./data/authority-directory.json";

export type HeatRisk = "normal" | "amber" | "red";
export type ActivityLevel = "rest" | "light" | "moderate" | "heavy";
export type VulnerableProfile = "pregnant" | "infant" | "elderly" | "outdoor-worker";
export type ClimateSource = "open-meteo" | "cached" | "manual";
export type RadarLevel = "normal" | "watch" | "high";

export interface ClimateTelemetry {
  observedAt: string;
  latitude?: number;
  longitude?: number;
  city?: string;
  countryCode?: string;
  temperatureC: number;
  relativeHumidity: number;
  windSpeedKmh: number;
  pressureHpa?: number;
  pressureChangeHpa?: number;
  precipitation48hMm?: number;
  precipitationNext48hMm?: number;
  soilMoisture?: number;
  uvIndex?: number;
  pm25?: number;
  usAqi?: number;
  source: ClimateSource;
}

export interface ClimateRisk {
  heatRisk: HeatRisk;
  label: string;
  apparentTemperatureC: number;
  wetBulbC: number;
  alerts: string[];
  firstAidPrompt: string;
}

export interface HydrationPlan {
  intervalMinutes: number;
  nextReminderAt: string;
  activity: ActivityLevel;
  electrolyteEvery: number;
  reminderNumber: number;
  message: string;
}

export interface AuthorityRoute {
  countryCode: string;
  countryName: string;
  emergencyNumbers: string[];
  notes: string;
}

export interface RiskRadarSignal {
  id: "heat" | "air" | "flood" | "uv" | "ground";
  label: string;
  level: RadarLevel;
  detail: string;
}

export interface SosPayloadInput {
  crisisType: string;
  people: number;
  vulnerable: string[];
  latitude?: number;
  longitude?: number;
  batteryPercent?: number;
  temperatureC?: number;
  countryCode?: string;
  contact?: string;
}

const AUTHORITY_ROUTES: Record<string, AuthorityRoute> = Object.fromEntries(
  authorityDirectory.map((route) => [route.countryCode, {
    countryCode: route.countryCode,
    countryName: route.countryName,
    emergencyNumbers: route.numbers,
    notes: route.notes,
  }]),
) as Record<string, AuthorityRoute>;

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(maximum, Math.max(minimum, value));
}

function finite(value: number | undefined, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

/** Apparent temperature approximation using air temperature, humidity and wind. */
export function apparentTemperatureC(temperatureC: number, relativeHumidity: number, windSpeedKmh: number): number {
  const temperature = finite(temperatureC);
  const humidity = clamp(finite(relativeHumidity), 0, 100);
  const windMs = Math.max(0, finite(windSpeedKmh)) / 3.6;
  const vapourPressure = (humidity / 100) * 6.105 * Math.exp((17.27 * temperature) / (237.7 + temperature));
  return Number((temperature + 0.33 * vapourPressure - 0.7 * windMs - 4).toFixed(1));
}

/** Stull's wet-bulb approximation. Use as a screening estimate, not a clinical measurement. */
export function wetBulbTemperatureC(temperatureC: number, relativeHumidity: number): number {
  const temperature = finite(temperatureC);
  const humidity = clamp(finite(relativeHumidity), 1, 100);
  const wetBulb = temperature * Math.atan(0.151977 * Math.sqrt(humidity + 8.313659))
    + Math.atan(temperature + humidity)
    - Math.atan(humidity - 1.676331)
    + 0.00391838 * Math.pow(humidity, 1.5) * Math.atan(0.023101 * humidity)
    - 4.686035;
  return Number(wetBulb.toFixed(1));
}

export function climateRisk(telemetry: Pick<ClimateTelemetry, "temperatureC" | "relativeHumidity" | "windSpeedKmh" | "pm25" | "precipitationNext48hMm" | "pressureChangeHpa"> & { vulnerableProfiles?: VulnerableProfile[] }): ClimateRisk {
  const apparent = apparentTemperatureC(telemetry.temperatureC, telemetry.relativeHumidity, telemetry.windSpeedKmh);
  const wetBulb = wetBulbTemperatureC(telemetry.temperatureC, telemetry.relativeHumidity);
  const profiles = telemetry.vulnerableProfiles ?? [];
  const thresholdOffset = profiles.length > 0 ? -2 : 0;
  const alerts: string[] = [];
  let heatRisk: HeatRisk = "normal";

  if (telemetry.temperatureC >= 40 || apparent >= 45 || wetBulb >= 31 || telemetry.temperatureC >= 38 + thresholdOffset) {
    heatRisk = "red";
    alerts.push("Extreme heat risk. Stop strenuous activity, move to a cool place, and check on vulnerable people.");
  } else if (telemetry.temperatureC >= 35 + thresholdOffset || apparent >= 38 || wetBulb >= 28) {
    heatRisk = "amber";
    alerts.push("Heat warning. Reduce exertion, seek shade, and drink regularly.");
  }

  if (finite(telemetry.pm25, -1) >= 55) alerts.push("Air quality is unhealthy for some people. Use a clean-air room and avoid smoke exposure.");
  if (finite(telemetry.precipitationNext48hMm, -1) >= 100) alerts.push("Heavy rainfall is expected. Move early to higher, safer ground and avoid floodwater.");
  if (finite(telemetry.pressureChangeHpa, 0) <= -6) alerts.push("Pressure is falling quickly. Monitor official weather and flood warnings.");

  return {
    heatRisk,
    label: heatRisk === "red" ? "Red crisis mode" : heatRisk === "amber" ? "Amber heat warning" : "Normal monitoring",
    apparentTemperatureC: apparent,
    wetBulbC: wetBulb,
    alerts,
    firstAidPrompt: heatRisk === "red"
      ? "If someone is confused, faints, has a seizure, or cannot drink, call emergency services and cool them while help is coming."
      : "If symptoms worsen, stop activity and seek medical help.",
  };
}

export function hydrationIntervalMinutes(temperatureC: number, relativeHumidity: number, activity: ActivityLevel, vulnerableProfiles: VulnerableProfile[] = []): number {
  const heatFactor = clamp((finite(temperatureC) - 26) / 13, 0, 1);
  const humidityFactor = clamp((finite(relativeHumidity) - 50) / 50, 0, 1);
  const activityFactor: Record<ActivityLevel, number> = { rest: 1.15, light: 1, moderate: 0.78, heavy: 0.58 };
  const profileFactor = vulnerableProfiles.length > 0 ? 0.82 : 1;
  const baseline = 90 - heatFactor * 55 - humidityFactor * 12;
  return Math.round(clamp(baseline * activityFactor[activity] * profileFactor, 25, 120));
}

export function makeHydrationPlan(input: {
  now?: Date;
  temperatureC: number;
  relativeHumidity: number;
  activity: ActivityLevel;
  vulnerableProfiles?: VulnerableProfile[];
  reminderNumber?: number;
}): HydrationPlan {
  const now = input.now ?? new Date();
  const reminderNumber = Math.max(1, input.reminderNumber ?? 1);
  const intervalMinutes = hydrationIntervalMinutes(input.temperatureC, input.relativeHumidity, input.activity, input.vulnerableProfiles);
  const nextReminderAt = new Date(now.getTime() + intervalMinutes * 60_000).toISOString();
  const electrolyteEvery = 3;
  const electrolyteMessage = reminderNumber % electrolyteEvery === 0
    ? "If you have been sweating heavily, use a suitable electrolyte drink. For diarrhoea, use an ORS packet and follow its instructions; do not use a DIY salt mix for routine heat hydration."
    : "Take small, regular sips. Do not force large amounts quickly or drink excessive plain water.";
  return {
    intervalMinutes,
    nextReminderAt,
    activity: input.activity,
    electrolyteEvery,
    reminderNumber,
    message: `Hydration reminder: take a short drink break. ${electrolyteMessage}`,
  };
}

export function precipitationRisk(next48hMm = 0, pressureChangeHpa = 0): "normal" | "watch" | "high" {
  if (next48hMm >= 100 || pressureChangeHpa <= -8) return "high";
  if (next48hMm >= 50 || pressureChangeHpa <= -6) return "watch";
  return "normal";
}

export function makeRiskRadar(telemetry: Pick<ClimateTelemetry, "temperatureC" | "relativeHumidity" | "windSpeedKmh" | "pm25" | "precipitationNext48hMm" | "pressureChangeHpa" | "uvIndex" | "soilMoisture">, vulnerableProfiles: VulnerableProfile[] = []): RiskRadarSignal[] {
  const heat = climateRisk({ ...telemetry, vulnerableProfiles });
  const pm25 = finite(telemetry.pm25, -1);
  const uv = finite(telemetry.uvIndex, -1);
  const soil = finite(telemetry.soilMoisture, -1);
  const flood = precipitationRisk(finite(telemetry.precipitationNext48hMm), finite(telemetry.pressureChangeHpa));
  return [
    {
      id: "heat",
      label: "Heat",
      level: heat.heatRisk === "red" ? "high" : heat.heatRisk === "amber" ? "watch" : "normal",
      detail: `${heat.label}; feels like ${heat.apparentTemperatureC.toFixed(1)}°C`,
    },
    {
      id: "air",
      label: "Air quality",
      level: pm25 >= 55 ? "high" : pm25 >= 35 ? "watch" : "normal",
      detail: pm25 >= 0 ? `PM2.5 ${pm25.toFixed(0)} µg/m³` : "No PM2.5 reading",
    },
    {
      id: "flood",
      label: "Rain and flood watch",
      level: flood,
      detail: finite(telemetry.precipitationNext48hMm, -1) >= 0 ? `${finite(telemetry.precipitationNext48hMm).toFixed(0)} mm expected in 48h` : "No rainfall forecast",
    },
    {
      id: "uv",
      label: "UV exposure",
      level: uv >= 8 ? "high" : uv >= 6 ? "watch" : "normal",
      detail: uv >= 0 ? `UV index ${uv.toFixed(1)}` : "No UV reading",
    },
    {
      id: "ground",
      label: "Ground moisture input",
      level: soil >= 0.45 ? "watch" : "normal",
      detail: soil >= 0 ? `${Math.round(soil * 100)}% soil moisture; not a landslide forecast` : "No soil-moisture reading",
    },
  ];
}

export function safeZoneSearchUrl(city?: string, crisisType = "emergency shelter hospital community centre"): string {
  const query = [crisisType, city].filter(Boolean).join(" ");
  return `https://www.openstreetmap.org/search?query=${encodeURIComponent(query)}`;
}

export function getAuthorityRoute(countryCode?: string): AuthorityRoute {
  return AUTHORITY_ROUTES[String(countryCode ?? "").toUpperCase()] ?? AUTHORITY_ROUTES.DEFAULT;
}

export function getAuthorityRoutes(): AuthorityRoute[] {
  return Object.values(AUTHORITY_ROUTES);
}

export function buildSosPayload(input: SosPayloadInput): string {
  const location = typeof input.latitude === "number" && Number.isFinite(input.latitude) && typeof input.longitude === "number" && Number.isFinite(input.longitude)
    ? `${input.latitude.toFixed(5)}, ${input.longitude.toFixed(5)} (https://maps.google.com/?q=${input.latitude},${input.longitude})`
    : "Location unavailable. Share your nearest landmark.";
  const battery = typeof input.batteryPercent === "number" ? `${Math.round(input.batteryPercent)}%` : "unknown";
  const temperature = typeof input.temperatureC === "number" ? `${input.temperatureC.toFixed(1)}°C` : "unknown";
  return [
    "SAFEHANDS SOS",
    `Crisis: ${input.crisisType}`,
    `People: ${Math.max(1, Math.round(input.people))}`,
    `Vulnerable people: ${input.vulnerable.length ? input.vulnerable.join(", ") : "none reported"}`,
    `Location: ${location}`,
    `Emergency contact: ${input.contact?.trim() || "not provided"}`,
    `Battery: ${battery}`,
    `Last ambient temperature: ${temperature}`,
    "Call local emergency services if possible. This message is a request for help, not a verified dispatch.",
  ].join("\n");
}

export function openMeteoWeatherUrl(latitude: number, longitude: number): string {
  const params = new URLSearchParams({
    latitude: String(latitude),
    longitude: String(longitude),
    current: "temperature_2m,relative_humidity_2m,apparent_temperature,precipitation,pressure_msl,wind_speed_10m,uv_index",
    hourly: "precipitation,pressure_msl,soil_moisture_0_to_1cm",
    past_days: "2",
    forecast_days: "2",
    timezone: "auto",
  });
  return `https://api.open-meteo.com/v1/forecast?${params.toString()}`;
}

export function openMeteoAirQualityUrl(latitude: number, longitude: number): string {
  const params = new URLSearchParams({
    latitude: String(latitude),
    longitude: String(longitude),
    current: "pm2_5,us_aqi,uv_index",
    forecast_days: "2",
    timezone: "auto",
  });
  return `https://air-quality-api.open-meteo.com/v1/air-quality?${params.toString()}`;
}

export async function fetchOpenMeteoTelemetry(latitude: number, longitude: number, signal?: AbortSignal): Promise<ClimateTelemetry> {
  const [weatherResponse, airResponse] = await Promise.all([
    fetch(openMeteoWeatherUrl(latitude, longitude), { signal }),
    fetch(openMeteoAirQualityUrl(latitude, longitude), { signal }),
  ]);
  if (!weatherResponse.ok || !airResponse.ok) throw new Error("Telemetry service unavailable");
  const weather = await weatherResponse.json() as Record<string, any>;
  const air = await airResponse.json() as Record<string, any>;
  const hourlyPrecipitation = Array.isArray(weather.hourly?.precipitation) ? weather.hourly.precipitation : [];
  const pressure = Array.isArray(weather.hourly?.pressure_msl) ? weather.hourly.pressure_msl : [];
  const hourlyTimes = Array.isArray(weather.hourly?.time) ? weather.hourly.time : [];
  const nowMs = Date.parse(String(weather.current?.time ?? new Date().toISOString()));
  const currentIndex = hourlyTimes.length
    ? Math.max(0, hourlyTimes.findIndex((time: string) => Date.parse(time) >= nowMs))
    : 0;
  const previousPrecipitation = hourlyPrecipitation.slice(Math.max(0, currentIndex - 48), currentIndex);
  const nextPrecipitation = hourlyPrecipitation.slice(currentIndex, currentIndex + 48);
  return {
    observedAt: new Date().toISOString(),
    latitude,
    longitude,
    temperatureC: Number(weather.current?.temperature_2m),
    relativeHumidity: Number(weather.current?.relative_humidity_2m),
    windSpeedKmh: Number(weather.current?.wind_speed_10m),
    pressureHpa: Number(weather.current?.pressure_msl),
    pressureChangeHpa: pressure.length > currentIndex + 1 ? Number(pressure[currentIndex]) - Number(pressure[Math.max(0, currentIndex - 6)]) : undefined,
    precipitation48hMm: previousPrecipitation.reduce((sum: number, value: number) => sum + Number(value || 0), 0),
    precipitationNext48hMm: nextPrecipitation.reduce((sum: number, value: number) => sum + Number(value || 0), 0),
    soilMoisture: Array.isArray(weather.hourly?.soil_moisture_0_to_1cm) ? Number(weather.hourly.soil_moisture_0_to_1cm[currentIndex]) : undefined,
    uvIndex: Number(air.current?.uv_index ?? weather.current?.uv_index),
    pm25: Number(air.current?.pm2_5),
    usAqi: Number(air.current?.us_aqi),
    source: "open-meteo",
  };
}

export default {
  apparentTemperatureC,
  wetBulbTemperatureC,
  climateRisk,
  hydrationIntervalMinutes,
  makeHydrationPlan,
  precipitationRisk,
  makeRiskRadar,
  safeZoneSearchUrl,
  getAuthorityRoute,
  getAuthorityRoutes,
  buildSosPayload,
  openMeteoWeatherUrl,
  openMeteoAirQualityUrl,
  fetchOpenMeteoTelemetry,
};
