import { execFileSync } from "node:child_process";
import { gzipSync } from "node:zlib";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const root = process.cwd();
const failures = [];

function file(path) {
  return join(root, path);
}

function requireFile(path) {
  if (!existsSync(file(path))) failures.push(`missing ${path}`);
}

function pass(label) {
  console.log(`PASS ${label}`);
}

function fail(label) {
  failures.push(label);
}

for (const required of [
  ".git",
  "package-lock.json",
  ".nvmrc",
  "Dockerfile",
  "README.md",
  ".env.example",
  "package.json",
  "src/triage.ts",
  "src/scam.ts",
  "src/climate.ts",
  "src/data/climate-protocols.json",
  "src/data/authority-directory.json",
  "public/sw.js",
]) requireFile(required);

try {
  execFileSync("git", ["rev-parse", "--verify", "HEAD"], { cwd: root, stdio: "ignore" });
  pass("git repository has at least one commit");
} catch {
  fail("git repository has no commit");
}

const packageJson = JSON.parse(readFileSync(file("package.json"), "utf8"));
if (packageJson.scripts?.test === "vitest run") pass("npm test is the single Vitest command");
else fail("package.json test script is not exactly vitest run");
if (packageJson.engines?.node?.includes("22.14.0")) pass("Node engine is pinned to the Node 22 line");
else fail("Node engine is not pinned");
if (readFileSync(file(".nvmrc"), "utf8").trim() === "22.14.0") pass(".nvmrc pins Node 22.14.0");
else fail(".nvmrc does not pin Node 22.14.0");

const envExample = readFileSync(file(".env.example"), "utf8");
if (!/(API_KEY|TOKEN|SECRET)\s*=\s*[^\n]+/i.test(envExample)) pass(".env.example contains no populated secret setting");
else fail(".env.example contains a populated secret setting");

const sourceRoots = ["src", "public", "index.html", "README.md", "DEMO.md", "Dockerfile", "vite.config.ts", "vitest.config.ts"];
function walk(path) {
  const absolute = file(path);
  if (!existsSync(absolute)) return [];
  if (statSync(absolute).isFile()) return [absolute];
  return readdirSync(absolute, { withFileTypes: true }).flatMap((entry) => walk(join(path, entry.name)));
}
const inspected = sourceRoots.flatMap(walk);
const absolutePathPattern = /(?:^|[^A-Za-z0-9])(?:[A-Za-z]:[\\/]|\/Users\/|\/home\/)/;
const secretPattern = /(?:BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|AIza[0-9A-Za-z_-]{20,}|(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{12,})/;
for (const absolute of inspected) {
  const contents = readFileSync(absolute, "utf8");
  const relativePath = relative(root, absolute);
  if (absolutePathPattern.test(contents)) fail(`absolute machine path found in ${relativePath}`);
  if (secretPattern.test(contents)) fail(`secret-like literal found in ${relativePath}`);
}
if (!failures.some((item) => /absolute machine path/.test(item))) pass("no absolute machine paths in app/config/docs");
if (!failures.some((item) => /secret-like literal/.test(item))) pass("no secret-like literals in app/config/docs");

const localeDirectory = file("src/data/locales");
const localeFiles = readdirSync(localeDirectory).filter((name) => name.endsWith(".json")).sort();
const localeKeys = localeFiles.map((name) => Object.keys(JSON.parse(readFileSync(join(localeDirectory, name), "utf8"))).sort().join("\n"));
const expectedLocaleFiles = ["ar.json", "bn.json", "en.json", "es.json", "fr.json", "ha.json", "hi.json", "pcm.json", "pt.json", "sw.json", "yo.json"];
if (JSON.stringify(localeFiles) === JSON.stringify(expectedLocaleFiles) && new Set(localeKeys).size === 1) pass("eleven locale JSON files have identical key sets");
else fail("locale JSON key sets differ or a locale is missing");

const fixtureCount = JSON.parse(readFileSync(file("src/data/scam-fixtures.json"), "utf8")).length;
if (fixtureCount >= 60) pass(`Scam Shield corpus has ${fixtureCount} fixtures`);
else fail("Scam Shield corpus has fewer than 60 fixtures");

const dist = file("dist");
if (existsSync(dist)) {
  const assets = walk("dist").filter((path) => path.endsWith(".js"));
  const gzippedBytes = assets.reduce((total, path) => total + gzipSync(readFileSync(path)).length, 0);
  if (gzippedBytes < 200 * 1024) pass(`initial JavaScript is ${gzippedBytes} bytes gzipped`);
  else fail(`initial JavaScript is ${gzippedBytes} bytes gzipped, over 200 KB`);
  const worker = file("dist/sw.js");
  const workerText = existsSync(worker) ? readFileSync(worker, "utf8") : "";
  for (const asset of ["./data/triage-protocol.json", "./data/facilities.json", "./data/scam-fixtures.json", "./data/climate-protocols.json", "./data/authority-directory.json", "./data/locales/en.json"]) {
    if (!workerText.includes(asset)) fail(`generated service worker does not precache ${asset}`);
  }
  if (workerText && !failures.some((item) => /generated service worker/.test(item))) pass("generated service worker precaches local health, climate, scam, and locale data");
} else {
  fail("dist is missing; run npm run build before the checklist");
}

if (failures.length) {
  console.error("\nBUILDATHON CHECKLIST FAILED");
  for (const failure of failures) console.error(`FAIL ${failure}`);
  process.exitCode = 1;
} else {
  console.log("\nBUILDATHON CHECKLIST PASSED");
}
