#!/usr/bin/env node
// Callers: `npm run gen:api` and `scripts/verify-ui.sh`.
// API: emits `src/api/generated.ts` from `schemas/control-api-v2.json`.
// Schema: `schemas/control-api-v2.json`.
// User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified. Prioritize turning the existing SPA into the exceptional polished Sovereign UI specified by the plan, using the intended frontend stack and replacing placeholder frontend tooling with real tests/linting.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");
const schemaPath = resolve(root, "schemas/control-api-v2.json");
const outPath = resolve(root, "apps/sovereign/ui/src/api/generated.ts");
const schema = JSON.parse(readFileSync(schemaPath, "utf8"));

function tsType(node) {
  if (!node) {
    return "unknown";
  }
  if (node.$ref) {
    return node.$ref.replace("#/definitions/", "");
  }
  if (Array.isArray(node.type)) {
    return node.type.map((item) => (item === "null" ? "null" : tsType({ type: item }))).join(" | ");
  }
  if (node.enum) {
    return node.enum.map((value) => JSON.stringify(value)).join(" | ");
  }
  if (node.type === "array") {
    return `Array<${tsType(node.items)}>`;
  }
  if (node.type === "object") {
    const required = new Set(node.required ?? []);
    const fields = Object.entries(node.properties ?? {}).map(([key, value]) => {
      const optional = required.has(key) ? "" : "?";
      return `  ${key}${optional}: ${tsType(value)};`;
    });
    return `{\n${fields.join("\n")}\n}`;
  }
  if (node.type === "integer" || node.type === "number") {
    return "number";
  }
  if (node.type === "boolean") {
    return "boolean";
  }
  if (node.type === "string") {
    return "string";
  }
  return "unknown";
}

const lines = ["/** Generated from schemas/control-api-v2.json. Diff-checked by verify-ui.sh. */", ""];
for (const [name, def] of Object.entries(schema.definitions ?? {})) {
  lines.push(`export type ${name} = ${tsType(def)};`, "");
}

const next = `${lines.join("\n").trim()}\n`;
if (process.argv.includes("--check")) {
  const current = readFileSync(outPath, "utf8");
  if (current !== next) {
    console.error("generated.ts is stale; run npm run gen:api");
    process.exit(1);
  }
  process.exit(0);
}
writeFileSync(outPath, next);
console.log(`wrote ${outPath}`);
