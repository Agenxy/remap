// SPDX-License-Identifier: GPL-3.0-or-later
// Bundles the `remap web` page script. The output is committed and embedded
// in the binary; `--check` fails when it no longer matches its sources.
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { build } from "esbuild";

const root = resolve(import.meta.dirname, "..");
const entry = resolve(root, "crates/remap-web/app/main.ts");
const output = resolve(root, "crates/remap-web/app/app.js");
const write = process.argv.includes("--write");
const check = process.argv.includes("--check");

if (write === check) {
  throw new Error("choose exactly one of --write or --check");
}

const result = await build({
  bundle: true,
  entryPoints: [entry],
  format: "iife",
  legalComments: "none",
  minify: true,
  platform: "browser",
  target: "es2024",
  write: false,
});
const bundled = result.outputFiles[0]?.contents;
if (bundled === undefined) {
  throw new Error("esbuild produced no web page script");
}

if (write) {
  await writeFile(output, bundled);
} else {
  const committed = await readFile(output);
  if (!committed.equals(bundled)) {
    throw new Error("crates/remap-web/app/app.js is stale; run bun run web:build");
  }
}
