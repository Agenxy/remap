import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { build } from "esbuild";

const root = resolve(import.meta.dirname, "..");
const entry = resolve(root, "crates/remap-mcp/app/dashboard.ts");
const output = resolve(root, "crates/remap-mcp/app/dashboard.js");
const write = process.argv.includes("--write");
const check = process.argv.includes("--check");
const metadataIndex = process.argv.indexOf("--metadata");
const metadata = metadataIndex === -1 ? undefined : process.argv.at(metadataIndex + 1);

if (write === check) {
  throw new Error("choose exactly one of --write or --check");
}
if (metadataIndex !== -1 && metadata === undefined) {
  throw new Error("--metadata requires an output path");
}

const result = await build({
  bundle: true,
  entryPoints: [entry],
  format: "iife",
  legalComments: "none",
  minify: true,
  metafile: metadata !== undefined,
  platform: "browser",
  target: "es2024",
  write: false,
});
const bundled = result.outputFiles[0]?.contents;
if (bundled === undefined) {
  throw new Error("esbuild produced no dashboard artifact");
}

if (write) {
  await writeFile(output, bundled);
} else {
  const committed = await readFile(output);
  if (!committed.equals(bundled)) {
    throw new Error("dashboard.js is stale; run bun run app:build");
  }
}
if (metadata !== undefined && result.metafile !== undefined) {
  await writeFile(metadata, `${JSON.stringify(result.metafile)}\n`);
}
