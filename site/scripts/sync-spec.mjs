// Mirror repo-root ./spec/*.md into site/src/content/docs/spec/*.md so Starlight
// can render them. Canonical source stays at ./spec/; this mirror is gitignored.
//
// Invoked automatically by `pnpm dev` and `pnpm build` via the package.json
// predev / prebuild hooks.
//
// Idempotent: safe to re-run. Removes entries in the mirror that no longer exist
// in the source (handles renames and deletions cleanly).

import { readdir, readFile, writeFile, mkdir, rm, stat } from "node:fs/promises";
import { dirname, join, resolve, basename } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SITE_ROOT = resolve(__dirname, "..");
const REPO_ROOT = resolve(SITE_ROOT, "..");
const SPEC_DIR = join(REPO_ROOT, "spec");
const DEST_DIR = join(SITE_ROOT, "src/content/docs/spec");

// Ordering hint for Starlight's sidebar — matches the numeric prefix on spec files.
const specOrder = (filename) => {
  const match = filename.match(/^(\d+)/);
  return match ? Number(match[1]) : 999;
};

async function listSpecFiles() {
  const entries = await readdir(SPEC_DIR, { withFileTypes: true });
  return entries
    .filter((e) => e.isFile() && e.name.endsWith(".md"))
    .map((e) => e.name)
    .sort();
}

async function mirrorFile(filename) {
  const srcPath = join(SPEC_DIR, filename);
  const destPath = join(DEST_DIR, filename);
  const raw = await readFile(srcPath, "utf8");

  // Ensure a Starlight-compatible frontmatter block with a sidebar order.
  const order = specOrder(filename);
  let body = raw;
  let frontmatter = {};
  const fmMatch = raw.match(/^---\n([\s\S]*?)\n---\n?/);
  if (fmMatch) {
    body = raw.slice(fmMatch[0].length);
    for (const line of fmMatch[1].split("\n")) {
      const m = line.match(/^([A-Za-z0-9_]+)\s*:\s*(.*)$/);
      if (m) frontmatter[m[1]] = m[2].trim();
    }
  }
  const title = frontmatter.title ?? basename(filename, ".md");

  const out = [
    "---",
    `title: ${JSON.stringify(title)}`,
    `sidebar:`,
    `  order: ${order}`,
    `editUrl: https://github.com/kaicoder03/openhost/edit/main/spec/${filename}`,
    "---",
    "",
    body.trimStart(),
  ].join("\n");

  await writeFile(destPath, out, "utf8");
}

async function pruneStale(expected) {
  let existing;
  try {
    existing = await readdir(DEST_DIR);
  } catch (err) {
    if (err && err.code === "ENOENT") return;
    throw err;
  }
  const wanted = new Set(expected);
  for (const name of existing) {
    if (!wanted.has(name) && name !== ".gitkeep") {
      await rm(join(DEST_DIR, name), { force: true });
    }
  }
}

async function main() {
  try {
    await stat(SPEC_DIR);
  } catch {
    console.error(`sync-spec: no spec/ directory at ${SPEC_DIR}`);
    process.exit(1);
  }
  await mkdir(DEST_DIR, { recursive: true });
  const files = await listSpecFiles();
  await pruneStale(files);
  for (const f of files) await mirrorFile(f);
  console.log(`sync-spec: mirrored ${files.length} file(s) into ${DEST_DIR}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
