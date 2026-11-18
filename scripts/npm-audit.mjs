#!/usr/bin/env node
// npm の lockfile の audit を、名指しの勧告だけ見逃して走らせる。
//
// 使い方: node scripts/npm-audit.mjs <dir>...   (例: node scripts/npm-audit.mjs docs-site)
//
// npm audit には pnpm の auditConfig.ignoreGhsas に当たる除外が無いので、`npm audit --json` を
// 読んで、下の IGNORED_GHSAS に無い勧告が 1 件でも在れば exit 1 にする。重さは問わない
// (`--audit-level=low` と同じく、通るのは 0 件だけ)。install は要らない (lockfile を読む)。
//
// 見逃してよいのは、直った版が無く、この repo に届かない勧告だけ。足すときは pnpm の
// ignoreGhsas と同じく、理由と外す条件を隣に書く。外す条件を満たしたら、行を消しても
// この script が exit 0 になることを確かめて消す。
import { execFileSync } from "node:child_process";

const IGNORED_GHSAS = [
  // picomatch: 単一の枝を繰り返す extglob (`+(*)` など) の ReDoS (high)。
  // 勧告の範囲は <= 4.0.7 で 2 系も含み、直った版はまだ無い (2026-11-18 の時点で npm の
  // 最新は 4.0.7。直しの PR は micromatch/picomatch の #265〜#273 で未 merge)。上げる先が
  // 無いので、lockfile の更新でも override でも越えられない。
  // 要求元は docs-site の astro・@astrojs/internal-helpers・vite・tinyglobby・fdir・anymatch (2.3.2)。
  // docs は静的な HTML として出る。picomatch が読むパターンは、build の間のこの repo の設定と、
  // Astro・vite の内部の物だけで、外の入力は入らない。
  // 外す条件: 勧告に直った版 (first_patched_version) が載ったとき。
  // `npm update picomatch --prefix docs-site --package-lock-only` で上げ、この行を消しても
  // この script が exit 0 になれば消す (CAPTURE-483・外すのは CAPTURE-484)。
  "GHSA-fc5q-39xc-vjpf",
];

const dirs = process.argv.slice(2);
if (dirs.length === 0) {
  console.error("usage: node scripts/npm-audit.mjs <dir>...");
  process.exit(2);
}

let failed = false;
const seen = new Set();
for (const dir of dirs) {
  let out;
  try {
    out = execFileSync("npm", ["audit", "--prefix", dir, "--json"], { encoding: "utf8" });
  } catch (error) {
    // 勧告が在ると npm audit は exit 1 だが、JSON は stdout に出ている。
    out = error.stdout;
  }
  let report;
  try {
    report = JSON.parse(out);
  } catch {
    console.error(`${dir}: npm audit の出力を JSON として読めない:\n${out}`);
    process.exit(2);
  }
  if (report.error) {
    console.error(`${dir}: npm audit が失敗した: ${JSON.stringify(report.error)}`);
    process.exit(2);
  }

  // vulnerabilities の via のうち object の物が勧告そのもの (文字列は依存の名前で、
  // その先の勧告を指すだけ)。
  const found = new Map();
  for (const vulnerability of Object.values(report.vulnerabilities ?? {})) {
    for (const via of vulnerability.via) {
      if (typeof via !== "object") continue;
      const ghsa = via.url.split("/").pop();
      const entry = found.get(ghsa) ?? { via, packages: new Set() };
      entry.packages.add(`${via.name}@${via.range}`);
      found.set(ghsa, entry);
    }
  }

  for (const [ghsa, { via, packages }] of found) {
    const ignored = IGNORED_GHSAS.includes(ghsa);
    if (!ignored) failed = true;
    console.log(
      `${dir}: ${ignored ? "ignored" : "FOUND  "} ${ghsa} (${via.severity}) ${via.title} — ${[...packages].join(", ")} ${via.url}`,
    );
  }
  for (const ghsa of found.keys()) seen.add(ghsa);
  if (found.size === 0) console.log(`${dir}: found 0 vulnerabilities`);
}
for (const ghsa of IGNORED_GHSAS) {
  if (!seen.has(ghsa)) {
    console.log(
      `unused  ${ghsa} — どの lockfile にももう当たらない。外す条件を見て IGNORED_GHSAS から消す`,
    );
  }
}
process.exit(failed ? 1 : 0);
