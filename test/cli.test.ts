/**
 * The command line, exercised as a command line.
 *
 * These spawn `dist/cli.js` rather than importing the module, because the thing
 * being checked is the part a user touches: argument parsing, what lands on
 * stdout versus stderr, and the exit code. A test that imported the functions
 * directly would pass while `wacz-signer verify` returned 0 on a bad archive.
 *
 * That means a build first. It costs a couple of seconds and buys certainty
 * that what shipped is what was tested — `bin` points at `dist/cli.js`, so a
 * source-only test would be measuring something nobody runs.
 */
import { execFile, spawn } from "node:child_process";
import { once } from "node:events";
import { connect, createServer } from "node:net";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { SOFTWARE } from "../src/version.js";

const execFileAsync = promisify(execFile);

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "dist", "cli.js");

interface Run {
  stdout: string;
  stderr: string;
  code: number;
}

/** Run the CLI, returning its exit code rather than throwing on a non-zero one. */
async function signer(...argv: string[]): Promise<Run> {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [cli, ...argv], { cwd: root });
    return { stdout, stderr, code: 0 };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; code?: number };
    return { stdout: e.stdout ?? "", stderr: e.stderr ?? "", code: e.code ?? -1 };
  }
}

let dir: string;
let digest: string;
let caCert: string;

beforeAll(async () => {
  await execFileAsync("pnpm", ["run", "build"], { cwd: root });

  dir = await mkdtemp(join(tmpdir(), "wacz-signer-cli-"));
  caCert = join(dir, "id", "insecure-dev-ca.crt");
  digest = join(dir, "datapackage-digest.json");

  await signer("init", "--dir", join(dir, "id"), "--domain", "sign.dev.local");
  const target = join(dir, "datapackage.json");
  await writeFile(target, '{"profile":"data-package"}', "utf8");
  await signer("sign", "--dir", join(dir, "id"), "--file", target, "--out", digest);
}, 240_000);

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("wacz-signer sign", () => {
  it("writes a datapackage-digest.json the verifier accepts", async () => {
    const parsed: unknown = JSON.parse(await readFile(digest, "utf8"));
    expect(parsed).toMatchObject({
      path: "datapackage.json",
      hash: expect.stringMatching(/^sha256:[0-9a-f]{64}$/) as unknown,
    });

    const run = await signer("verify", "--file", digest, "--root", caCert);
    expect(run.code).toBe(0);
    expect(run.stdout).toContain("valid");
    expect(run.stdout).not.toContain("FAILED");
  }, 120_000);

  it("hashes the file it was pointed at", async () => {
    // The same bytes openssl would digest from a shell — if these disagree, the
    // signature covers something other than the archive it claims to.
    const target = join(dir, "datapackage.json");
    const { stdout } = await execFileAsync("openssl", ["dgst", "-sha256", "-r", target]);
    const expected = `sha256:${stdout.trim().split(/\s+/)[0] ?? ""}`;

    const parsed = JSON.parse(await readFile(digest, "utf8")) as { hash: string };
    expect(parsed.hash).toBe(expected);
  }, 30_000);
});

describe("wacz-signer verify", () => {
  it("exits non-zero when a stage fails", async () => {
    // A wrong root is the failure a caller most needs the exit code to catch,
    // since the output still says the signature itself is fine.
    const other = join(dir, "other");
    await signer("init", "--dir", other, "--domain", "sign.dev.local");

    const run = await signer("verify", "--file", digest, "--root", join(other, "insecure-dev-ca.crt"));
    expect(run.code).toBe(1);
    expect(run.stdout).toContain("not valid");
    expect(run.stdout).toMatch(/FAILED\s+chain/);
  }, 180_000);

  it("reports the chain as skipped, not failed, when no root is named", async () => {
    const run = await signer("verify", "--file", digest);
    expect(run.code).toBe(0);
    expect(run.stdout).toMatch(/skipped\s+chain/);
  }, 60_000);

  it("reads py-wacz's fixture, whose certificates expired years ago", async () => {
    const fixture = join(root, "test", "fixtures", "pywacz-signed.datapackage-digest.json");

    // Signed in January 2022 against a real Let's Encrypt certificate, so both
    // it and the timestamp authority's certificate are long gone. It passes
    // anyway, with no flag: the token fixes when the signature was made, and
    // that is the instant the certificates are judged against.
    //
    // This used to require --allow-expired, and the reason it did is the reason
    // the flag reads wrong now — it stops asking about time, where the token
    // answers the question.
    const strict = await signer("verify", "--file", fixture);
    expect(strict.code).toBe(0);
    expect(strict.stdout).toMatch(/ok\s+timestamp/);
    expect(strict.stdout).toContain("2022-01-18");

    // The flag still works, and still means something different: no time check
    // at all, for a payload with no token to anchor to.
    const lenient = await signer("verify", "--file", fixture, "--allow-expired");
    expect(lenient.code).toBe(0);
    expect(lenient.stdout).toMatch(/ok\s+signature/);
  }, 120_000);

  it("prints every openssl command under --explain", async () => {
    const run = await signer("verify", "--file", digest, "--root", caCert, "--explain");

    // The claim this package makes is that nothing happens outside openssl.
    // These lines are what lets a reader check that claim by hand.
    expect(run.stderr).toContain("+ openssl dgst -sha256 -verify");
    expect(run.stderr).toContain("+ openssl verify -CAfile");
    expect(run.stderr).toContain("+ openssl x509 -in leaf.pem -noout -checkhost");
    // stdout stays the report, so `--explain` can be added without breaking a pipe.
    expect(run.stdout).not.toContain("+ openssl");
  }, 60_000);

  it("prints the timestamp command too, when there is a timestamp to check", async () => {
    // `digest` above has none: signing without `--tsa-url` produces no token,
    // so the stage is skipped and the command never runs. py-wacz's fixture
    // carries a real one, which makes it the input that reaches this line.
    const fixture = join(root, "test", "fixtures", "pywacz-signed.datapackage-digest.json");
    const run = await signer("verify", "--file", fixture, "--allow-expired", "--explain");

    expect(run.stderr).toContain("+ openssl ts -verify");
  }, 60_000);
});

describe("wacz-signer's argument handling", () => {
  it("prints usage and exits 0 with no command", async () => {
    const run = await signer();
    expect(run.code).toBe(0);
    // Every subcommand is listed. Asserting the set rather than one literal
    // line: a command added without a description, or dropped by accident,
    // fails here.
    for (const name of ["init", "sign", "verify", "serve"]) {
      expect(run.stdout).toContain(name);
    }
  }, 30_000);

  it("exits 2 on an unknown command", async () => {
    const run = await signer("frobnicate");
    expect(run.code).toBe(2);
  }, 30_000);

  it("exits 2 when a required flag is missing", async () => {
    const run = await signer("verify");
    expect(run.code).toBe(2);
    // Names the option that is missing. The exact phrasing is commander's and
    // not worth pinning; that it identifies `--file` is the part a reader
    // needs.
    expect(run.stderr).toContain("--file");
    expect(run.stderr).toMatch(/required|not specified/i);
  }, 30_000);
});

describe("wacz-signer's paths", () => {
  it("accepts a relative --dir", async () => {
    // openssl runs with the identity directory as its cwd, so a relative --dir
    // used to be applied twice: `--dir ./id` looked for `./id/./id/insecure-dev-ca.key`.
    // openssl reported it as "Can't open ... for writing", which reads like a
    // permissions problem, and every existing test passed absolute paths from
    // mkdtemp so nothing caught it.
    const run = await signer("init", "--dir", "./relative-id", "--domain", "sign.dev.local");
    expect(run.code).toBe(0);
    expect(existsSync(join(root, "relative-id", "insecure-dev-ca.crt"))).toBe(true);

    await rm(join(root, "relative-id"), { recursive: true, force: true });
  }, 180_000);
});

/**
 * What the hand-rolled parser let through.
 *
 * Written before the switch to commander and watched fail, so the record shows
 * what the change was for. Swapping one parser for another is not a
 * user-visible improvement; these four are.
 */
describe("argument parsing the hand-rolled version got wrong", () => {
  it("accepts --flag=value", async () => {
    // The universally expected form. The old parser treated `--dir=/x` as a
    // boolean flag literally named `dir=/x`, so `--dir` came out missing and
    // the command exited 2 without creating anything.
    const target = join(dir, "eq-form");
    const run = await signer("init", `--dir=${target}`, "--domain=sign.dev.local");

    expect(run.code).toBe(0);
    expect(existsSync(join(target, "insecure-dev-ca.crt"))).toBe(true);
  }, 180_000);

  it("refuses a flag it does not recognise", async () => {
    // The one that matters. `--singer-days` is a plausible typo for
    // `--signer-days`, and the old parser accepted it in silence — leaving
    // --signer-days at its 90-day default, so an identity meant to be already
    // expired came out valid and verified cleanly. Being able to make an
    // expired identity is the main reason signer runs its own CA.
    const run = await signer(
      "init", "--dir", join(dir, "typo"), "--domain", "sign.dev.local", "--singer-days", "0",
    );

    expect(run.code).not.toBe(0);
    expect(run.stderr).toContain("singer-days");
    expect(existsSync(join(dir, "typo", "insecure-dev-ca.crt"))).toBe(false);
  }, 60_000);

  it("prints a version rather than the usage text", async () => {
    const run = await signer("--version");

    expect(run.code).toBe(0);
    expect(run.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  }, 30_000);

  it("prints the version package.json declares, not a stale copy of it", async () => {
    // src/cli.ts holds the number as a literal, so that startup never depends
    // on resolving a path relative to dist/ — which differs between `node
    // dist/cli.js`, a global install and the container. The cost of that is a
    // second place to forget, and it had already drifted once: the tags were at
    // v0.2.1 while the literal still said 0.1.0. Nobody noticed because
    // `--version` did not work yet.
    const pkg: unknown = JSON.parse(
      await readFile(new URL("../package.json", import.meta.url), "utf8"),
    );
    const declared = (pkg as { version: string }).version;

    const run = await signer("--version");

    expect(run.stdout.trim()).toBe(declared);
    // And the copy that outlives the process: `software` is written into every
    // signature, so a stale value there is baked into archives.
    expect(SOFTWARE).toBe(`wacz-signer/${declared}`);
  }, 30_000);

  it("documents each subcommand's own options", async () => {
    // The old usage was one fixed block covering every command at once, so
    // `wacz-signer init --help` could not tell you what init takes.
    const run = await signer("init", "--help");

    expect(run.code).toBe(0);
    expect(run.stdout).toContain("--signer-days");
    expect(run.stdout).not.toContain("--allow-expired");
  }, 30_000);
});

/** 空いている口を 1 つ借りる。開いて閉じるので、その間に取られる隙はあるが、試験には足りる。 */
const freePort = async (): Promise<number> => {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("口の番号が取れない");
  await new Promise<void>((resolve, reject) => {
    server.close((err) => {
      if (err) reject(err);
      else resolve();
    });
  });
  return address.port;
};

/** TCP が繋がるか（繋がったら即切る）。127.0.0.1 なので名前は引かない。 */
const connects = (port: number): Promise<boolean> =>
  new Promise((resolve) => {
    const socket = connect(port, "127.0.0.1");
    socket.once("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("error", () => {
      resolve(false);
    });
  });

/** 条件が真になるまで 50 ms ごとに見る。期限を過ぎたら投げる。 */
const until = async (check: () => Promise<boolean>, ms: number): Promise<void> => {
  const deadline = Date.now() + ms;
  while (!(await check())) {
    if (Date.now() > deadline) throw new Error(`${String(ms)} ms 待っても条件が真にならない`);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
};

/** 期限付きで待つ。期限の時計は、どちらが先でも止める。 */
const withTimeout = async <T>(promise: Promise<T>, ms: number, what: string): Promise<T> => {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          reject(new Error(`${what}（${String(ms)} ms）`));
        }, ms);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
};

/**
 * serve の止め方。
 *
 * コンテナでは node が PID 1 で、PID 1 には既定の振る舞い（終了）の信号が届かない。handler が無いと
 * SIGTERM を無視して猶予の後に SIGKILL で殺され、compose の down は 1 台 10 秒待つ。PID 1 の形は
 * 手元では再現できないので、ここで見るのは「受けたら閉じて 0 で終わる」こと。handler が無いと
 * 子プロセスは信号で死ぬ（{ code: null, signal: "SIGTERM" }）。
 */
describe("serve の止め方", () => {
  it.each(["SIGTERM", "SIGINT"] as const)(
    "%s を受けたら、受け付けを閉じて終了コード 0 で終わる",
    async (signal) => {
      const port = await freePort();
      const child = spawn(
        process.execPath,
        [cli, "serve", "--dir", join(dir, "id"), "--host", "127.0.0.1", "--port", String(port)],
        { cwd: root, stdio: ["ignore", "ignore", "pipe"] },
      );
      let stderrText = "";
      child.stderr.on("data", (chunk: Buffer) => {
        stderrText += chunk.toString();
      });
      try {
        await until(() => connects(port), 5_000);
        const exited = once(child, "exit");
        child.kill(signal);
        const [code, sig] = (await withTimeout(exited, 2_000, "終わるのを待つ")) as [
          number | null,
          NodeJS.Signals | null,
        ];
        expect({ code, sig }).toEqual({ code: 0, sig: null });
        expect(stderrText).toContain(`${signal} を受けた`);
      } finally {
        if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
      }
    },
    15_000,
  );
});
