#!/usr/bin/env node

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { sanitizeMcpLine } from "./mcp-output-sanitizer.mjs";

const secret = process.env.LAW_OC || "";
if (!secret) {
  process.stderr.write("LAW_OC 사용자 환경변수가 필요합니다.\n");
  process.exit(2);
}

const here = dirname(fileURLToPath(import.meta.url));
const server = resolve(here, "../node_modules/korean-law-mcp/build/index.js");
const child = spawn(process.execPath, [server], {
  cwd: resolve(here, ".."),
  env: { ...process.env },
  stdio: ["pipe", "pipe", "pipe"],
  windowsHide: true,
});

process.stdin.pipe(child.stdin);

function forwardSanitized(stream, destination) {
  stream.setEncoding("utf8");
  let pending = "";
  stream.on("data", (chunk) => {
    pending += chunk;
    const lines = pending.split(/\r?\n/);
    pending = lines.pop() || "";
    for (const line of lines) destination.write(`${sanitizeMcpLine(line, secret)}\n`);
  });
  stream.on("end", () => {
    if (pending) destination.write(sanitizeMcpLine(pending, secret));
  });
}

forwardSanitized(child.stdout, process.stdout);
forwardSanitized(child.stderr, process.stderr);

child.on("error", () => {
  process.stderr.write("한국법 MCP 하위 프로세스를 시작하지 못했습니다.\n");
  process.exitCode = 1;
});
child.on("exit", (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  else process.exitCode = code ?? 1;
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => child.kill(signal));
}
