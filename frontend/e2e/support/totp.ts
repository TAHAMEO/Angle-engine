import { createHmac } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

const STEP_MS = 30_000;
const LEDGER = "e2e/.auth/totp-steps.json";

function base32(secret: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const char of secret.replace(/=+$/, "")) bits += alphabet.indexOf(char).toString(2).padStart(5, "0");
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

/** RFC 6238 code (SHA-1, 6 digits, 30-second steps) — what an authenticator app shows. */
export function totp(secret: string, step: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac("sha1", base32(secret)).update(counter).digest();
  const offset = mac[mac.length - 1]! & 0x0f;
  return ((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).toString().padStart(6, "0");
}

function readLedger(): Record<string, number> {
  try {
    return JSON.parse(readFileSync(LEDGER, "utf8")) as Record<string, number>;
  } catch {
    return {};
  }
}

/**
 * A code for a time step this account has not used yet. The server accepts each step once (replay protection), so
 * signing the same account in twice within 30 seconds has to wait for the next step. Used steps are recorded in a
 * ledger shared by the setup project and the test workers.
 */
export async function freshCode(email: string, secret: string): Promise<string> {
  const ledger = readLedger();
  let step = Math.floor(Date.now() / STEP_MS);
  const last = ledger[email] ?? -1;
  if (step <= last) {
    await new Promise((resolve) => setTimeout(resolve, (last + 1) * STEP_MS - Date.now() + 500));
    step = Math.floor(Date.now() / STEP_MS);
  }
  ledger[email] = step;
  mkdirSync(dirname(LEDGER), { recursive: true });
  writeFileSync(LEDGER, JSON.stringify(ledger));
  return totp(secret, step);
}
