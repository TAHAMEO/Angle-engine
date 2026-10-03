/** A fresh idempotency key for one user action (retries of the same action reuse it). */
export function newIdempotencyKey(): string {
  return crypto.randomUUID();
}
