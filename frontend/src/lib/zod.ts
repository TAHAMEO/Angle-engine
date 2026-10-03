import { z } from "zod";

/*
 * Zod compiles object parsers with `new Function` when it thinks eval is available, and its feature probe alone
 * trips the Content-Security-Policy (no 'unsafe-eval'), filing a violation report on every form. Use the
 * interpreter everywhere; import `z` from here, never from "zod" directly (lint rule).
 */
z.config({ jitless: true });

export { z };
