/** Typed errors for RFC 9457 problem+json responses from the Angel Engine API. */

export interface PolicyAlternative {
  kind: string;
  label: string;
  template?: string;
  connector_id?: string;
}

export interface PolicyPayload {
  decision_id?: string;
  decision: "allow" | "warn" | "review" | "refuse";
  categories: string[];
  rule_ids?: string[];
  rule_pack_version?: string;
  rationale?: string;
  alternatives?: PolicyAlternative[];
  notices?: string[];
}

export interface Problem {
  type: string;
  title: string;
  status: number;
  code: string;
  detail?: string;
  request_id?: string;
  [key: string]: unknown;
}

export class ApiError extends Error {
  readonly problem: Problem;
  constructor(problem: Problem) {
    super(problem.detail ?? problem.title);
    this.name = "ApiError";
    this.problem = problem;
  }
  get status(): number {
    return this.problem.status;
  }
  get code(): string {
    return this.problem.code;
  }
  get requestId(): string | undefined {
    return this.problem.request_id;
  }
}

export class PolicyRefusalError extends ApiError {
  get policy(): PolicyPayload {
    return this.problem.policy as PolicyPayload;
  }
}
export class PolicyAcknowledgementError extends ApiError {
  get policy(): PolicyPayload {
    return this.problem.policy as PolicyPayload;
  }
}
export class ValidationError extends ApiError {
  /** Field errors from FastAPI validation (values are never echoed back). */
  get fieldErrors(): { loc: (string | number)[]; msg: string }[] {
    return (this.problem.errors as { loc: (string | number)[]; msg: string }[] | undefined) ?? [];
  }
}
export class NotFoundOrForbiddenError extends ApiError {}
export class ConflictError extends ApiError {
  get allowedTransitions(): string[] {
    return (this.problem.allowed_transitions as string[] | undefined) ?? [];
  }
  get failedPreconditions(): Record<string, string[]> {
    return (this.problem.failed_preconditions as Record<string, string[]> | undefined) ?? {};
  }
}
export class PreconditionError extends ApiError {
  get currentVersion(): number | undefined {
    return this.problem.current_version as number | undefined;
  }
}
export class RateLimitError extends ApiError {
  get retryAfter(): number {
    return (this.problem.retry_after as number | undefined) ?? 60;
  }
}
export class ReauthRequiredError extends ApiError {}
export class UnauthenticatedError extends ApiError {}

const BY_SLUG: Record<string, new (p: Problem) => ApiError> = {
  "policy-refused": PolicyRefusalError,
  "policy-acknowledgement-required": PolicyAcknowledgementError,
  "validation-error": ValidationError,
  "not-found": NotFoundOrForbiddenError,
  forbidden: NotFoundOrForbiddenError,
  conflict: ConflictError,
  "conflict-state": ConflictError,
  "precondition-failed": PreconditionError,
  "precondition-required": PreconditionError,
  "rate-limited": RateLimitError,
  "reauth-required": ReauthRequiredError,
  unauthenticated: UnauthenticatedError,
};

export function toProblem(status: number, body: unknown): Problem {
  if (body && typeof body === "object" && "type" in body && "status" in body) {
    return body as Problem;
  }
  return {
    type: "/problems/http-error",
    title: status >= 500 ? "The server could not complete the request" : "The request failed",
    status,
    code: `http_${status}`,
  };
}

export function errorFor(status: number, body: unknown): ApiError {
  const problem = toProblem(status, body);
  const slug = problem.type.split("/").pop() ?? "";
  const Cls = BY_SLUG[slug] ?? ApiError;
  return new Cls(problem);
}

/** Human-readable message for toasts and inline alerts. */
export function messageOf(error: unknown): string {
  if (error instanceof ApiError) {
    const ref = error.requestId ? ` (reference ${error.requestId})` : "";
    return `${error.problem.detail ?? error.problem.title}${error.status >= 500 ? ref : ""}`;
  }
  if (error instanceof Error) return error.message;
  return "Something went wrong.";
}
