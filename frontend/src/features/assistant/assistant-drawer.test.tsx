import { screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { INSUFFICIENT } from "@/components/security/notices";
import type { InteractionOut } from "@/lib/api/types";
import { renderWithProviders } from "@/test/utils";

import { InteractionView } from "./assistant-drawer";

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn(), replace: vi.fn() }) }));

function interaction(overrides: Partial<InteractionOut>): InteractionOut {
  return {
    id: "i1",
    task: "chat",
    status: "completed",
    provider: "fake",
    provider_label: "offline demo AI",
    model: "fake-offline-demo",
    grounding: "partial",
    grounding_label: "Some statements are uncited AI commentary",
    segments: [],
    proposals: [],
    cited_evidence: [],
    context_documents: 3,
    created_at: "2026-10-03T00:00:00Z",
    completed_at: "2026-10-03T00:00:05Z",
    error_code: null,
    expired: false,
    poll_after_ms: null,
    request: null,
    requested_by_me: true,
    validation: {},
    verdict: null,
    uncited_label: "Uncited AI commentary",
    ...overrides,
  };
}

describe("InteractionView", () => {
  it("renders cited statements with evidence chips and labels uncited commentary", () => {
    renderWithProviders(
      <InteractionView
        investigationId="inv"
        canWrite
        interaction={interaction({
          segments: [
            { kind: "cited", text: "The roastery opened in March.", citations: [{ evidence_id: "e1", label: "E-14", cited_text: "opened a second roastery" }] },
            { kind: "uncited", text: "This suggests growth.", citations: [] },
          ],
        })}
      />,
    );
    expect(screen.getByText("The roastery opened in March.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Evidence E-14" })).toBeInTheDocument();
    expect(screen.getByText("[Uncited AI commentary]")).toBeInTheDocument();
    expect(screen.getByText("AI hypothesis")).toBeInTheDocument();
  });

  it("shows the insufficient-evidence answer verbatim", () => {
    renderWithProviders(
      <InteractionView
        investigationId="inv"
        canWrite
        interaction={interaction({
          grounding: "insufficient_evidence",
          grounding_label: "Insufficient public evidence",
          segments: [{ kind: "notice", text: INSUFFICIENT, citations: [] }],
        })}
      />,
    );
    expect(screen.getByRole("note")).toHaveTextContent(INSUFFICIENT);
  });

  it("shows progress while the request runs and never renders HTML from the model", () => {
    const { rerender } = renderWithProviders(
      <InteractionView investigationId="inv" canWrite interaction={interaction({ status: "running", segments: [] })} />,
    );
    expect(screen.getByRole("status")).toHaveTextContent(/Reading 3 evidence documents/);
    rerender(
      <InteractionView
        investigationId="inv"
        canWrite
        interaction={interaction({ segments: [{ kind: "plain", text: "<img src=x onerror=alert(1)>", citations: [] }] })}
      />,
    );
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
  });
});
