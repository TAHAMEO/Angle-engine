import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { renderWithProviders } from "@/test/utils";

import { ConfidenceLevel, PROVENANCE, ProvenanceBadge, STATUS, VerificationStatusBadge } from "./badges";

describe("provenance kit", () => {
  it.each(Object.entries(STATUS))("labels status %s with text and an icon", (status, meta) => {
    const { container } = renderWithProviders(<VerificationStatusBadge status={status} />);
    expect(screen.getByText(meta.label)).toBeInTheDocument();
    expect(container.querySelector("svg")).not.toBeNull(); // never colour alone
  });

  it.each(Object.entries(PROVENANCE))("labels provenance %s", (provenance, meta) => {
    renderWithProviders(<ProvenanceBadge provenance={provenance} />);
    expect(screen.getByText(meta.label)).toBeInTheDocument();
  });

  it("draws AI hypotheses with a dashed border", () => {
    renderWithProviders(<VerificationStatusBadge status="ai_hypothesis" />);
    expect(screen.getByText("AI hypothesis").closest(".badge")?.className).toContain("border-dashed");
  });

  it("falls back safely for unknown values", () => {
    renderWithProviders(<VerificationStatusBadge status="made_up" />);
    expect(screen.getByText("Unverified")).toBeInTheDocument();
  });

  it("shows n/a when no confidence applies", () => {
    renderWithProviders(<ConfidenceLevel confidence={null} />);
    expect(screen.getByText("n/a")).toBeInTheDocument();
  });
});
