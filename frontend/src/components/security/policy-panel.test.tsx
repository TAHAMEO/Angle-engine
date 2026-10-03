import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { renderWithProviders } from "@/test/utils";

import { PolicyDecisionPanel } from "./policy-panel";

describe("PolicyDecisionPanel", () => {
  it("refuses with a reason and lawful alternatives, without echoing the request", async () => {
    const onUse = vi.fn();
    renderWithProviders(
      <PolicyDecisionPanel
        policy={{
          decision: "refuse",
          categories: ["home_address"],
          rationale: "Home addresses of private individuals are never searched.",
          alternatives: [{ kind: "template", label: "Research the organization's registered office", template: "registered office of ACME" }],
        }}
        onUseAlternative={onUse}
      />,
    );
    expect(screen.getByRole("alert")).toHaveTextContent("Angel Engine can't help with this request");
    expect(screen.getByText(/Home addresses of individuals/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Use this instead" }));
    expect(onUse).toHaveBeenCalledWith(expect.objectContaining({ template: "registered office of ACME" }));
  });

  it("explains a pending supervisor review", () => {
    renderWithProviders(<PolicyDecisionPanel policy={{ decision: "review", categories: ["individual_subject"] }} />);
    expect(screen.getByRole("status")).toHaveTextContent("This needs a supervisor's review");
  });

  it("asks for acknowledgement of warnings", async () => {
    const onAck = vi.fn();
    renderWithProviders(
      <PolicyDecisionPanel policy={{ decision: "warn", categories: [], notices: ["Locations are generalized to region level."] }} onAcknowledge={onAck} />,
    );
    expect(screen.getByText("Locations are generalized to region level.")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /I understand/ }));
    expect(onAck).toHaveBeenCalledOnce();
  });

  it("renders nothing for allowed requests", () => {
    const { container } = renderWithProviders(<PolicyDecisionPanel policy={{ decision: "allow", categories: [] }} />);
    expect(container).toBeEmptyDOMElement();
  });
});
