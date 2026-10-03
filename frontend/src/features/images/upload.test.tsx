import { screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { UPLOAD_NOTICE } from "@/components/security/notices";
import { renderWithProviders } from "@/test/utils";

import { ImageUpload } from "./upload";

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));

describe("ImageUpload", () => {
  it("always shows the upload notice and offers a button alternative to dragging", () => {
    renderWithProviders(<ImageUpload investigationId="inv" />);
    expect(screen.getByText(UPLOAD_NOTICE)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Choose images" })).toBeInTheDocument();
  });
});
