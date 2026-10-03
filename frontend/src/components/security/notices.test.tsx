import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { FACE_NOTICE, FaceNotice, INSUFFICIENT, UPLOAD_NOTICE, UploadNotice } from "./notices";

describe("required notices", () => {
  it("keep their exact wording", () => {
    expect(FACE_NOTICE).toBe("A face was detected in the image. Angel Engine does not perform facial identification.");
    expect(UPLOAD_NOTICE).toBe(
      "Upload only images you are legally authorized to investigate. Angel Engine does not perform facial identification.",
    );
    expect(INSUFFICIENT).toBe("Insufficient public evidence to establish this conclusion.");
  });

  it("render verbatim", () => {
    render(
      <>
        <FaceNotice />
        <UploadNotice />
      </>,
    );
    expect(screen.getByText(FACE_NOTICE)).toBeInTheDocument();
    expect(screen.getByText(UPLOAD_NOTICE)).toBeInTheDocument();
  });
});
