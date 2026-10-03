import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ExternalLink } from "./external-link";

describe("ExternalLink", () => {
  it("opens public pages without referrer or opener", () => {
    render(<ExternalLink href="https://news.example.org/story" />);
    const link = screen.getByRole("link");
    expect(link).toHaveAttribute("rel", "noopener noreferrer nofollow");
    expect(link).toHaveAttribute("referrerpolicy", "no-referrer");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveTextContent("news.example.org");
  });

  it("shows look-alike hostnames in punycode", () => {
    render(<ExternalLink href="https://exаmple.com/" />); // Cyrillic "а"
    expect(screen.getByRole("link")).toHaveTextContent("xn--");
  });

  it.each(["javascript:alert(1)", "data:text/html,hi", "file:///etc/passwd", "not a url"])("never links %s", (href) => {
    render(<ExternalLink href={href}>label</ExternalLink>);
    expect(screen.queryByRole("link")).toBeNull();
  });
});
