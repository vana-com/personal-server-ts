import { describe, expect, it } from "vitest";
import { escapeHtml, renderAccountPage } from "./account-page.js";

describe("renderAccountPage", () => {
  it("escapes text inputs and keeps pre-rendered body HTML as is", () => {
    const html = renderAccountPage({
      title: "<t>",
      headingAccent: "<a>",
      heading: "<h>",
      description: "<d>",
      bodyHtml: '<dl class="unity-details"><dd>x</dd></dl>',
    });

    expect(html).toContain("<title>&lt;t&gt;</title>");
    expect(html).toContain(
      '<span class="unity-header-title-accent">&lt;a&gt;</span><br>&lt;h&gt;',
    );
    expect(html).toContain("&lt;d&gt;</p>");
    expect(html).toContain('<dl class="unity-details"><dd>x</dd></dl>');
    expect(html).not.toContain("<h>");
  });

  it("is self-contained so it renders offline", () => {
    const html = renderAccountPage({
      title: "t",
      headingAccent: "a",
      heading: "h",
      script: "void 0;",
    });

    expect(html).not.toMatch(/<link[^>]+href="https?:/);
    expect(html).not.toMatch(/<script[^>]+src=/);
    expect(html).not.toMatch(/@import|url\(\s*["']?https?:/);
    expect(html).toContain("<script>void 0;</script>");
  });

  it("follows the system colour scheme like Vana Account", () => {
    const html = renderAccountPage({
      title: "t",
      headingAccent: "a",
      heading: "h",
    });

    expect(html).toContain('<meta name="color-scheme" content="light dark">');
    expect(html).toContain("@media (prefers-color-scheme: dark)");
  });

  it("drops the panel min-height for slim pages", () => {
    const slim = renderAccountPage({
      title: "t",
      headingAccent: "a",
      heading: "h",
      slim: true,
    });
    const full = renderAccountPage({
      title: "t",
      headingAccent: "a",
      heading: "h",
    });

    expect(slim).toContain('class="unity-panel unity-panel--slim"');
    expect(full).not.toContain('class="unity-panel unity-panel--slim"');
  });
});

describe("escapeHtml", () => {
  it("escapes the five HTML-significant characters", () => {
    expect(escapeHtml(`&<>"'`)).toBe("&amp;&lt;&gt;&quot;&#39;");
  });
});
