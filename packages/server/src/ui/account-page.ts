/**
 * Shared shell for the browser pages the Personal Server shows a person
 * (device approval and its terminal states).
 *
 * Mirrors Vana Account's Unity auth shell (canvas background, one rounded
 * panel, blue Vana logotype, accent lead-in heading, pill buttons) so a
 * `vana login` hand-off feels like it belongs to account.vana.org. Values are
 * copied from `packages/unity-design` in vana-com/unity-surfaces
 * (`tokens-primitive.css`, `shell.css`, `vana-logotype.tsx`).
 *
 * Everything is inline: these pages are served by a local server and must
 * render offline. Account self-hosts Inter and IBM Plex Mono, so we name them
 * first and fall back to system fonts rather than fetching anything.
 */

export interface AccountPageOptions {
  /** Document `<title>`. */
  title: string;
  /** Accent-coloured lead-in line of the heading (plain text). */
  headingAccent: string;
  /** Main heading line (plain text). */
  heading: string;
  /** Optional description under the heading (plain text). */
  description?: string;
  /** Pre-rendered, already-escaped HTML for the panel body. */
  bodyHtml?: string;
  /** Inline script contents, appended at the end of `<body>`. */
  script?: string;
  /**
   * Short interstitial pages (success/error) drop the panel's 480px
   * min-height, like Account's `UnityPanel slim`.
   */
  slim?: boolean;
}

export function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Vana logotype from Unity Design (`VanaLogotype`), filled with currentColor. */
const VANA_LOGOTYPE_SVG = `<svg class="unity-logotype" aria-label="Vana" role="img" viewBox="0 0 718 200" height="13" xmlns="http://www.w3.org/2000/svg" fill="currentColor"><path d="M344.76 99.9947C344.76 129.81 344.76 159.639 344.76 189.454C344.76 191.122 344.786 192.804 344.548 194.446C344.004 198.236 342.161 199.864 338.343 199.891C330.162 199.944 321.982 199.918 313.788 199.918C291.965 199.918 270.141 199.958 248.318 199.904C220.541 199.824 195.417 179.511 189.662 152.152C185.287 131.318 189.967 112.527 204.207 96.6715C211.446 88.6104 221.045 84.0193 231.453 81.31C243.306 78.2137 255.424 78.6008 267.503 78.6408C274.265 78.6675 281.026 78.6408 287.788 78.6408C294.987 78.6408 300.662 75.8782 304.255 69.3786C307.888 62.7989 307.371 56.2726 303.672 49.9999C301.312 45.9961 297.546 43.7139 293.012 42.9798C290.214 42.5261 287.351 42.3526 284.513 42.3392C264.228 42.2858 243.956 42.3259 223.67 42.3125C216.047 42.3125 213.727 39.9502 213.713 32.2362C213.7 24.3619 213.673 16.4877 213.726 8.61342C213.78 2.32737 215.848 0.325439 222.106 0.325439C259.945 0.325439 297.772 0.325439 335.611 0.325439C343.222 0.325439 344.773 1.83356 344.773 9.45423C344.786 39.6299 344.773 69.8056 344.773 99.9947H344.76ZM268.709 157.944C275.471 157.944 282.22 157.957 288.981 157.944C299.363 157.904 306.642 150.603 306.748 140.153C306.867 129.209 299.734 121.696 289.034 121.642C275.643 121.575 262.239 121.575 248.848 121.642C238.732 121.682 232.196 127.328 231.201 137.431C230.114 148.588 236.147 157.971 248.782 157.957C255.424 157.957 262.054 157.957 268.696 157.957L268.709 157.944Z"/><path d="M717.957 100.395C717.957 130.571 717.957 160.76 717.957 190.936C717.957 198.743 716.791 199.931 709.207 199.931C680.264 199.931 651.321 199.717 622.391 199.998C595.489 200.251 568.058 180.325 562.741 149.936C559.32 130.411 563.616 112.38 577.113 97.3522C586.42 86.9955 598.539 81.8706 612.076 79.922C628.476 77.5598 644.996 78.9878 661.45 78.6809C675.332 78.4273 683.87 65.5749 678.5 52.6558C676.286 47.3307 672.136 44.181 666.568 42.9531C664.009 42.3792 661.397 42.3125 658.785 42.3125C638.38 42.3259 617.989 42.3259 597.584 42.3125C589.364 42.3125 587.362 40.2572 587.349 31.9025C587.349 24.0283 587.322 16.154 587.349 8.27976C587.375 2.14052 589.178 0.325439 595.145 0.325439C633.461 0.325439 671.765 0.325439 710.082 0.325439C716.473 0.325439 717.957 1.83356 717.957 8.41322C717.957 39.0694 717.957 69.7256 717.957 100.382V100.395ZM642.398 121.616C636.113 121.616 629.815 121.963 623.571 121.522C612.699 120.748 603.709 128.943 604.611 141.181C605.314 150.777 611.916 157.85 621.436 157.904C635.291 157.984 649.159 157.984 663.014 157.904C673.33 157.85 679.866 150.79 679.879 139.913C679.879 128.702 673.555 121.776 663.014 121.616C656.147 121.522 649.279 121.602 642.398 121.602V121.616Z"/><path d="M379.576 99.9952C379.576 70.1798 379.576 40.3645 379.576 10.5491C379.576 8.88082 379.576 7.1992 379.828 5.55762C380.358 2.15435 382.294 0.312575 385.887 0.325921C413.04 0.365959 440.247 -0.608312 467.347 0.632883C500.546 2.15435 527.5 23.4282 535.124 57.2741C536.94 65.3352 537.763 73.4496 537.749 81.7109C537.683 117.852 537.723 153.98 537.709 190.122C537.709 191.67 537.802 193.258 537.511 194.753C536.901 197.903 535.071 199.891 531.664 199.891C521.349 199.905 511.033 199.905 500.718 199.891C497.656 199.891 495.813 198.196 495.269 195.274C494.924 193.418 494.885 191.483 494.885 189.588C494.858 152.98 494.898 116.358 494.858 79.749C494.832 62.1187 484.742 47.7849 468.527 43.7143C454.526 40.2043 438.231 43.1805 428.844 56.1263C424.588 61.9986 422.52 68.6183 422.507 75.8519C422.48 113.902 422.494 151.939 422.48 189.988C422.48 191.417 422.547 192.858 422.374 194.273C421.937 197.836 419.776 199.865 416.222 199.891C406.027 199.945 395.831 199.905 385.622 199.918C382.387 199.918 380.491 198.223 379.934 195.14C379.616 193.405 379.589 191.59 379.589 189.802C379.576 159.866 379.576 129.931 379.576 99.9952Z"/><path d="M89.4414 199.918C73.0805 199.918 56.7064 199.918 40.3454 199.918C34.4719 199.918 33.0798 198.891 32.0059 192.978C29.7785 180.673 27.7632 168.341 25.6153 156.023C22.4863 138.072 19.3043 120.135 16.2018 102.184C13.6032 87.1697 11.0973 72.1419 8.51192 57.1141C5.83371 41.7526 3.11573 26.3912 0.450787 11.0297C0.17236 9.38813 0 7.70652 0 6.05159C0.0265169 2.63497 1.78989 0.472886 5.13102 0.432848C15.9234 0.28604 26.7158 0.339424 37.5081 0.406155C41.1012 0.432848 42.2944 3.20885 42.9308 6.07828C44.0313 11.0698 44.9329 16.1146 45.8212 21.1595C48.0751 33.9451 50.276 46.7307 52.5034 59.5164C56.0699 79.9227 59.61 100.329 63.2163 120.735C64.2902 126.834 65.4304 132.92 66.69 138.98C68.9837 150.03 78.0127 157.557 89.163 157.864C99.8493 158.158 109.674 150.978 112.458 140.408C115.136 130.264 116.343 119.828 118.212 109.511C121.487 91.347 124.669 73.1695 127.851 54.992C130.384 40.4447 132.85 25.8974 135.342 11.35C135.448 10.7628 135.488 10.1622 135.594 9.57498C137.026 1.22027 138.087 0.312732 146.4 0.312732C155.057 0.312732 163.715 0.28604 172.373 0.326078C177.769 0.352771 179.983 2.54154 179.175 7.79994C177.159 20.8525 174.879 33.8784 172.651 46.9042C169.575 64.8549 166.46 82.8055 163.344 100.756C160.719 115.891 158.041 131.025 155.415 146.16C152.804 161.174 150.218 176.189 147.619 191.203C147.474 192.031 147.341 192.845 147.169 193.659C146.121 198.517 144.53 199.878 139.625 199.878C122.906 199.905 106.187 199.878 89.4547 199.878L89.4414 199.918Z"/></svg>`;

/** Account's favicon (`apps/account/src/app/icon.svg`), as a data URI. */
const VANA_FAVICON_HREF =
  "data:image/svg+xml," +
  encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><defs><linearGradient id="g" x1="16" y1="0" x2="16" y2="32" gradientUnits="userSpaceOnUse"><stop stop-color="#3854d5"/><stop offset="1" stop-color="#070a44"/></linearGradient></defs><rect width="32" height="32" rx="4" fill="url(#g)"/><path fill="#fff" d="M16.0001 25.5676C14.4316 25.5676 12.8619 25.5676 11.2935 25.5676C10.7304 25.5676 10.597 25.4691 10.494 24.9023C10.2805 23.7227 10.0873 22.5405 9.88139 21.3596C9.58143 19.6388 9.27639 17.9192 8.97897 16.1984C8.72985 14.759 8.48962 13.3184 8.24178 11.8777C7.98503 10.4051 7.72447 8.93248 7.469 7.45986C7.4423 7.30249 7.42578 7.14128 7.42578 6.98263C7.42832 6.6551 7.59737 6.44783 7.91767 6.44399C8.95228 6.42992 9.98689 6.43504 11.0215 6.44143C11.3659 6.44399 11.4803 6.71011 11.5413 6.98519C11.6468 7.4637 11.7333 7.94732 11.8184 8.43095C12.0345 9.65664 12.2455 10.8823 12.459 12.108C12.8009 14.0643 13.1403 16.0205 13.486 17.9768C13.589 18.5615 13.6983 19.1449 13.819 19.7258C14.0389 20.7851 14.9045 21.5067 15.9734 21.5362C16.9978 21.5643 17.9397 20.876 18.2066 19.8627C18.4633 18.8903 18.579 17.8898 18.7582 16.9008C19.0721 15.1595 19.3772 13.4169 19.6822 11.6743C19.925 10.2797 20.1614 8.88514 20.4004 7.49057C20.4105 7.43427 20.4143 7.3767 20.4245 7.3204C20.5618 6.51948 20.6635 6.43248 21.4604 6.43248C22.2904 6.43248 23.1203 6.42992 23.9503 6.43376C24.4676 6.43631 24.6799 6.64614 24.6023 7.15024C24.4091 8.40152 24.1905 9.65024 23.977 10.899C23.6821 12.6198 23.3834 14.3406 23.0847 16.0615C22.8331 17.5123 22.5763 18.9632 22.3247 20.4141C22.0743 21.8535 21.8264 23.2928 21.5773 24.7322C21.5633 24.8115 21.5506 24.8895 21.5341 24.9676C21.4337 25.4333 21.2812 25.5638 20.8109 25.5638C19.2081 25.5664 17.6054 25.5638 16.0014 25.5638L16.0001 25.5676Z"/></svg>',
  );

/*
 * Tokens come from Unity Design: tokens-primitive.css (light `:root`, dark
 * `[data-theme="dark"]`) and shell.css. Account follows the system theme
 * (next-themes `defaultTheme="system"`), so prefers-color-scheme is the
 * equivalent switch here.
 */
const ACCOUNT_PAGE_CSS = `
    :root {
      color-scheme: light dark;
      --color-accent: oklch(0.5175 0.2649 272.23);
      --color-background: oklch(1 0 0);
      --color-canvas: oklch(0.9702 0 0);
      --color-destructive: oklch(0.577 0.245 27.325);
      --color-success: color-mix(in oklch, oklch(0.7699 0.212 148.6) 80%, black);
      --color-foreground: oklch(0.2142 0.0025 67.69);
      --color-foreground-dim: oklch(0.5352 0.0151 71.18);
      --color-input: oklch(0.815 0 0);
      --radius-card: 9px;
      --radius-squish: 14px;
      --radius-control: 999px;
      --font-sans: "Inter", "InterVariable", ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      --font-mono: "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      --fluid-step: max(0px, min(1px, calc((100vw - 500px) / 700)));
      --text-body: calc(14px + (1 * var(--fluid-step)));
      --text-small: 14px;
      --text-title: calc(27px + (9 * var(--fluid-step)));
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --color-accent: oklch(0.68 0.14 253.66);
        --color-background: oklch(0.2248 0.0029 264.54);
        --color-canvas: oklch(0.18 0 0);
        --color-destructive: oklch(0.68 0.19 27);
        --color-success: color-mix(in oklch, oklch(0.76 0.18 148.6) 70%, white);
        --color-foreground: oklch(0.86 0 0);
        --color-foreground-dim: oklch(0.72 0 0);
        --color-input: oklch(0.36 0 0);
      }
    }
    *, *::before, *::after { box-sizing: border-box; }
    html, body { margin: 0; }
    body {
      min-height: 100vh;
      min-height: 100dvh;
      background: var(--color-canvas);
      color: var(--color-foreground);
      font-family: var(--font-sans);
      font-size: var(--text-body);
      line-height: 1.4545;
      font-synthesis: none;
      text-rendering: optimizeLegibility;
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
    }
    ::selection { background: var(--color-foreground); color: var(--color-background); }
    .unity-shell {
      display: flex;
      flex-direction: column;
      min-height: 100vh;
      min-height: 100dvh;
    }
    .unity-shell-container {
      display: flex;
      flex: 1;
      align-items: center;
      justify-content: center;
      padding: clamp(16px, 4vw, 32px);
    }
    .unity-panel {
      width: 100%;
      max-width: 480px;
      min-height: 480px;
      display: flex;
      flex-direction: column;
      gap: clamp(20px, 3vw, 32px);
      padding: clamp(20px, 3vw, 32px);
      border-radius: var(--radius-squish);
      background: var(--color-background);
      box-shadow: 0 0 0 1px color-mix(in oklab, var(--color-input) 20%, transparent);
    }
    .unity-panel--slim { min-height: 0; }
    .unity-header { display: flex; flex-direction: column; gap: clamp(12px, 2vw, 20px); }
    .unity-header-block { display: flex; flex-direction: column; gap: 10px; }
    .unity-logotype { display: block; align-self: flex-start; width: auto; height: 13px; margin-left: 4px; color: var(--color-accent); }
    .unity-header-title {
      margin: 0;
      font-size: var(--text-title);
      font-weight: 500;
      letter-spacing: -0.01em;
      line-height: 1.05;
      color: var(--color-foreground);
    }
    .unity-header-title-accent { color: var(--color-accent); }
    .unity-header-description {
      margin: 0;
      font-size: var(--text-body);
      line-height: 1.55;
      color: var(--color-foreground-dim);
    }
    .unity-content { display: flex; flex-direction: column; gap: 16px; }
    .unity-details {
      display: grid;
      grid-template-columns: max-content 1fr;
      gap: 8px 16px;
      margin: 0;
      font-size: var(--text-small);
    }
    .unity-details dt { font-weight: 500; }
    .unity-details dd { margin: 0; min-width: 0; overflow-wrap: anywhere; }
    .unity-mono { font-family: var(--font-mono); }
    .unity-actions { display: flex; flex-direction: column; gap: 8px; margin-top: auto; }
    .unity-button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 100%;
      min-height: 40px;
      padding: 8px 16px;
      border: 0;
      border-radius: var(--radius-control);
      background: var(--color-foreground);
      color: var(--color-background);
      font-family: var(--font-sans);
      font-size: 15px;
      font-weight: 500;
      cursor: pointer;
      text-decoration: none;
      transition: opacity 160ms ease, transform 160ms ease;
    }
    .unity-button:hover { opacity: 0.9; }
    .unity-button:active { transform: translateY(1px); }
    .unity-button:focus-visible { outline: 2px solid var(--color-accent); outline-offset: 2px; }
    .unity-button:disabled { cursor: not-allowed; opacity: 0.55; }
    .unity-status, .unity-error {
      margin: 0;
      font-size: var(--text-small);
      line-height: 1.4;
      color: var(--color-foreground-dim);
    }
    .unity-status:empty, .unity-error:empty { display: none; }
    .unity-error { color: var(--color-destructive); font-weight: 500; }
    .unity-success { color: var(--color-success); }
    @media (max-width: 380px) {
      .unity-details { grid-template-columns: 1fr; gap: 2px 0; }
      .unity-details dd { margin-bottom: 8px; }
    }
    @media (prefers-reduced-motion: reduce) {
      .unity-button { transition: none; }
    }
`;

/** Accent lead-in + heading, as Account's `UnityPageHeader` renders it. */
export function renderAccountPageHeading(
  headingAccent: string,
  heading: string,
): string {
  return `<span class="unity-header-title-accent">${escapeHtml(headingAccent)}</span><br>${escapeHtml(heading)}`;
}

export function renderAccountPage(options: AccountPageOptions): string {
  const panelClass = options.slim
    ? "unity-panel unity-panel--slim"
    : "unity-panel";
  const description = options.description
    ? `\n        <p class="unity-header-description" id="page-description">${escapeHtml(options.description)}</p>`
    : "";
  const body = options.bodyHtml
    ? `\n      <div class="unity-content">${options.bodyHtml}\n      </div>`
    : "";
  const script = options.script ? `\n  <script>${options.script}</script>` : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="light dark">
  <title>${escapeHtml(options.title)}</title>
  <link rel="icon" type="image/svg+xml" href="${VANA_FAVICON_HREF}">
  <style>${ACCOUNT_PAGE_CSS}  </style>
</head>
<body>
  <main class="unity-shell">
    <div class="unity-shell-container">
    <section class="${panelClass}" aria-labelledby="page-heading">
      <header class="unity-header">
        <div class="unity-header-block">
          ${VANA_LOGOTYPE_SVG}
          <h1 class="unity-header-title" id="page-heading">${renderAccountPageHeading(options.headingAccent, options.heading)}</h1>
        </div>${description}
      </header>${body}
    </section>
    </div>
  </main>${script}
</body>
</html>`;
}
