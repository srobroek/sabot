# Surface: Web and frontend

The client-side and HTTP surface `code.md` structurally misses. `code.md` traces
server-side taint to a sink; this surface covers the DOM sinks and the running app's
HTTP responses under the browser trust model. A static half reads frontend source,
and a dynamic half scans the project's own dev server.

## Detect

`*.html` `*.htm`, `*.jsx` `*.tsx` `*.vue` `*.svelte`, a `package.json` with a
`react`/`vue`/`svelte`/`angular`/`next`/`vite` dependency, `*.css` with templated
values, a `Content-Security-Policy` string anywhere, service-worker files, and any
server that renders HTML. A Tauri or Electron app counts: its webview runs the
frontend with native IPC behind it.

## Tools

| Tool | Tier | Class | Run recipe | Catches | Overlap |
|------|------|-------|-----------|---------|---------|
| eslint-plugin-security + no-unsanitized | default-on | local | `npx eslint --format json .` with the plugins | `innerHTML`, `dangerouslySetInnerHTML`, `document.write`, `eval`, `javascript:` URLs | project-local; the DOM-sink detector `code.md` lacks |
| opengrep js/ts pack | default-on | local | `opengrep --config /opt/sabot-db/semgrep-rules/javascript --config /opt/sabot-db/semgrep-rules/typescript --config /opt/sabot-db/semgrep-rules/html --json <files>` (173 + 30 + 6 baked rules, XSS rules included) | reflected and stored XSS patterns, template injection | **baked, offline.** Never `p/xss` or `p/javascript`: a registry shorthand resolves over the network and exits `OG_RC=2` under `--network none`, scanning nothing |
| retire.js | default-on | local | `npx retire --outputformat json` | known-vulnerable JS libraries shipped in the bundle | complements osv-scanner with browser-lib CVEs |
| nuclei | opt-in | dynamic | `nuclei -u <local-url> -json -o <artifacts>/nuclei.json` | live findings against the running app: headers, exposures, known CVEs | dynamic; needs the dev server up |
| ZAP baseline | opt-in | dynamic | `zap-baseline.py -t <local-url> -J <artifacts>/zap.json` | passive scan: CSP, cookie flags, missing headers, mixed content | dynamic; passive by default |
| Playwright probe | opt-in | dynamic | `require("playwright")` from `NODE_PATH`, `chromium.launch({args:["--no-sandbox"]})`, driven per `harnesses.md` | DOM XSS that only fires after render, `postMessage` origin gaps | **chromium is baked into `sabot/node:1`** and launches offline against `127.0.0.1`. Pass `--no-sandbox`, because chromium's sandbox needs privileges the container drops, and keep the `TMPDIR` that `run-contained.sh` points at the `/scratch` tmpfs, since the root filesystem is read-only. Missing either fails at `launch()` |

MUST Treat every dynamic-class tool as gated by the dev-server section below, since it cannot run without a live instance.
NOT A live DAST tool pointed at any host other than the project's own dev server is out of scope, matching the rest of the skill.

## Running the project's own dev server

"Live" means the project's dev server, started by the agent the way a developer
starts it, scanned locally, and torn down. It is not a remote target.

1. Find the start command in the repo: `package.json` scripts (`dev`, `start`,
   `preview`), a `justfile`/`Makefile` target, `cargo run`, `tauri dev`. Use the
   repo's own command; never invent one.
2. Start it bound to loopback, capture the URL and the PID.
3. Wait for the port to answer, with a timeout, before scanning.
4. Scan that URL only.
5. Stop the server by its PID, and confirm the port is closed.

MUST Bind the dev server to `127.0.0.1`/`localhost` only. That loopback URL is the one scan target; a dev server reachable off-host is its own finding and stays out of remote-scan scope regardless.
MUST Launch the server through the repo's declared start command. An invented invocation describes nothing the project intended.
MUST Confine a payload-submitting scan to a worktree or scratch checkout, since an active scan mutates whatever state the app writes.
MUST Stop the server at the end and confirm the port is closed. A campaign that leaves a dev server running has changed the developer's machine.
NOT Never scan a staging, production, or shared URL, even one the user pastes. The target is a server the agent started locally and controls.

## Attack checklist

| # | Attack | Where it hides | Confirm by |
|---|--------|----------------|-----------|
| 1 | DOM-sink XSS | `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `{@html}`, `document.write` on any value not from a literal | trace the value to user input or a fetched response |
| 2 | Reflected/stored XSS | a server rendering a request value into HTML without escaping | submit a marker payload to the running app and see it execute |
| 3 | `javascript:`/`data:` URL sink | an `href`/`src` built from input | supply a `javascript:` URL and check it is not sanitized |
| 4 | CSP absent or bypassable | the response headers, or a `<meta>` CSP | check for `unsafe-inline`, `unsafe-eval`, a wildcard source, or no CSP at all |
| 5 | postMessage origin gap | a `message` listener that skips `event.origin` | check whether any origin can post to it |
| 6 | Client-side secret | a token, key, or internal URL in the shipped bundle | grep the built assets, not just source |
| 7 | CSRF on a state-changing request | a POST with no anti-CSRF token and cookie auth | check for a token and SameSite |
| 8 | Cookie flags | `Set-Cookie` on the live server | check `HttpOnly`, `Secure`, `SameSite` |
| 9 | Clickjacking | missing `X-Frame-Options`/`frame-ancestors` | check the live headers |
| 10 | Open redirect | a redirect target from a parameter | supply an external host and see if it redirects |
| 11 | Source map or debug artifact shipped | `.map` files, a debug route, verbose errors on the live server | request them against the running instance |
| 12 | Tauri/Electron IPC from the webview | `code.md` covers the native handler bodies; here, what the webview is allowed to invoke | enumerate the exposed IPC and whether the webview input is trusted |

## Harness patterns

**Static** doesn't need a server: run the eslint/opengrep/retire.js tools and trace DOM
sinks by reading, exactly like `code.md`.

**Dynamic** drives the running instance. `sabot-fuzzer` writes the scan config and, when
DOM XSS needs render, a Playwright script that loads a page, injects a marker into
each input, and asserts the marker never reaches `document` as script. `gremlin`
starts the server, then runs the scan and tears it down per the section above.

## Impact calibration

| Level | Meaning on this surface |
|---|---|
| CRITICAL | stored XSS, or a client-side secret that grants real access |
| HIGH | reflected XSS, a CSP that permits `unsafe-inline` on a page handling auth, an open redirect used in an auth flow |
| MEDIUM | a missing security header, a CSRF gap on a low-value action, a shipped source map |
| LOW | a cookie missing `SameSite` with no session value, a verbose error with no secret |

## False-positive traps

| Looks like a finding | Clears when |
|---|---|
| `innerHTML` assignment | the value is a literal or already HTML-escaped by the framework |
| `dangerouslySetInnerHTML` | the content is passed through a sanitizer such as DOMPurify first |
| Missing CSP on a dev server | production sets it at the edge, which the report must confirm rather than assume |
| A token in the bundle | it is a public, publishable key (a Stripe publishable key, a public analytics id) |
| `retire.js` CVE | the vulnerable code path is not reachable in this app's usage |
