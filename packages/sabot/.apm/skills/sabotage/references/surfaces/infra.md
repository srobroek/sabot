# Surface: Infra, config, supply chain

Deterministic scanners cover most of this surface, leaving the reading layer only
what policy engines cannot see. CI workflow injection carries the highest impact
here, because a compromised workflow holds repository credentials.

## Detect

`*.tf` `*.tfvars` `*.hcl`, `Dockerfile` `*.dockerfile` `compose.yaml`,
`*.yaml` carrying `apiVersion:` with `kind:`, `kustomization.yaml`,
`.github/workflows/**` `.gitlab-ci.yml` `.circleci/config.yml`, `Chart.yaml`,
lockfiles (`Cargo.lock` `package-lock.json` `pnpm-lock.yaml` `uv.lock` `go.sum`
`poetry.lock`), `.pre-commit-config.yaml`, and `renovate.json`.

## Tools

| Tool | Tier | Class | Run recipe | Catches | Overlap |
|------|------|-------|-----------|---------|---------|
| trivy | default-on | local | `trivy --cache-dir /opt/sabot-db/trivy fs --skip-db-update --skip-check-update --scanners misconfig,vuln,secret --format json .` | IaC misconfig, CVEs, secrets across Terraform, Docker, and k8s in one pass | broad; subsumes much of checkov for common rules |
| checkov | default-on | local | `checkov -d . -o json` | deeper IaC policy checks, including custom policies | overlaps trivy, and catches policy classes trivy misses |
| zizmor | default-on | local | `zizmor --format json .github/workflows/` | CI workflow injection: `pull_request_target` with untrusted checkout, template injection into `run:`, over-broad `GITHUB_TOKEN` | unique; no other tool does workflow dataflow |
| actionlint | default-on | local | `actionlint -format '{{json .}}'` | workflow syntax, shell inside `run:` through embedded shellcheck | complements zizmor, which judges security rather than validity |
| ~~pinact~~ | dropped | - | - | actions referenced by tag rather than SHA | **not installed.** `zizmor --offline` reports the same unpinned refs (`error[unpinned-uses]`), and pinact's unique capability is *writing* the pin, which is remediation rather than detection |
| osv-scanner | default-on | global | `XDG_CACHE_HOME=/opt/sabot-db/osv osv-scanner scan source --offline-vulnerabilities --format json -r .` (the env var is MANDATORY; `--offline*` alone loads no db and reports 0) | CVEs across every lockfile ecosystem | overlaps the repo's `dep-audit` package, which is preferred when present |
| hadolint | default-on | local | `hadolint -f json <Dockerfile>` | root user, unpinned base image, unsafe `RUN`, missing `HEALTHCHECK` | embeds shellcheck for `RUN` bodies |
| kube-linter | default-on | local | `kube-linter lint --format json <path>` | missing limits, privileged containers, `runAsNonRoot`, host mounts | k8s only |
| tflint | default-on | local | `tflint -f json` | provider-aware Terraform errors | complements the policy scanners |
| gitleaks | default-on | local | `gitleaks dir --report-format json .` for the working tree, AND `gitleaks git --report-format json .` for history. **Verify the history pass saw commits**: in a worktree, `.git` is a pointer file outside the mount, so `gitleaks git` scans 0 commits and exits 0 | committed credentials | the repo's `secrets-scan` package is preferred when present |
| grype | opt-in | global | `grype dir:. -o json` | container image and SBOM CVEs | overlaps trivy's vuln scanner |
| conftest | opt-in | local | `conftest test --output json <files>` | custom Rego policy, useful only when the repo ships policies | none |

MUST Prefer the repo's own `dep-audit` and `secrets-scan` packages when they exist, and run these scanners only to fill what those leave uncovered.
MUST Treat `osv-scanner` and `grype` as global class, so a scoped run skips them and the report states that skip.

## Attack checklist

| # | Attack | Where it hides | Confirm by |
|---|--------|----------------|-----------|
| 1 | CI workflow injection | `${{ github.event.* }}` interpolated into a `run:` block | confirm the field is attacker-controllable, such as a PR title, branch name, or issue body |
| 2 | `pull_request_target` with untrusted checkout | a workflow checking out `github.event.pull_request.head.sha` while holding secrets | check whether the job runs code from the PR with the repository token available |
| 3 | Unpinned action | `uses: org/action@v4` rather than `@<sha>` | a moved tag executes new code with the workflow's permissions |
| 4 | Over-broad token permission | a workflow lacking a `permissions:` block, or granting `write-all` | compare the grant against what the job actually needs |
| 5 | Secret reaching a log or artifact | `echo "$SECRET"`, a secret passed as a CLI argument, an uploaded build directory | trace whether the value can appear in output |
| 6 | Container running as root | a Dockerfile with no `USER` directive | confirm the process does not need root at runtime |
| 7 | Unpinned base image | `FROM node:latest` or a floating major tag | a rebuilt image pulls different code |
| 8 | Overly permissive network or IAM policy | a security group open to `0.0.0.0/0`, an IAM policy with `Action: "*"` | check whether a narrower scope satisfies the use |
| 9 | Unencrypted storage or transit | a bucket or volume without encryption, TLS disabled | confirm the data is sensitive |
| 10 | Missing k8s resource limits | a pod spec with no `limits` | one workload can starve the node, which is a robustness finding with a security consequence |
| 11 | Privileged container or host mount | `privileged: true`, `hostPath`, `hostNetwork` | a container escape becomes host compromise |
| 12 | Typosquat or unexpected dependency | a lockfile entry whose name is one edit from a popular package, or a transitive addition nobody requested | compare against the manifest's declared intent |
| 13 | Lockfile drift | a manifest and lockfile disagreeing, or a lockfile absent | an unpinned install resolves differently on each machine |
| 14 | Pre-commit hook fetching remote code | a `.pre-commit-config.yaml` repo pinned to a branch | a moved branch executes new code locally |
| 15 | Terraform state exposure | local state committed, or a backend without encryption and locking | state contains secrets in plaintext |

## Harness patterns

Most of this surface is statically decidable, so fuzzing adds little. Two
exceptions:

**Config parser robustness.** When the repo ships code that reads its own config,
that parser goes through `scripts/fuzz-cli.py`, since a crash on malformed config
is a startup denial.

**Policy assertion.** When the repo ships Rego or custom scanner policies,
`sabot-fuzzer` writes fixtures that should fail each policy, and `gremlin` confirms the
policy actually rejects them. A policy that passes everything is a silent gap, and
it looks identical to a compliant repo.

## Impact calibration

| Level | Meaning on this surface |
|---|---|
| CRITICAL | workflow injection reaching a token with write access, a committed live credential, or a publicly exposed datastore |
| HIGH | an unpinned action or MCP-equivalent remote fetch in a privileged job, a privileged container, or a known-exploited CVE in a shipped dependency |
| MEDIUM | an unencrypted volume, a missing resource limit, an over-broad IAM policy with no traced abuse path, or an unfixed CVE with no reachable call path |
| LOW | a hardening default absent from a dev-only environment, or a CVE in a dev dependency that never ships |

## False-positive traps

| Looks like a finding | Clears when |
|---|---|
| `0.0.0.0/0` on a security group | the port serves a public web endpoint by design |
| A container without `USER` | the image is a build stage discarded before the final image |
| An unpinned action | it is a first-party action in the same repository, so the tag and the code share a trust boundary |
| A CVE reported by a scanner | the vulnerable function is never called, which the report states as REACHABLE rather than PROVEN |
| `${{ }}` inside a workflow | the interpolated field is repo-controlled, such as `github.repository` or a `vars` entry, rather than attacker-supplied |
| Missing encryption on a bucket | the account or provider default enforces it, which the report cites as the mitigating control |
| A hardcoded secret in a fixture | the file is a test fixture with a value the scanner's allowlist covers, and the value is not live |
