# The network stage: close the gaps that need egress, and nothing else

The campaign runs under `--network none`, which is why its findings are trustworthy
and why five real gaps stay open. Every one of them has the same shape: a tool that
answers a question about a LOCAL artifact by asking a REMOTE service. No baked
database substitutes, because the remote answer is the answer.

A tool that merely needs to DOWNLOAD something is not one of them. A Playwright
browser and a CodeQL query pack both run entirely offline against loopback once they
are on disk, so their egress need is one-time acquisition and the fix is baking them
into the image (`references/isolation.md`), not a stage that runs with the network up.
Sending that to the network stage would put the DAST probes themselves on a networked
container for no reason at all.

This stage runs once, after step 12 and before the report, and it is a separate
opt-in the user names. It is not "the campaign with network on".

MUST Run this stage in a container WITH egress, never on the host. The target stays mounted read-only and the same user, capability, and filesystem constraints apply. Egress is the only thing that changes, so a compromised tool still cannot write the target or reach the developer's machine.
MUST Keep every attack, harness, fuzz run, and DAST probe out of this stage. It performs reads and lookups. A campaign action that gained network would be attacking over the network, which the hard rules forbid outright.
NOT Never run this stage against a network host, public endpoint, or third-party service belonging to anyone. Fetching a vulnerability database is using a service as published; probing a host is not.

## What it closes

| Gap | The remote question | Verb |
|---|---|---|
| secret liveness | is this found credential still active | `trufflehog filesystem --results=verified` over a directory holding ONLY the candidates the user owns, never the target tree |
| dependency advisories | is the baked OSV/trivy DB stale against today's | `osv-scanner` and `trivy` with a fresh DB fetch |
| Rust advisories | same, for `cargo-audit` | `cargo audit` after `cargo audit fetch` |
| action refs | does each pinned action ref still resolve to what GitHub serves for it | `zizmor` without `--offline`, for its online audits (`impostor-commit`, `ref-confusion`, `stale-action-refs`, `known-vulnerable-actions`); pinact was dropped from the image |
| registry rule packs | the curated `p/*` packs with no baked equivalent (`p/trailofbits`, and anything the baked tree lacks) | `opengrep --config p/<pack>` |

MUST Bake a downloadable-once artifact into the image rather than routing it here. A missing Playwright browser cost one campaign 7 of its 13 DAST probes, and that was an image defect: the probes drive `127.0.0.1` and don't touch the network once the browser exists. The same holds for CodeQL packs, a `cargo-fuzz` toolchain, and any tool whose install step is the only networked part of it.

MUST Re-run this stage's DB-backed scanners against the SAME target the offline pass scanned, and report the delta rather than replacing the offline result. A fresh DB finding that the baked DB missed is a finding about the image's freshness as much as about the target, and both belong in the report.
MUST State the fetch timestamp for every database this stage refreshes. "Current as of" is the claim being made, and without a timestamp the report implies today.

## Secret verification needs its own consent

Verifying a credential SENDS IT to the provider. That is unavoidable: liveness is
established by authenticating. One action hides two very different situations.

| Whose credential | What verification is | Allowed |
|---|---|---|
| the user's own | authenticating to the user's own service with the user's own key, read-only | yes, on the user's explicit say-so |
| a third party's, committed by mistake | authenticating to somebody else's service with a key the user does not own | NO |

MUST Ask separately for secret verification, naming it as sending the found credential to its provider. "Allow the network stage" is not that consent, because the other four gaps carry no such transfer.
MUST Identify the owner of each candidate secret BEFORE verifying it, and verify only the ones the user owns. A vendor key, a partner token, or a credential whose provider the user has no account with is reported by location, type, and `file:line` and never sent anywhere.
MUST Use the provider's cheapest read-only identity call and nothing further, because a verification that goes on to list buckets or read mail has stopped verifying and started using the credential.
DEFAULT A rate-limited or errored verification is UNVERIFIED, never clean. A provider that refused to answer has not said the key is dead.
NOT Never print, log, or write a credential's value, in this stage least of all. Location, type, and `file:line`, exactly as everywhere else.
NOT Never verify a secret found in a public repository's history without saying plainly that the credential should be rotated regardless of the verdict. A dead key in public history is still a disclosure, and a live one is an incident.

## A verified-clean pass still needs a control

`trufflehog` returning nothing means either "no live credentials" or "trufflehog did
not work", and offline the campaign could not tell those apart: its one pass had no
control at all.

MUST Plant a canary credential in a fixture and confirm the tool flags it, in the same invocation shape, before reading any zero as clean. Use a credential the user owns and can revoke, or a provider's documented test key. Without the control the result is NOT EXECUTED.
MUST Revoke or remove the canary when the stage ends, and record that it was removed.

## Reporting

A finding from this stage is tiered on the same two axes as any other, plus one extra
fact: it required egress and therefore was not reproducible under the campaign's own
isolation.

MUST Mark every network-stage finding with the tool, the remote service consulted, and the fetch timestamp. A reader must be able to tell which findings the offline campaign could have produced on its own.
MUST Record the stage as DECLINED, listing all five gaps as still open, when the user does not opt in. A declined stage is a known coverage boundary; an unmentioned one reads as full coverage.
