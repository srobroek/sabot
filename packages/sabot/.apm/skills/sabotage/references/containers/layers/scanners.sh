#!/usr/bin/env bash
set -eux

# scanners.sh -- the config, dependency, secret, and web scanners that carry a remote
# data dependency, plus the data itself.
#
# These were the last rows tool-coverage-matrix.md listed as UNMEASURED. Each one turns
# into a different kind of false clean offline:
#
#   Nuclei      ships NO templates in the binary. It fetches nuclei-templates on first
#               run, and under --network none it runs with zero of them. Baked here; the
#               campaign MUST pass -templates at the baked path.
#   Bearer      same shape: rules come from bearer/bearer-rules on first run. Baked, and
#               the campaign MUST pass --external-rule-dir.
#   Checkov     policies ship in the wheel, so it is self-contained ONCE INSTALLED. The
#               install itself is the network op.
#   GuardDog    heuristics ship in the wheel too, but its scan reaches for the registry
#               to fetch the package under test. Only the local-target form is offline.
#   Kingfisher  rules are compiled in; its credential VALIDATION needs network. Offline
#               runs the detection half, and the report must say which half ran.
#
# WHY A SEPARATE IMAGE, not layers/base-extras.sh
#   base-extras runs inside Dockerfile.base, which every language surface inherits. This
#   layer adds two pipx virtualenvs and two checked-out data trees, and neither the rust
#   nor the go surface has any use for a Terraform policy set. Stacking it on base would
#   pay for all of it four times over. It is an OPTIONAL escalation surface, like
#   sabot/rust-extras:1: absent is a preflight note, present-but-broken is a failure.
#
# Runs as root at build time (Dockerfile.scanners invokes it).
#
# Every pinned version carries a '# renovate:' line. The two data trees are pinned by
# commit SHA and advanced by hand: neither repo tags releases, and renovate's semver
# datasource cannot track a bare SHA (same treatment as radamsa in base-extras.sh).

# renovate: datasource=pypi depName=checkov
CHECKOV_VERSION=3.3.9
# renovate: datasource=pypi depName=guarddog
GUARDDOG_VERSION=3.2.0
# renovate: datasource=github-releases depName=mongodb/kingfisher
KINGFISHER_VERSION=1.113.0
# renovate: datasource=github-releases depName=projectdiscovery/nuclei
NUCLEI_VERSION=3.11.1
# renovate: datasource=github-releases depName=bearer/bearer
BEARER_VERSION=2.1.0
NUCLEI_TEMPLATES_SHA=c0faffdf5be7c06ff3cca3502891745715c46b84
BEARER_RULES_SHA=82c335f781a61a6d8b052394f84fd1d93edec467

arch="$(dpkg --print-architecture)"
case "$arch" in
arm64) kf=arm64 nu=arm64 be=arm64 ;;
amd64) kf=x64 nu=amd64 be=amd64 ;;
*)
	echo "sabot scanners: unsupported arch: $arch" >&2
	exit 1
	;;
esac

apt-get update -q
apt-get install -y --no-install-recommends pipx
rm -rf /var/lib/apt/lists/*

# --- release binaries ---------------------------------------------------------------
# kingfisher's tgz unpacks a bare `kingfisher`; bearer publishes a plain tar.gz alongside
# its .deb, so prefer the tarball and skip dpkg. Both name arm64 differently from the
# other (x64 vs amd64), hence the map above.
curl -fsSL "https://github.com/mongodb/kingfisher/releases/download/v${KINGFISHER_VERSION}/kingfisher-linux-${kf}.tgz" |
	tar -xz -C /usr/local/bin kingfisher
curl -fsSL -o /tmp/nuclei.zip \
	"https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${nu}.zip"
unzip -o -q /tmp/nuclei.zip -d /usr/local/bin nuclei
rm /tmp/nuclei.zip
curl -fsSL "https://github.com/bearer/bearer/releases/download/v${BEARER_VERSION}/bearer_${BEARER_VERSION}_linux_${be}.tar.gz" |
	tar -xz -C /usr/local/bin bearer
chmod +x /usr/local/bin/kingfisher /usr/local/bin/nuclei /usr/local/bin/bearer

# --- python wheels ------------------------------------------------------------------
# pipx, not `pip install --break-system-packages`: checkov and guarddog both pull large
# dependency trees that overlap and conflict, and a shared site-packages resolves one of
# them wrong. pipx gives each its own venv and exports only the entry point.
export PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
pipx install "checkov==${CHECKOV_VERSION}"
pipx install "guarddog==${GUARDDOG_VERSION}"

# --- baked template and rule trees --------------------------------------------------
# This is the half that matters: nuclei with no templates and bearer with no rules both
# run to completion offline having checked nothing. Shallow-fetch the pinned commit
# rather than cloning; nuclei-templates carries years of history.
mkdir -p /opt/sabot-db
for spec in "nuclei-templates https://github.com/projectdiscovery/nuclei-templates $NUCLEI_TEMPLATES_SHA" \
	"bearer-rules https://github.com/bearer/bearer-rules $BEARER_RULES_SHA"; do
	set -- $spec
	git init -q "/opt/sabot-db/$1"
	git -C "/opt/sabot-db/$1" remote add origin "$2"
	git -C "/opt/sabot-db/$1" fetch -q --depth 1 origin "$3"
	git -C "/opt/sabot-db/$1" checkout -q FETCH_HEAD
	rm -rf "/opt/sabot-db/$1/.git"
done

# Assert a FLOOR on each tree, not `test -d`. A fetch that resolved to an empty tree, or
# an upstream that moved its layout, leaves a directory that passes every existence check
# and loads zero rules, which is exactly the failure this bake exists to prevent.
tmpl_count="$(find /opt/sabot-db/nuclei-templates -name '*.yaml' | wc -l)"
[ "$tmpl_count" -gt 1000 ] || {
	echo "sabot scanners: only $tmpl_count nuclei templates baked; expected thousands" >&2
	exit 1
}
rule_count="$(find /opt/sabot-db/bearer-rules \( -name '*.yml' -o -name '*.yaml' \) | wc -l)"
[ "$rule_count" -gt 100 ] || {
	echo "sabot scanners: only $rule_count bearer rules baked; expected hundreds" >&2
	exit 1
}

# --- probes: assert the WORK, not the version string --------------------------------
kingfisher --version
nuclei -version
bearer version
checkov --version
guarddog --version

# QUARANTINE. `-validate` is all-or-nothing, and at this pin one upstream template fails
# to unmarshal:
#
#   http/cves/2026/CVE-2026-3395.yaml: line 52: cannot unmarshal !!str `POST /a...`
#   into []string
#
# It is broken at upstream HEAD too, so advancing the pin does not fix it, and `-et` does
# not suppress it because validation loads a template before excluding it. Deleting the
# one file is what keeps the check below a ZERO-ERROR gate: the alternative is grepping
# for a success string in output that also contains errors, which would pass silently the
# next time a template breaks. Drop entries from this list as upstream repairs them.
for bad in http/cves/2026/CVE-2026-3395.yaml; do
	rm -f "/opt/sabot-db/nuclei-templates/$bad"
done

# nuclei -version answers with zero templates loaded, so parse the whole tree instead.
# -validate needs no target, which makes it the cheapest proof the baked tree is readable
# and well-formed.
#
# -ud is NOT optional, and it is the reason this probe exists. nuclei resolves a
# template's `helpers/` payload files against its DEFAULT template directory, not against
# the tree given to -templates, so with -templates alone roughly 5000 templates failed to
# compile with `access to helper file ... denied` (measured). -ud repoints that default at
# the baked tree.
#
# -duc (disable-update-check) on every invocation: the updater writes to its config dir
# and reaches the network, and under the campaign's --read-only rootfs that failure takes
# the scan with it.
nuclei -templates /opt/sabot-db/nuclei-templates -ud /opt/sabot-db/nuclei-templates \
	-validate -duc >/tmp/nuclei-out.txt 2>&1
grep -q "All templates validated successfully" /tmp/nuclei-out.txt || {
	echo "sabot scanners: nuclei did not validate the baked templates" >&2
	grep -E '^.\[91m|ERR|FTL' /tmp/nuclei-out.txt >&2 || cat /tmp/nuclei-out.txt >&2
	exit 1
}
rm /tmp/nuclei-out.txt

probe=/tmp/sabot-scanners-probe
mkdir -p "$probe"

# Checkov: prove the policy set LOADS by finding a seeded misconfiguration. A public-read,
# unversioned, unencrypted bucket trips several CKV_AWS_* the default set has long carried.
cat >"$probe/main.tf" <<'EOF'
resource "aws_s3_bucket" "b" {
  bucket = "sabot-probe"
  acl    = "public-read"
}
EOF
checkov -d "$probe" --compact --quiet >"$probe/checkov.txt" 2>&1 || true
grep -q "CKV_AWS" "$probe/checkov.txt" || {
	echo "sabot scanners: checkov loaded no AWS policies on the probe" >&2
	cat "$probe/checkov.txt" >&2
	exit 1
}

# Bearer: prove the BAKED rules load, by pointing it at them explicitly and requiring a
# rule-specific finding on a seeded weak hash. Without --external-rule-dir it reports a
# clean. A non-empty file is not that proof: an empty `{}` report or an error log passes
# `test -s`, so the report is parsed and must carry python_lang_weak_hash_md5, and with
# --exit-code 0 any non-zero exit is an error rather than a finding.
mkdir -p "$probe/app"
cat >"$probe/app/db.py" <<'EOF'
import hashlib

PASSWORD = "hunter2-not-a-real-secret"


def weak(x):
    return hashlib.md5(x).hexdigest()
EOF
rc=0
bearer scan "$probe/app" --external-rule-dir /opt/sabot-db/bearer-rules \
	--format json --output "$probe/bearer.json" --exit-code 0 >"$probe/bearer.log" 2>&1 || rc=$?
[ "$rc" -eq 0 ] && python3 - "$probe/bearer.json" <<'EOF' || {
import json, sys
report = json.load(open(sys.argv[1]))
ids = {f.get("id") for findings in report.values() if isinstance(findings, list)
       for f in findings if isinstance(f, dict)}
sys.exit(0 if "python_lang_weak_hash_md5" in ids else f"bearer rule ids: {sorted(map(str, ids))}")
EOF
	echo "sabot scanners: bearer (rc=$rc) did not report python_lang_weak_hash_md5 against the baked rules" >&2
	cat "$probe/bearer.log" >&2
	exit 1
}

# Kingfisher: detection only. --no-validate is not optional here; the default path opens
# outbound connections to validate each candidate, and offline that turns every real hit
# into a validation error.
#
# Its output used to be discarded. Now it must find a seeded AWS key pair: exit 200 is
# "findings discovered" (0 is none, anything else an error), and the report must name an
# aws rule. The pair is generated here, never committed, because textbook keys are
# allowlisted and a credential-shaped literal in the repo trips its own secret scan
# (tool-coverage-matrix.md, "Seeding a secrets fixture"). Measured: kingfisher reports
# `kingfisher.aws.2` on an AKIA id with a 40-character secret.
python3 - "$probe/app/credentials" <<'EOF'
import secrets, string, sys
key_id = "AKIA" + "".join(secrets.choice(string.ascii_uppercase + "234567") for _ in range(16))
secret = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(40))
open(sys.argv[1], "w").write(
    f"[default]\naws_access_key_id = {key_id}\naws_secret_access_key = {secret}\n")
EOF
rc=0
kingfisher scan "$probe/app" --no-validate --format json >"$probe/kf.json" 2>"$probe/kf.log" || rc=$?
[ "$rc" -eq 200 ] && grep -q '"kingfisher\.aws\.' "$probe/kf.json" || {
	echo "sabot scanners: kingfisher (rc=$rc) did not report the seeded AWS key" >&2
	cat "$probe/kf.log" >&2
	exit 1
}

echo "scanners: $tmpl_count nuclei templates, $rule_count bearer rules; checkov, bearer and kingfisher each reported their seeded finding"
rm -rf "${probe:?}"

chmod -R a+rX /opt/sabot-db /opt/pipx
