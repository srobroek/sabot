#!/usr/bin/env bash
set -eux

# heavy.sh -- the JVM analysis engines, in their own image because of size.
#
# Joern alone unpacks to well over 1GB, and base is inherited by every surface. Kept
# here, a rust or python campaign never pays for it: the triager escalates to
# sabot/heavy:1 when a finding wants a whole-program dataflow query or a DAST pass.
#
# WHAT IS HERE
#   Joern      a CPG (code property graph) engine with its own query language. Answers
#              interprocedural reachability that a per-file matcher (semgrep, ast-grep)
#              cannot. Offline it needs its query scripts from the campaign, not a DB,
#              but the CPG build itself downloads NOTHING once the CLI is unpacked.
#   OWASP-ZAP  a web proxy/scanner. Its PASSIVE rules ship in the bundle; its ACTIVE
#              scan needs a running target, which offline means a server the campaign
#              itself started inside the container. See isolation.md.
#
# CodeQL is NOT here, and not because of size. github/codeql-cli-binaries publishes no
# linux-arm64 asset at all (v2.26.3 ships linux64/osx64/win64, all x86_64), and upstream
# declined to commit to one. Emulating x86_64 for a whole-program engine buys a bake and
# an unusable runtime, so the arm64 surface treats CodeQL as ABSENT. tool-coverage-matrix.md
# records it as a platform gap, and a report that would have run it must name the gap
# rather than imply the analysis happened.
#
# Runs as root at build time (Dockerfile.heavy invokes it).
#
# Every version is pinned with a '# renovate:' line so containers/renovate.json tracks it.

# renovate: datasource=github-releases depName=joernio/joern
JOERN_VERSION=v4.0.604
# renovate: datasource=github-releases depName=zaproxy/zaproxy
ZAP_VERSION=v2.17.0
# ZAP publishes no checksum file beside its Core zip, so the digest is pinned here: the
# GitHub release asset digest, which matched a local sha256 of the download. A ZAP_VERSION
# bump without a new digest fails the build on the mismatch rather than installing
# whatever the URL now serves.
ZAP_CORE_SHA256=0cb73b7f72d12c263fb61de304edb82a455d7aa4e1813c216c061765c306f5b7

# Joern names arm64 as arm64 and x86_64 as x86_64, which is dpkg's amd64. Unlike the go
# distribution the spelling differs, so map it rather than reusing the dpkg name.
arch="$(dpkg --print-architecture)"
case "$arch" in
arm64) joern_arch=arm64 ;;
amd64) joern_arch=x86_64 ;;
*)
	echo "sabot heavy: unsupported arch: $arch" >&2
	exit 1
	;;
esac

# Both engines are JVM. Base ships no JRE (measured: `java: not found`), so this layer
# installs one. headless, because there is no display in a campaign container and the
# full JRE pulls an X stack that nothing here uses.
apt-get update -q
apt-get install -y --no-install-recommends default-jre-headless unzip
rm -rf /var/lib/apt/lists/*

# --- Joern -------------------------------------------------------------------------
#
# The zip is the joern-cli distribution: launcher scripts plus a jar tree. There is also
# an install.sh upstream, and it is deliberately NOT used -- it fetches at run time and
# writes into $HOME, which under a read-only image as uid 1000 cannot work.
mkdir -p /opt
curl -fsSL -o /tmp/joern.zip \
	"https://github.com/joernio/joern/releases/download/${JOERN_VERSION}/joern-cli-linux-${joern_arch}.zip"
curl -fsSL -o /tmp/joern.zip.sha512 \
	"https://github.com/joernio/joern/releases/download/${JOERN_VERSION}/joern-cli-linux-${joern_arch}.zip.sha512"
# The upstream .sha512 is `digest  target/joern-cli-linux-<arch>.zip`, naming a path that
# does not exist here, so feeding it to `sha512sum -c` verbatim fails on the filename
# rather than on the bytes (measured: "No such file or directory ... FAILED open or read",
# which reads like a corrupt download). Take the digest field and name the local file.
(cd /tmp && echo "$(awk '{print $1}' joern.zip.sha512)  joern.zip" | sha512sum -c -)
unzip -q /tmp/joern.zip -d /opt
rm /tmp/joern.zip /tmp/joern.zip.sha512
# The zip may unpack as joern-cli/ or joern/ depending on release; normalise the path so
# the PATH entry below does not depend on which.
[ -d /opt/joern-cli ] || mv /opt/joern /opt/joern-cli
ln -sf /opt/joern-cli/joern /usr/local/bin/joern
ln -sf /opt/joern-cli/joern-parse /usr/local/bin/joern-parse

# --- OWASP-ZAP ---------------------------------------------------------------------
#
# The Core zip (108MB) rather than the full Linux tarball (243MB): the difference is the
# bundled add-on set, and a --network none campaign cannot install add-ons anyway. What
# the core carries is the passive rule set, which is the half that works offline.
zap_ver="${ZAP_VERSION#v}"
curl -fsSL -o /tmp/zap.zip \
	"https://github.com/zaproxy/zaproxy/releases/download/${ZAP_VERSION}/ZAP_${zap_ver}_Core.zip"
echo "${ZAP_CORE_SHA256}  /tmp/zap.zip" | sha256sum -c --strict -
unzip -q /tmp/zap.zip -d /opt
rm /tmp/zap.zip
[ -d "/opt/ZAP_${zap_ver}" ] || {
	echo "sabot heavy: ZAP unpacked to an unexpected path" >&2
	ls /opt >&2
	exit 1
}
mv "/opt/ZAP_${zap_ver}" /opt/zap
ln -sf /opt/zap/zap.sh /usr/local/bin/zap.sh

# ZAP MUST be invoked with `-dir <writable path>`. It does NOT honour $HOME: it derives its
# home from the passwd entry and hardcodes ~/.ZAP, so under the campaign's --read-only
# rootfs it refuses to start even with HOME on the tmpfs (measured):
#
#   Unable to create home directory: /home/breaker/.ZAP/
#   Is the path correct and there's write permission?
#
# Worse, it exits 0 while saying so, so a wrapper that trusts the exit code records a
# clean DAST pass that never ran. isolation.md carries this as a MUST.

# --- prove both RUN, and that Joern builds a CPG without the network ----------------
#
# `joern --version` is not enough. Joern's value is the CPG, and a CPG build is where a
# missing jar or a write to an unwritable $HOME shows up. So parse a real source file and
# assert the output graph exists. This is the same reasoning as cargo-deny's probe in
# rust-extras.sh: assert the WORK, not the version string.
java -version
joern --version
# -dir even here: without it ZAP writes into /root and the image carries dead state.
zap.sh -cmd -dir /opt/sabot-zap-home -version

# Joern writes caches and its workspace under $HOME. At campaign time HOME is on the
# /scratch tmpfs (run-contained.sh), writable; here it must not be /root, or the probe
# leaves root-owned state the breaker user cannot use.
export HOME=/opt/sabot-joern-home
mkdir -p "$HOME"

probe=/opt/sabot-heavy-probe
mkdir -p "$probe"
cat >"$probe/Sink.java" <<'EOF'
public class Sink {
	public static void run(String cmd) throws Exception {
		Runtime.getRuntime().exec(cmd);
	}
}
EOF
(
	cd "$probe"
	# joern-parse builds the CPG. Offline is the point: if any jar were missing or a
	# resolver ran, this is where it would fail rather than at query time.
	joern-parse "$probe" --output "$probe/cpg.bin"
	test -s "$probe/cpg.bin" || {
		echo "sabot heavy: joern-parse produced no CPG" >&2
		exit 1
	}
	echo "joern builds a CPG offline ($(stat -c %s "$probe/cpg.bin") bytes)"
)
rm -rf "${probe:?}"

# LAST: the probe above wrote into $HOME and the unpacks wrote as root. The campaign runs
# as uid 1000 against a read-only image, so anything unreadable now stays unreadable.
chmod -R a+rX /opt/joern-cli /opt/zap /opt/sabot-zap-home "$HOME"
