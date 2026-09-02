#!/usr/bin/env bash
#
# Collect external-acceptance evidence into one directory.
#
# The artifacts this produces are the only evidence that other people's mail
# systems accept what Pigeon sends. They are collected by a script rather than
# by hand because evidence assembled after the fact, from memory, by somebody
# who already believes the result, is not evidence.
#
# Nothing here talks to the network or publishes anything. It records what is
# in front of it, and checksums the lot at the end.
#
# See docs/ACCEPTANCE.md for the procedure this implements.

set -euo pipefail

: "${PIGEON_CONFIG:?PIGEON_CONFIG must point at the deployed configuration}"

pigeon_bin="${PIGEON_BIN:-pigeon}"
root="${ACCEPTANCE_DIR:-evidence}"

usage() {
    cat >&2 <<'USAGE'
usage: acceptance-capture.sh <command> [args]

  init <tag>                what is being tested: commit, versions, DNS state
  headers <provider>        complete received headers, on stdin
  placement <provider> <inbox|junk|quarantined|rejected|missing>
  delivery <spool-id>       this host's record of sending it
  bounce                    the SRS bounce as the original sender received it
  finish                    checksum every artifact into MANIFEST

The run directory is $ACCEPTANCE_DIR/<tag> (default evidence/<tag>), fixed by
init and remembered in evidence/.current for the commands that follow.
USAGE
    exit 64
}

# The run directory, chosen by `init` and reused by everything after it. Keeping
# it in a file rather than an environment variable means a run survives the
# operator closing their terminal, which over a multi-day bounce test is not a
# hypothetical.
current_run() {
    if [ ! -f "$root/.current" ]; then
        echo "no run in progress: start one with 'acceptance-capture.sh init <tag>'" >&2
        exit 1
    fi
    cat "$root/.current"
}

# Providers are a fixed set so that a typo becomes an error rather than a
# silently separate provider that nobody notices is missing from the manifest.
check_provider() {
    case "$1" in
        gmail|outlook|yahoo|fastmail|proton|other) ;;
        *)
            echo "unknown provider '$1' (gmail outlook yahoo fastmail proton other)" >&2
            exit 64
            ;;
    esac
}

cmd_init() {
    local tag="${1:-}"
    [ -n "$tag" ] || usage
    local run="$root/$tag"

    if [ -d "$run" ]; then
        echo "$run already exists. A re-run after any change needs its own" >&2
        echo "directory: artifacts from before a fix describe a build that is" >&2
        echo "no longer the one shipping." >&2
        exit 1
    fi

    mkdir -p "$run"
    printf '%s\n' "$run" > "$root/.current"

    {
        echo "tag           $tag"
        echo "commit        $(git rev-parse HEAD 2>/dev/null || echo 'not a git checkout')"
        echo "dirty         $(git status --porcelain 2>/dev/null | wc -l | tr -d ' ') modified files"
        echo "captured_by   $(id -un)@$(hostname)"
        echo "captured_at   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo
        echo "pigeon        $("$pigeon_bin" --version 2>&1 || echo unavailable)"
        echo "routing       $("$pigeon_bin" config checksum 2>&1 || echo unavailable)"
    } > "$run/RUN"

    # Health and DNS as they stood at the start. A provider result is only
    # interpretable against the configuration that produced it — a DKIM failure
    # reads very differently if `domains check` was already complaining.
    "$pigeon_bin" health --json      > "$run/health.json"       2>&1 || true
    "$pigeon_bin" domains check --json > "$run/domains-check.json" 2>&1 || true

    echo "Run $run started."
    echo
    echo "  $(sed -n '2p' "$run/RUN")"
    echo
    echo "If 'dirty' above is not 0, stop: an acceptance run against uncommitted"
    echo "changes proves nothing about the release."
}

cmd_headers() {
    local provider="${1:-}"
    [ -n "$provider" ] || usage
    check_provider "$provider"
    local run; run="$(current_run)"

    cat > "$run/headers-$provider.txt"

    if [ ! -s "$run/headers-$provider.txt" ]; then
        rm -f "$run/headers-$provider.txt"
        echo "nothing on stdin. Pipe the complete original message:" >&2
        echo "  acceptance-capture.sh headers $provider < original.txt" >&2
        exit 1
    fi

    # Not a verdict — a reading aid. The manifest keeps the complete headers,
    # and the judgement is made by a person against those.
    echo "Saved $(wc -l < "$run/headers-$provider.txt" | tr -d ' ') lines."
    echo
    grep -i -E '^(authentication-results|arc-authentication-results|received-spf|arc-seal|dkim-signature):' \
        "$run/headers-$provider.txt" | cut -c1-160 || echo "  no authentication headers found — check this is the complete original"
}

cmd_placement() {
    local provider="${1:-}" where="${2:-}"
    [ -n "$provider" ] && [ -n "$where" ] || usage
    check_provider "$provider"
    case "$where" in
        inbox|junk|quarantined|rejected|missing) ;;
        *) echo "placement must be one of: inbox junk quarantined rejected missing" >&2; exit 64 ;;
    esac
    local run; run="$(current_run)"

    printf '%s\t%s\t%s\n' "$provider" "$where" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        >> "$run/placement.tsv"
    echo "$provider: $where"

    # Authentication passing and the message landing in junk is the failure this
    # whole exercise exists to catch, and it is invisible from the sending side.
    if [ "$where" != "inbox" ]; then
        echo
        echo "Recorded as a finding. Placement is the result, not the 250:"
        echo "an authenticated message in a junk folder has not been delivered."
    fi
}

cmd_delivery() {
    local spool="${1:-}"
    [ -n "$spool" ] || usage
    local run; run="$(current_run)"

    # Ties the provider's copy to this host's record of sending it: the far
    # end's own 250 line, with its queue id, appears in the delivery events.
    "$pigeon_bin" queue show "$spool" --json > "$run/delivery-$spool.json"
    echo "Saved this host's record for $spool."
}

cmd_bounce() {
    local run; run="$(current_run)"
    cat > "$run/bounce.txt"

    if [ ! -s "$run/bounce.txt" ]; then
        rm -f "$run/bounce.txt"
        echo "nothing on stdin. Pipe the bounce as the original sender received it." >&2
        exit 1
    fi

    # The SRS ring as it stands, so a reversal failure can be read against the
    # keys that were live when the return path was issued rather than the keys
    # that are live now — those differ across a rotation, which is the case
    # where this evidence matters most.
    "$pigeon_bin" srs keys > "$run/srs-keys.txt" 2>&1 || true

    echo "Saved $(wc -l < "$run/bounce.txt" | tr -d ' ') lines."
    echo
    if grep -qi 'srs0=\|srs1=' "$run/bounce.txt"; then
        echo "Contains an SRS address. What matters is that this arrived at the"
        echo "ORIGINAL sender: that is the proof the reversal worked, and the"
        echo "return path in the bounce itself does not show it."
    else
        echo "No SRS address in the text. If this bounce reached the original"
        echo "sender anyway, the return path may not have been rewritten — which"
        echo "is a finding, not a pass."
    fi
}

cmd_finish() {
    local run; run="$(current_run)"

    ( cd "$run" && rm -f MANIFEST && \
      find . -type f ! -name MANIFEST | sort | xargs shasum -a 256 > MANIFEST )

    echo "Sealed $run:"
    echo
    sed 's/^/  /' "$run/MANIFEST"
    echo
    echo "Missing pieces, if any, are missing on purpose or the run is partial —"
    echo "record which in the release notes. A partial run is worth having; a"
    echo "partial run described as a pass is not."
    rm -f "$root/.current"
}

case "${1:-}" in
    init)      shift; cmd_init "$@" ;;
    headers)   shift; cmd_headers "$@" ;;
    placement) shift; cmd_placement "$@" ;;
    delivery)  shift; cmd_delivery "$@" ;;
    bounce)    shift; cmd_bounce "$@" ;;
    finish)    shift; cmd_finish "$@" ;;
    *)         usage ;;
esac
