#!/usr/bin/env bash
# This repository is public and its history cannot be unpublished — a
# rewrite changes the SHAs but not what was already fetched. So the rule
# ("mechanism only; particulars are caller inputs or org variables") is
# enforced mechanically rather than remembered.
#
# Vendored from truvity/ci-workflows (hack/leak-canary.sh), which is public
# for the same reason. Keep it in step with that copy.
#
# Every chart value, module input or hierarchy field that names a cluster,
# an account, a hostname, a key or a secret path is an INPUT with a neutral
# default; the consuming estate supplies the particulars from its own
# repository.
#
# Deltas from that copy, each with its reason (the Go module brought them):
#
#   - No bare 'arn:aws' pattern. pkg/custody COMPOSES the ARNs of its key
#     policies from caller inputs, and its tests, pkg/ceremony's and the
#     documentation assert composed ARNs. A concrete leaked ARN still trips
#     the account-id pattern: every real ARN carries a 12-digit account.
#   - The account-id pattern skips AWS's own documented placeholder
#     accounts (111122223333, 444455556666), the neutral values the
#     component contract asks examples and tests to use. Only those two:
#     a real account on the same line as one still matches.
#   - go.mod and go.sum are not scanned: their content is public
#     dependency data by definition, and pseudo-version timestamps are
#     long digit runs.
#
# Add a pattern here the first time something new turns out to be a
# particular. Never add an exception without one.
set -uo pipefail

account_id='\b[0-9]{12}\b'
documented_placeholders='\b(111122223333|444455556666)\b'

# The 12-digit patterns are anchored on word boundaries. Without them,
# `[0-9]{12}` also matches a 12-digit run that happens to fall inside a
# longer hex string -- and a nixpkgs commit SHA is exactly that. The
# devbox bump to 17de0b976395537756f30a3e78f2f06e5cec89ed contains
# `976395537756`, which failed this canary simultaneously in every repo
# that carries it, for a value that is neither a particular nor secret.
# `\b` keeps every real shape (bare, in an ARN, as an ECR host: each is
# bounded by a non-word character) and drops the hex-embedded ones.
patterns=(
  "$account_id"                            # AWS account id
  '\b[0-9]{12}\.dkr\.ecr\.'              # ECR registry host
  '\.svc\.cluster\.local'              # in-cluster DNS
  '/secrets/'                          # SSM parameter paths
  'truvity-[a-z0-9-]*-(ci-cache|artifacts|state)'   # S3 buckets
  '\.truvity\.(xyz|com|co)'            # internal hostnames
  'glpat-|ghp_|github_pat_'            # tokens, in case of an accident
)

fail=0

# Scan TRACKED FILES ONLY. The point of this canary is to stop particulars
# being committed, so git's index is exactly the right scope -- and a
# recursive walk of the working tree is not. It descended into generated,
# gitignored directories: .devbox/state.json carries a
# `nix_print_dev_env_hash` whose hex contains a 12-digit run, which matched
# the AWS-account-id pattern. That made the canary fail on a clean checkout
# for a value that is neither committed nor secret.
#
# This matters more than a nuisance: a canary that cries wolf is one people
# learn to skip, and this one is what stands between us and publishing
# particulars from a public repo.
mapfile -d '' tracked < <(git ls-files -z)

for p in "${patterns[@]}"; do
  # Exclude this script: it necessarily contains the patterns it bans.
  hits=$(printf '%s\0' "${tracked[@]}" \
           | grep -zZvE '^(hack/leak-canary\.sh|go\.mod|go\.sum)$' \
           | xargs -0 -r grep -InE "$p" 2>/dev/null \
           | sed -E 's#truvity/secrets##g' | grep -E "$p")
  # (the repository's own name, truvity/secrets, is public and is not an SSM path)
  if [ "$p" = "$account_id" ] && [ -n "$hits" ]; then
    hits=$(printf '%s\n' "$hits" | sed -E "s/$documented_placeholders/<placeholder>/g" | grep -E "$p")
  fi
  if [ -n "$hits" ]; then
    echo "LEAK: pattern /$p/ matched — particulars belong in caller inputs or org variables:"
    echo "$hits" | head -5 | sed 's/^/    /'
    fail=1
  fi
done

# The worked example (examples/org) is the one place an adopter copies from, so
# it is held to a stricter rule than the rest: it describes a made-up
# organisation. No name of a real one, and every host it names is under a
# domain reserved for examples (RFC 2606) or is a bare placeholder.
#
#   - Not the names of the organisations that maintain this repository, or of
#     the estates that adopt it. (An import path of this module is not a
#     name: it is removed before the match.)
#   - Every URL's host is under example.com, example.org, example.net or
#     example.internal, or is a bare name or `<service>.<namespace>.svc` (a Service of the
#     install itself; `.svc.cluster.local` stays banned above),
#     loopback, or one of the public registries the plugin images come from.
org_files=$(git ls-files -z -- 'examples/org' | tr '\0' '\n')
if [ -n "$org_files" ]; then
  # shellcheck disable=SC2086
  names=$(grep -InEi 'truvity|opwerm|nexus|trustform|trust-form' $org_files 2>/dev/null \
            | grep -vE 'github\.com/truvity/secrets' | head -5)
  if [ -n "$names" ]; then
    echo "LEAK: examples/org names an organisation — it describes a made-up one:"
    echo "$names" | sed 's/^/    /'
    fail=1
  fi

  # shellcheck disable=SC2086
  regions=$(grep -InE 'eu-central-1|eu-north-1' $org_files 2>/dev/null | head -5)
  if [ -n "$regions" ]; then
    echo "LEAK: examples/org names a real region (use eu-example-1, eu-example-2):"
    echo "$regions" | sed 's/^/    /'
    fail=1
  fi

  # shellcheck disable=SC2086
  hosts=$(grep -InEo 'https?://[A-Za-z0-9._-]+' $org_files 2>/dev/null \
            | grep -vE '://[A-Za-z0-9._-]*(example\.(com|org|net|internal)|alertmanager\.example\.svc)$' \
            | grep -vE '://(github\.com|ghcr\.io|pkg-containers\.githubusercontent\.com|127\.0\.0\.1|localhost)$' \
            | grep -vE '://[A-Za-z0-9-]+(\.openbao-internal|\.[A-Za-z0-9-]+\.svc)?$' | head -5)
  if [ -n "$hosts" ]; then
    echo "LEAK: examples/org names a host outside the reserved example domains:"
    echo "$hosts" | sed 's/^/    /'
    fail=1
  fi
fi

if [ "$fail" = 0 ]; then
  echo "leak canary clean — ${#patterns[@]} patterns checked, no particulars found"
fi
exit $fail
