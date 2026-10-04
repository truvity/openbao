#!/usr/bin/env bash
# Golden renders: every tests/cases/<chart>/<case>/values.yaml is rendered
# with `helm template` and compared byte-for-byte against
# tests/golden/<chart>/<case>.yaml. A template change that alters output
# therefore shows up as a reviewable diff, with no cluster involved.
#
# The worked example's values (examples/org/<level>/{ops,consumers}.values.yaml)
# are rendered the same way, against examples/org/<level>/golden/<chart>.yaml.
#
#   hack/golden.sh            compare (CI)
#   hack/golden.sh update     regenerate the golden files
#   hack/golden.sh examples   compare the worked example's only
set -euo pipefail

mode="${1:-check}"
root="$(cd "$(dirname "$0")/.." && pwd)"
fail=0

for values in "$root"/tests/cases/*/*/values.yaml; do
  [ "$mode" = examples ] && break
  case_dir="$(dirname "$values")"
  case_name="$(basename "$case_dir")"
  chart="$(basename "$(dirname "$case_dir")")"
  golden="$root/tests/golden/$chart/$case_name.yaml"

  # A case may pin its release name (tests/cases/<chart>/<case>/release) as
  # well as its namespace: object names and selectors that carry the release
  # are exactly what a second install in one namespace depends on.
  release="$(cat "$case_dir/release" 2>/dev/null || echo "$chart")"

  rendered="$(helm template "$release" "$root/charts/$chart" \
      --namespace "$(cat "$case_dir/namespace" 2>/dev/null || echo default)" \
      -f "$values")"

  if [ "$mode" = update ]; then
    mkdir -p "$(dirname "$golden")"
    printf '%s\n' "$rendered" > "$golden"
    echo "updated $golden"
    continue
  fi

  if ! diff -u "$golden" <(printf '%s\n' "$rendered"); then
    echo "GOLDEN MISMATCH: $chart/$case_name — run 'just golden' and review the diff"
    fail=1
  fi
done

# The worked example: each level's own values files, rendered whole (a level
# repeats everything the level below says, so it renders without it).
for values in "$root"/examples/org/0*/ops.values.yaml "$root"/examples/org/0*/consumers.values.yaml; do
  [ -e "$values" ] || continue
  level_dir="$(dirname "$values")"
  chart="openbao-$(basename "$values" .values.yaml)"
  golden="$level_dir/golden/$chart.yaml"

  rendered="$(helm template "$chart" "$root/charts/$chart" --namespace default -f "$values")"

  if [ "$mode" = update ]; then
    mkdir -p "$level_dir/golden"
    printf '%s\n' "$rendered" > "$golden"
    echo "updated $golden"
    continue
  fi

  if ! diff -u "$golden" <(printf '%s\n' "$rendered"); then
    echo "GOLDEN MISMATCH: examples/org/$(basename "$level_dir")/$chart — run 'just golden' and review the diff"
    fail=1
  fi
done

[ "$fail" = 0 ] && echo "golden renders match"
exit $fail
