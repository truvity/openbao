package builder

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// ciSecretSegments is how many segments a CI secret path has:
// `<prefix>/<key>` under the shared KV mount.
const ciSecretSegments = 2

// ciSecretSegment is one segment of a CI secret path: no wildcard, no dot,
// nothing that could climb out of the prefix a policy names.
var ciSecretSegment = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// CISecretPolicy is the policy name of a CI secret path, derived so that a
// rename of the path renames the policy with it and there is no second name
// to keep in step: `ci/goreleaser` is `ci-goreleaser`.
func CISecretPolicy(path string) string {
	return strings.ReplaceAll(path, "/", "-")
}

// CISecretGrants turns "which groups may read which secret path" into the
// single-secret [SecretGrant]s [Environment.Secrets] takes, sorted by path,
// each with its groups sorted and its policy named by [CISecretPolicy].
//
// It refuses what would widen a CI job's reach beyond one path: a path that
// is not `<prefix>/<key>` with lower-case letters, digits and dashes in each
// segment, a path nobody reads, and two paths that derive one policy name
// (whichever applied second would silently take the other's rules). Who may
// be a holder is the caller's rule.
func CISecretGrants(paths map[string][]string) ([]SecretGrant, error) {
	var (
		out      []SecretGrant
		problems []error
	)

	derived := map[string]string{}

	for _, path := range slices.Sorted(maps.Keys(paths)) {
		fail := func(format string, args ...any) {
			problems = append(problems, fmt.Errorf("secret path %q: "+format, append([]any{path}, args...)...))
		}

		segments := strings.Split(path, "/")
		if len(segments) != ciSecretSegments {
			fail("not <prefix>/<key>")
		}

		for _, segment := range segments {
			if !ciSecretSegment.MatchString(segment) {
				fail("%q is not a path segment: lower-case letters, digits and dashes", segment)
			}
		}

		policy := CISecretPolicy(path)
		if other, dup := derived[policy]; dup {
			fail("its policy name %q is %q's too -- two paths may not derive one policy", policy, other)
		}

		derived[policy] = path

		groups := slices.Sorted(slices.Values(paths[path]))
		if len(groups) == 0 {
			fail("grants nobody; a path nobody reads is one to keep in step for nothing")
		}

		out = append(out, SecretGrant{Policy: policy, Path: path, Groups: groups})
	}

	if err := errors.Join(problems...); err != nil {
		return nil, err
	}

	return out, nil
}
