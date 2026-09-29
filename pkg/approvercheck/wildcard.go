package approvercheck

// Ported from github.com/cert-manager/approver-policy pkg/internal/util
// (v0.28.0, pkg/internal/util/wildcard.go), which pkg/internal/approver/...
// uses for every glob comparison. Not importable directly: it lives under
// approver-policy's own internal/ tree, and Go's internal-package rule
// blocks any import whose path does not share the prefix up to the parent
// of "internal" -- true regardless of vendoring. This is a byte-for-byte
// copy of the algorithm (only the package name changed), so approvercheck's
// glob semantics match approver-policy's exactly. See the package documentation
// (doc.go) for why the evaluators are ported rather than imported.

// wildcardMatches reports whether str matches pattern, where '*' in pattern
// matches any run of zero or more characters (and only '*' -- no '?', no
// character classes).
func wildcardMatches(pattern, str string) bool {
	if pattern == "" {
		return str == ""
	}

	if pattern == "*" {
		return true
	}

	return matchRunes([]rune(pattern), []rune(str))
}

// wildcardContains reports whether str matches at least one of patterns.
func wildcardContains(patterns []string, str string) bool {
	for _, pattern := range patterns {
		if wildcardMatches(pattern, str) {
			return true
		}
	}

	return false
}

// wildcardSubset reports whether every member of members matches at least
// one pattern in patterns -- i.e. members is a subset of what patterns
// allows.
func wildcardSubset(patterns, members []string) bool {
	for _, member := range members {
		if !wildcardContains(patterns, member) {
			return false
		}
	}

	return true
}

// matchRunes is the standard iterative backtrack-checkpoint glob matcher
// (Russ Cox, "Glob Matching Can Be Simple And Fast Too",
// https://research.swtch.com/glob) -- the same algorithm Go's own
// path/filepath.Match and glibc's glob(3) use. On each '*' it records one
// checkpoint and, on a later mismatch, rewinds str one past that checkpoint
// rather than forking, so it runs in O(n*m) with no exponential blowup on
// multiple wildcards (CWE-770).
func matchRunes(pattern, str []rune) bool {
	px, sx := 0, 0
	starPx, starSx := -1, -1

	for sx < len(str) {
		switch {
		case px < len(pattern) && pattern[px] == '*':
			starPx, starSx = px, sx
			px++
		case px < len(pattern) && pattern[px] == str[sx]:
			px++
			sx++
		case starPx >= 0:
			starSx++
			sx = starSx
			px = starPx + 1
		default:
			return false
		}
	}

	for px < len(pattern) && pattern[px] == '*' {
		px++
	}

	return px == len(pattern)
}
