package main

import (
	"strings"

	"github.com/steigr/strongbox-go/pkg/strongbox"
)

// resolveEntry selects the best matching entry for name from results.
//
// name may be a plain title ("bar") or a slash-separated path ("foo/bar",
// "a/b/c"). For path queries the last component is the entry title; preceding
// components form the group path used to disambiguate entries that share a
// title.
//
// Resolution order:
//  1. Collect entries whose Title exactly matches the last path component
//     (case-insensitive). If none match exactly, all results are candidates.
//  2. If only one candidate remains, return it.
//  3. If a group path was given, filter candidates whose BreadcrumbTitle
//     matches that path (see matchesBreadcrumb). If this yields exactly one
//     entry, return it.
//  4. Return the first remaining candidate (preserves existing behaviour when
//     disambiguation is not possible, e.g. when BreadcrumbTitle is empty).
//
// Returns nil when results is empty.
func resolveEntry(results []strongbox.AutoFillCredential, name string) *strongbox.AutoFillCredential {
	if len(results) == 0 {
		return nil
	}

	entryName := name
	groupPath := ""
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		entryName = name[idx+1:]
		groupPath = name[:idx]
	}

	// 1. Exact title matches.
	candidates := make([]int, 0, len(results))
	for i := range results {
		if strings.EqualFold(results[i].Title, entryName) {
			candidates = append(candidates, i)
		}
	}
	if len(candidates) == 0 {
		// No exact match: treat all results as candidates (fuzzy search hit).
		for i := range results {
			candidates = append(candidates, i)
		}
	}

	// 2. Single candidate: done.
	if len(candidates) == 1 {
		return &results[candidates[0]]
	}

	// 3. Group path disambiguation via BreadcrumbTitle.
	if groupPath != "" {
		var pathMatches []int
		for _, i := range candidates {
			if matchesBreadcrumb(results[i].BreadcrumbTitle, groupPath) {
				pathMatches = append(pathMatches, i)
			}
		}
		if len(pathMatches) == 1 {
			return &results[pathMatches[0]]
		}
		if len(pathMatches) > 1 {
			candidates = pathMatches
		}
		// len == 0: no breadcrumb info available; fall through.
	}

	// 4. First candidate.
	return &results[candidates[0]]
}

// searchTerm returns the Strongbox query to use for name. For path queries the
// last component (entry title) is used so that entries in non-AutoFill groups
// are not silently excluded when the group name alone would match nothing.
func searchTerm(name string) string {
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		return name[idx+1:]
	}
	return name
}

// matchesBreadcrumb reports whether breadcrumb places an entry inside
// groupPath. It handles two forms that Strongbox may produce:
//
//   - Group-only:  "foo"      (just the parent group path)
//   - Full path:   "foo/bar"  (group path + "/" + entry title)
//
// " > " separators (Strongbox UI style) are normalised to "/" before
// comparison. Both sides are lower-cased; leading/trailing slashes ignored.
func matchesBreadcrumb(breadcrumb, groupPath string) bool {
	if breadcrumb == "" || groupPath == "" {
		return false
	}
	norm := strings.ToLower(strings.Trim(strings.ReplaceAll(breadcrumb, " > ", "/"), "/"))
	gp := strings.ToLower(strings.Trim(groupPath, "/"))

	// Case A: breadcrumb is the group path only (no entry title appended).
	if norm == gp {
		return true
	}
	// Case B: breadcrumb is the full path (group/entryTitle); strip the last
	// component and compare the remainder to groupPath.
	if idx := strings.LastIndex(norm, "/"); idx >= 0 {
		return norm[:idx] == gp
	}
	return false
}
