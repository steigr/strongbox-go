package main

import (
	"testing"

	"github.com/steigr/strongbox-go/pkg/strongbox"
)

func cred(title, breadcrumb string) strongbox.AutoFillCredential {
	return strongbox.AutoFillCredential{Title: title, BreadcrumbTitle: breadcrumb, UUID: title}
}

// ---------------------------------------------------------------------------
// searchTerm
// ---------------------------------------------------------------------------

func TestSearchTerm(t *testing.T) {
	cases := []struct{ in, want string }{
		{"bar", "bar"},
		{"foo/bar", "bar"},
		{"a/b/c", "c"},
		{"foo/bar/baz", "baz"},
		{"/bar", "bar"},
	}
	for _, c := range cases {
		if got := searchTerm(c.in); got != c.want {
			t.Errorf("searchTerm(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// matchesBreadcrumb
// ---------------------------------------------------------------------------

func TestMatchesBreadcrumb(t *testing.T) {
	cases := []struct {
		breadcrumb, groupPath string
		want                  bool
	}{
		// breadcrumb = full path (group + "/" + entry title)
		{"foo/bar", "foo", true},
		{"foo/bar", "bar", false},  // "bar" is the entry title, not a group
		{"a/b/c", "a/b", true},
		{"a/b/c", "b/c", false},   // "c" is the entry; remainder is "a/b" ≠ "b/c"
		{"a/b/c", "a", false},     // "a" is a prefix, not the direct parent group

		// breadcrumb = group path only (entry title not appended)
		{"foo", "foo", true},
		{"a/b", "a/b", true},
		{"other", "foo", false},

		// " > " separator (Strongbox UI style) — groupPath always uses "/"
		{"foo > bar", "foo", true},
		{"a > b > c", "a/b", true},

		// edge cases
		{"", "foo", false},
		{"foo", "", false},
		{"Foo/Bar", "foo", true}, // case-insensitive
	}
	for _, c := range cases {
		got := matchesBreadcrumb(c.breadcrumb, c.groupPath)
		if got != c.want {
			t.Errorf("matchesBreadcrumb(%q, %q) = %v, want %v", c.breadcrumb, c.groupPath, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// resolveEntry
// ---------------------------------------------------------------------------

func TestResolveEntry_EmptyResults(t *testing.T) {
	if resolveEntry(nil, "bar") != nil {
		t.Fatal("expected nil for empty results")
	}
	if resolveEntry([]strongbox.AutoFillCredential{}, "bar") != nil {
		t.Fatal("expected nil for empty results")
	}
}

func TestResolveEntry_SingleResult(t *testing.T) {
	results := []strongbox.AutoFillCredential{cred("bar", "")}
	e := resolveEntry(results, "bar")
	if e == nil || e.Title != "bar" {
		t.Fatal("expected bar")
	}
}

func TestResolveEntry_ExactTitleMatch(t *testing.T) {
	results := []strongbox.AutoFillCredential{
		cred("barbecue", ""),
		cred("bar", ""),
		cred("barbell", ""),
	}
	e := resolveEntry(results, "bar")
	if e.Title != "bar" {
		t.Errorf("got %q, want bar", e.Title)
	}
}

func TestResolveEntry_FirstResultWhenNoExactMatch(t *testing.T) {
	results := []strongbox.AutoFillCredential{
		cred("barbecue", ""),
		cred("barbell", ""),
	}
	e := resolveEntry(results, "bar")
	if e.Title != "barbecue" {
		t.Errorf("got %q, want first result barbecue", e.Title)
	}
}

func TestResolveEntry_PathQuery_UniqueTitle(t *testing.T) {
	// Only one entry named "bar", regardless of group — return it.
	results := []strongbox.AutoFillCredential{
		cred("something", "other"),
		cred("bar", "foo"),
	}
	e := resolveEntry(results, "foo/bar")
	if e.Title != "bar" {
		t.Errorf("got %q, want bar", e.Title)
	}
}

func TestResolveEntry_PathQuery_BreadcrumbDisambiguates(t *testing.T) {
	// Two entries named "bar" in different groups.
	results := []strongbox.AutoFillCredential{
		cred("bar", "other"),
		cred("bar", "foo"),
	}
	e := resolveEntry(results, "foo/bar")
	if e.BreadcrumbTitle != "foo" {
		t.Errorf("got breadcrumb %q, want foo", e.BreadcrumbTitle)
	}
}

func TestResolveEntry_PathQuery_BreadcrumbGTSeparator(t *testing.T) {
	// Strongbox UI uses " > " as separator.
	results := []strongbox.AutoFillCredential{
		cred("bar", "other > sub"),
		cred("bar", "foo > sub"),
	}
	e := resolveEntry(results, "foo/sub/bar")
	if e.BreadcrumbTitle != "foo > sub" {
		t.Errorf("got breadcrumb %q, want foo > sub", e.BreadcrumbTitle)
	}
}

func TestResolveEntry_PathQuery_NoBreadcrumb_FallsBackToFirstTitleMatch(t *testing.T) {
	// No breadcrumb info: can't disambiguate, use first exact title match.
	results := []strongbox.AutoFillCredential{
		cred("bar", ""),
		cred("bar", ""),
	}
	results[0].UUID = "first"
	results[1].UUID = "second"
	e := resolveEntry(results, "foo/bar")
	if e.UUID != "first" {
		t.Errorf("got UUID %q, want first", e.UUID)
	}
}

func TestResolveEntry_PathQuery_CaseInsensitive(t *testing.T) {
	results := []strongbox.AutoFillCredential{
		cred("BAR", "FOO"),
	}
	e := resolveEntry(results, "foo/bar")
	if e == nil || e.Title != "BAR" {
		t.Fatal("case-insensitive match failed")
	}
}

func TestResolveEntry_DeepPath(t *testing.T) {
	results := []strongbox.AutoFillCredential{
		cred("baz", "a/b"),
		cred("baz", "x/y"),
	}
	e := resolveEntry(results, "a/b/baz")
	if e.BreadcrumbTitle != "a/b" {
		t.Errorf("got %q, want a/b", e.BreadcrumbTitle)
	}
}
