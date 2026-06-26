package main

import (
	"strings"
	"testing"

	"github.com/steigr/strongbox-go/pkg/strongbox"
)

func TestUnlockedNonAutoFillHint(t *testing.T) {
	cases := []struct {
		name      string
		databases []strongbox.DatabaseSummary
		wantEmpty bool
		wantSubs  []string
	}{
		{
			name:      "no databases",
			databases: nil,
			wantEmpty: true,
		},
		{
			name: "all autofill unlocked",
			databases: []strongbox.DatabaseSummary{
				{NickName: "Work", AutoFillEnabled: true, Locked: false},
			},
			wantEmpty: true,
		},
		{
			name: "autofill locked only",
			databases: []strongbox.DatabaseSummary{
				{NickName: "Work", AutoFillEnabled: true, Locked: true},
			},
			wantEmpty: true,
		},
		{
			name: "non-autofill locked — no hint",
			databases: []strongbox.DatabaseSummary{
				{NickName: "Archive", AutoFillEnabled: false, Locked: true},
			},
			wantEmpty: true,
		},
		{
			name: "one unlocked non-autofill database",
			databases: []strongbox.DatabaseSummary{
				{NickName: "Work", AutoFillEnabled: true, Locked: false},
				{NickName: "Archive", AutoFillEnabled: false, Locked: false},
			},
			wantEmpty: false,
			wantSubs:  []string{"Archive", "AutoFill"},
		},
		{
			name: "multiple unlocked non-autofill databases",
			databases: []strongbox.DatabaseSummary{
				{NickName: "A", AutoFillEnabled: false, Locked: false},
				{NickName: "B", AutoFillEnabled: false, Locked: false},
			},
			wantEmpty: false,
			wantSubs:  []string{"A", "B", "AutoFill"},
		},
		{
			name: "mix: autofill unlocked, non-autofill unlocked, autofill locked",
			databases: []strongbox.DatabaseSummary{
				{NickName: "Active", AutoFillEnabled: true, Locked: false},
				{NickName: "Offline", AutoFillEnabled: false, Locked: false},
				{NickName: "Locked", AutoFillEnabled: true, Locked: true},
			},
			wantEmpty: false,
			wantSubs:  []string{"Offline"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status := &strongbox.GetStatusResponse{Databases: c.databases}
			hint := unlockedNonAutoFillHint(status)
			if c.wantEmpty {
				if hint != "" {
					t.Errorf("expected empty hint, got: %q", hint)
				}
				return
			}
			if hint == "" {
				t.Fatal("expected non-empty hint, got empty")
			}
			for _, sub := range c.wantSubs {
				if !strings.Contains(hint, sub) {
					t.Errorf("hint %q does not contain %q", hint, sub)
				}
			}
		})
	}
}
