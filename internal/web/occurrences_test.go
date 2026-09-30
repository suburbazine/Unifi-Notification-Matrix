package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/store"
)

// THE BOARD SHOWS EVERY OCCURRENCE IT KEPT, NOT ONLY THE NEWEST.
//
// The incident's own title and detail are the newest arrival's, which is what
// an alert should be about and exactly what hides the others. A manager
// reviewing "Sale voided at Register 1 -- occurrence 3" has to be able to see
// all three voids, and the count on its own does not say which sales.
//
// Against the REAL store: the list is read through an optional interface, and
// a fake without it would answer an empty list and pass.
func TestTheBoardListsAnIncidentsOccurrences(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "incidents.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	t0 := time.Date(2026, 9, 30, 13, 0, 0, 0, time.UTC)

	inc := incident.Open("inc-1", "lsprotect/wv01-register-1/lsprotect-sale-voided",
		incident.SeverityMedium, "lsprotect", "Sale voided at Register 1", "invoice 1001", t0)
	if err := db.AddOccurrence(ctx, inc.ID, inc.FirstOccurrence(), 0); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"invoice 1002", "invoice 1003"} {
		o, err := inc.Occur(t0.Add(time.Minute), incident.SeverityMedium, "Sale voided at Register 1", d)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.AddOccurrence(ctx, inc.ID, o, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Put(ctx, inc); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	srv, err := New(Deps{
		Store:           db,
		Config:          func() *config.Config { return cfg },
		SaveConfig:      func(*config.Config) error { return nil },
		Health:          func() Health { return Health{} },
		PasswordHash:    func() string { return "" },
		SetPasswordHash: func(string) error { return nil },
		Version:         "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	// The count, on the list the board already reads.
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/incidents", nil))
	var list struct{ Incidents []incidentView }
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("incident list: %v\n%s", err, w.Body.String())
	}
	if len(list.Incidents) != 1 || list.Incidents[0].Occurrences != 3 {
		t.Fatalf("the board's list says %+v; want one incident with 3 occurrences", list.Incidents)
	}

	// Every one of them, newest first.
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/incidents/inc-1/occurrences", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("occurrences answered %d: %s", w.Code, w.Body.String())
	}
	var got struct {
		Occurrences []occurrenceView `json:"occurrences"`
		Kept        int              `json:"kept"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Occurrences) != 3 {
		t.Fatalf("listed %d occurrences, want all 3", len(got.Occurrences))
	}
	for i, want := range []string{"invoice 1003", "invoice 1002", "invoice 1001"} {
		if got.Occurrences[i].Detail != want {
			t.Errorf("occurrence %d is %q, want %q (newest first)", i, got.Occurrences[i].Detail, want)
		}
	}
	if got.Kept != incident.MaxOccurrences {
		t.Errorf("kept = %d; the page needs the cap to say when older ones are gone", got.Kept)
	}

	// An incident that does not exist is not an empty list.
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/incidents/nope/occurrences", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("a missing incident answered %d, want 404", w.Code)
	}
}
