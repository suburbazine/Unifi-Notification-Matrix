package web

import (
	"net/http"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/setup"
)

// handleChecklist reports what is left to do to make this installation work.
//
// PUBLIC, like the status page, and for the same reason: somebody standing in
// front of a wall display should be able to see that nothing is configured.
// But a hook URL is a CREDENTIAL -- anyone holding one can raise an alarm here
// -- so the URLs are included only for a signed-in caller. A reader who is not
// signed in learns that a hook exists and whether anything has ever arrived at
// it, which is the useful half and discloses nothing.
func (s *Server) handleChecklist(w http.ResponseWriter, r *http.Request) {
	if s.deps.Checklist == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"available": false,
			"detail":    "this build does not report a setup checklist",
		})
		return
	}
	in := s.deps.Checklist()
	authed := s.authenticated(r)

	// Each line of How goes out with its kind, so the page can draw a
	// warning as a bordered callout and number only the actions. The kind
	// is decided by setup.KindOf, in the package that writes the lines --
	// not by the page guessing from capital letters, which would drift the
	// first time somebody reworded a warning.
	lines := func(ls []string) []map[string]string {
		out := make([]map[string]string, 0, len(ls))
		for _, l := range ls {
			out = append(out, map[string]string{"text": l, "kind": string(setup.KindOf(l))})
		}
		return out
	}
	steps := make([]map[string]any, 0, 8)
	for _, st := range setup.Steps(in) {
		ref := make([]map[string]any, 0, len(st.Reference))
		for _, t := range st.Reference {
			ref = append(ref, map[string]any{"title": t.Title, "lines": lines(t.Lines)})
		}
		steps = append(steps, map[string]any{
			"key":       st.Key,
			"title":     st.Title,
			"status":    string(st.Status),
			"why":       st.Why,
			"state":     st.State,
			"how":       lines(st.How),
			"reference": ref,
		})
	}

	hooks := make([]map[string]any, 0, len(in.Hooks))
	for _, h := range in.Hooks {
		row := map[string]any{
			"name": h.Name, "product": h.Product,
			"count": h.Count, "last_at": h.LastAt,
			// Counts and reasons carry no credential, and they are the answer
			// to "I made the rule and nothing happens" -- so they are readable
			// without a session, like everything else on the status surface.
			"rejected": h.Rejected, "last_reject": h.LastReject,
			// Test mode is NOT a credential, and it is the most important
			// thing on this row: a hook in test mode is accepting real alarms
			// and throwing them away. Anything that can see the hook can see
			// that, including a wall display nobody is signed in at.
			"test_armed_until": h.TestArmedUntil,
			"test_count":       h.TestCount,
			"last_test_at":     h.LastTestAt,
		}
		if authed {
			// The URL and the header are BOTH credentials. Either one alone is
			// not enough to raise an alarm here, which is the point of having
			// two -- but neither is anybody else's business.
			row["url"] = h.URL
			row["header_name"] = setup.HeaderName
			row["header_value"] = h.Header
		}
		hooks = append(hooks, row)
	}

	sources := make([]map[string]any, 0, len(in.SourcesLive))
	for _, src := range in.SourcesLive {
		detail := ""
		if src.Fatal != "" {
			detail = "cannot run: " + src.Fatal
		}
		sources = append(sources, map[string]any{
			"name": src.Name, "silent": src.Silent,
			"events": src.Events, "detail": detail,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"available":     true,
		"ready":         setup.Ready(in),
		"authenticated": authed,
		"steps":         steps,
		"hooks":         hooks,
		"sources":       sources,
	})
}
