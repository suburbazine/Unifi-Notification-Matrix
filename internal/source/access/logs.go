package access

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

// Log polling constants.
//
// The binding constraint here is NOT the console's rate limit. Access indexes
// its system log asynchronously and rows have been measured arriving up to
// about three and a half minutes after the event. Polling faster than that
// buys nothing and spends a request budget the Protect reconciliation sweeps
// on the same console need.
const (
	// defaultPollEvery is the floor, not a tuning knob. Below the indexing lag
	// every extra poll returns rows the previous one already returned.
	defaultPollEvery = 3 * time.Minute

	// defaultOverlap is how far back each window reaches beyond the last one.
	//
	// Comfortably more than twice the worst measured lag. Overlap is cheap --
	// duplicate rows are discarded by id -- and a gap is not recoverable,
	// because there is no cursor to rewind to and the row is simply never seen.
	defaultOverlap = 10 * time.Minute

	logPageSize = 500
	logMaxPages = 20

	// maxSeenRows bounds the de-duplication set. A busy site with a long
	// overlap must not be able to grow it without limit.
	maxSeenRows = 50_000
)

// topicsPolled are the log topics this source reads.
//
// Deliberately two, not six:
//
//   - `door_openings` is the ONLY confirmed source of denials, which is the
//     alarm class Access does not push anywhere else.
//   - `critical` is the console's own escalation of anything it considers
//     serious, relayed rather than reinterpreted.
//
// `admin_activity`, `device_events`, `updates` and `visitor` are not polled.
// They carry real information, but none of it is a CONDITION -- an added
// credential is a fact for the audit record, not something that stays true and
// needs acknowledging, and turning each one into an incident would put a queue
// of un-ackable rows in front of the alarms. `device_events` additionally
// carries door-position rows that are informational only and arrive minutes
// late, which is why position is polled directly instead.
var topicsPolled = []string{topicDoorOpenings, topicCritical}

// denialMarkers identify a refused credential in a log row.
//
// Matched as substrings of the event type and log key, because THE LOG KEY
// VOCABULARY HAS NEVER BEEN ENUMERATED from hardware. That is not a shortcut
// to be tidied up later -- it is why unrecognised keys are counted by name in
// Health and why `notifymatrix probe` exists. A site that finds a denial class
// missing here can capture the real key and it can be added.
var denialMarkers = []string{
	"denied", "deny", "reject", "unauthorized", "unauthorised",
	"invalid", "fail", "forbidden", "not_allowed", "no_permission",
}

// logRow is a decoded row plus the decision this source made about it.
type logRow struct {
	hit   logHit
	topic string
}

// fetchLogs is one page of one topic. Injected so the poller is testable
// without a console.
type fetchLogs func(ctx context.Context, topic string, since, until time.Time, page int) ([]logHit, error)

// poller reads the system log on a schedule, with an overlapping window and
// de-duplication by row id.
type poller struct {
	fetch    fetchLogs
	every    time.Duration
	overlap  time.Duration
	now      func() time.Time
	maxPages int

	mu sync.Mutex

	// watermark is the end of the last window that COMPLETED. It advances only
	// on success -- see poll.
	watermark time.Time

	// seen is row ids already emitted, with when they were seen so the set can
	// be evicted. The row id is the only trustworthy de-duplicator: `since`
	// and `until` are seconds while `event.published` is milliseconds, and the
	// inclusive/exclusive boundary semantics are undocumented and unmeasured,
	// so the time boundary cannot be relied on for correctness.
	seen map[string]time.Time

	// unknownKeys counts log keys this source did not recognise, by name.
	unknownKeys map[string]int64
	rowsSeen    int64
	lastErr     string
	lastRunAt   time.Time
}

func newPoller(fetch fetchLogs, every, overlap time.Duration, now func() time.Time) *poller {
	if every <= 0 {
		every = defaultPollEvery
	}
	if overlap <= 0 {
		overlap = defaultOverlap
	}
	if now == nil {
		now = time.Now
	}
	return &poller{
		fetch: fetch, every: every, overlap: overlap, now: now,
		maxPages:    logMaxPages,
		seen:        map[string]time.Time{},
		unknownKeys: map[string]int64{},
	}
}

// poll reads one window across every polled topic.
//
// THE WATERMARK ADVANCES ONLY IF EVERY TOPIC SUCCEEDED. A partial window looks
// exactly like a complete one to everything downstream, so advancing past a
// failed query silently drops whatever was in it -- and on a log with no
// cursor, dropped means gone. The cost of not advancing is re-reading rows
// that are then discarded by id; the cost of advancing is a denial nobody ever
// hears about.
func (p *poller) poll(ctx context.Context) ([]logRow, error) {
	now := p.now()

	p.mu.Lock()
	since := p.watermark.Add(-p.overlap)
	if p.watermark.IsZero() {
		// Cold start. One overlap window back and no further: a fresh install
		// must not replay yesterday's denials as though they were happening
		// now, which would page somebody about an event they already handled.
		since = now.Add(-p.overlap)
	}
	p.mu.Unlock()

	var (
		rows    []logRow
		firstEr error
	)
	for _, topic := range topicsPolled {
		got, err := p.readTopic(ctx, topic, since, now)
		if err != nil {
			if firstEr == nil {
				firstEr = err
			}
			continue
		}
		rows = append(rows, got...)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastRunAt = now
	if firstEr != nil {
		p.lastErr = firstEr.Error()
		// Deliberately NOT advancing the watermark, and deliberately still
		// returning the rows that did arrive: a row read once is a row worth
		// emitting, and the next window will cover the topic that failed.
		return p.filterLocked(rows, now), firstEr
	}
	p.lastErr = ""
	p.watermark = now
	return p.filterLocked(rows, now), nil
}

// readTopic pages through one topic's window.
func (p *poller) readTopic(ctx context.Context, topic string, since, until time.Time) ([]logRow, error) {
	var out []logRow
	for page := 1; page <= p.maxPages; page++ {
		hits, err := p.fetch(ctx, topic, since, until, page)
		if err != nil {
			return nil, err
		}
		for _, h := range hits {
			out = append(out, logRow{hit: h, topic: topic})
		}
		// There are no pagination fields in the response -- no total, no
		// cursor, no next -- so a short page is the only end-of-data signal
		// there is.
		if len(hits) < logPageSize {
			break
		}
	}
	return out, nil
}

// filterLocked drops rows already emitted and records the rest.
func (p *poller) filterLocked(rows []logRow, now time.Time) []logRow {
	out := rows[:0:0]
	for _, r := range rows {
		id := r.hit.ID
		if id == "" {
			// A row with no id cannot be de-duplicated, so emitting it would
			// re-emit it on every overlapping window until it aged out.
			// Counted rather than emitted.
			p.unknownKeys["<row-with-no-id>"]++
			continue
		}
		if _, ok := p.seen[id]; ok {
			continue
		}
		p.seen[id] = now
		p.rowsSeen++
		out = append(out, r)
	}
	p.evictLocked(now)

	// Oldest first, so a burst of denials reaches the rule engine in the order
	// they happened rather than in whatever order the console paged them.
	sort.SliceStable(out, func(i, j int) bool {
		ti, oki := out[i].hit.at()
		tj, okj := out[j].hit.at()
		if !oki || !okj {
			return false
		}
		return ti.Before(tj)
	})
	return out
}

// evictLocked forgets row ids that can no longer appear in a window.
func (p *poller) evictLocked(now time.Time) {
	// Twice the overlap: a row cannot be returned by a window that starts
	// after it, so anything older than the furthest reach of the next window
	// is safe to forget.
	cutoff := now.Add(-2 * p.overlap)
	for id, at := range p.seen {
		if at.Before(cutoff) {
			delete(p.seen, id)
		}
	}
	if len(p.seen) <= maxSeenRows {
		return
	}
	// Still oversized: drop the oldest. Re-emitting an old row is a
	// duplicated alert, which is bad; exhausting memory is worse, and the
	// bound is generous enough that reaching it means something unusual.
	type aged struct {
		id string
		at time.Time
	}
	all := make([]aged, 0, len(p.seen))
	for id, at := range p.seen {
		all = append(all, aged{id, at})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
	for _, a := range all[:len(all)-maxSeenRows] {
		delete(p.seen, a.id)
	}
}

// isDenial classifies a row as a refused credential.
func isDenial(h logHit) bool {
	hay := strings.ToLower(h.Source.Event.LogKey + " " + h.Source.Event.Type)
	for _, m := range denialMarkers {
		if strings.Contains(hay, m) {
			return true
		}
	}
	return false
}

// noteUnknown records a log key this source had no rule for.
func (p *poller) noteUnknown(topic, key string) {
	if key == "" {
		key = "<no-log-key>"
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.unknownKeys) < 512 {
		p.unknownKeys[topic+"/"+key]++
	}
}

// stats is the poller's contribution to Health.
func (p *poller) stats() (rows int64, lastRun time.Time, lastErr string, unknown map[string]int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	unknown = make(map[string]int64, len(p.unknownKeys))
	for k, v := range p.unknownKeys {
		unknown[k] = v
	}
	return p.rowsSeen, p.lastRunAt, p.lastErr, unknown
}
