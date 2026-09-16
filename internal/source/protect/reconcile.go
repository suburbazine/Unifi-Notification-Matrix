package protect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// StateReader re-reads current device state over REST.
//
// This is an interface because the reconciliation sweep is the part of this
// source that MUST be exercised by tests: neither socket accepts a resume
// cursor, so everything that happened during a disconnect is unrecoverable
// from the stream and the sweep is the only thing standing between a console
// reboot and a silently missed alarm. A sweep that is only ever run against
// real hardware is a sweep nobody has actually verified.
type StateReader interface {
	// Devices returns every camera, sensor and NVR with its current state.
	//
	// A partial result WITH an error is legitimate and expected: see
	// restReader.Devices for why partial is safe on this particular read.
	Devices(ctx context.Context) ([]DeviceState, error)
}

const (
	pathCameras = "/proxy/protect/integration/v1/cameras"
	pathSensors = "/proxy/protect/integration/v1/sensors"
	pathNVRs    = "/proxy/protect/integration/v1/nvrs"
)

// maxBodyBytes caps a collection response. Generous, because these are
// whole-site arrays.
const maxBodyBytes = 8 << 20

// ErrTruncated means the console sent more than we are willing to read.
//
// Detected rather than returned: reading exactly the cap cannot distinguish a
// complete body from a longer one, so we read one byte past it and fail. A
// silently truncated array decodes as a shorter site and every camera past the
// cut looks like it does not exist.
var ErrTruncated = errors.New("protect: response body exceeded the size cap")

type restReader struct {
	base    *url.URL
	key     secret.Secret
	hc      *http.Client
	pace    func(context.Context) error
	maxBody int64
}

// Devices reads the three collection endpoints the public API actually
// exposes.
//
// A failure on one endpoint returns the others plus the error. Partial is safe
// HERE and only here: every caller acts on records that are present and never
// interprets absence, so a missing camera list can cost us a detection we
// retry for, but can never manufacture a false clear. The error still reaches
// Health so the operator sees a sweep that is not completing.
func (r *restReader) Devices(ctx context.Context) ([]DeviceState, error) {
	type endpoint struct {
		path string
		kind string
	}
	// /v1/nvrs carries no state field at all -- no disk array, no utilisation,
	// no health, no power. It is read for identity (the MAC->id map the Alarm
	// Manager webhook needs) and contributes no health claim whatsoever.
	endpoints := []endpoint{
		{pathCameras, "camera"},
		{pathSensors, "sensor"},
		{pathNVRs, "nvr"},
	}

	var (
		out  []DeviceState
		errs []error
		okN  int
	)
	for _, ep := range endpoints {
		devices, err := r.collection(ctx, ep.path, ep.kind)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		okN++
		out = append(out, devices...)
	}
	if okN == 0 {
		return nil, errors.Join(errs...)
	}
	return out, errors.Join(errs...)
}

func (r *restReader) collection(ctx context.Context, path, kind string) ([]DeviceState, error) {
	if r.pace != nil {
		// One pacer per console, shared with every other caller. The sweep is
		// bursty by nature -- three collection reads the instant a socket
		// reconnects -- and a console reboot reconnects everything at once.
		if err := r.pace(ctx); err != nil {
			return nil, err
		}
	}

	u := *r.base
	u.Path = path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("protect sweep %s: %w", redactURL(&u), err)
	}
	setAPIKey(req.Header, r.key)
	req.Header.Set("Accept", "application/json")

	resp, err := r.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("protect sweep %s: %w", redactURL(&u), err)
	}
	defer resp.Body.Close()

	limit := r.maxBody
	if limit <= 0 {
		limit = maxBodyBytes
	}
	// One byte past the cap, deliberately. Reading exactly the cap cannot
	// distinguish a complete body from a longer one.
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("protect sweep %s: reading body: %w", redactURL(&u), err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("protect sweep %s: %w", redactURL(&u), ErrTruncated)
	}

	if resp.StatusCode != http.StatusOK {
		// The body of a credential-bearing endpoint never reaches an error
		// string: it can carry stream and snapshot URLs, and those path tokens
		// are all anyone on the network needs to watch a camera. Status and
		// size only.
		return nil, fmt.Errorf("protect sweep %s: status %d (%d bytes)", redactURL(&u), resp.StatusCode, len(body))
	}

	// HTTP 200 is not success on this hardware. A 200 carrying an object where
	// the contract says array is a failure reported in the payload, and
	// treating it as an empty site would report every camera as unknown.
	if t := bytes.TrimLeft(body, " \t\r\n"); len(t) == 0 || t[0] != '[' {
		return nil, fmt.Errorf("protect sweep %s: 200 with a non-array body (%d bytes)", redactURL(&u), len(body))
	}

	var records []json.RawMessage
	if err := json.Unmarshal(body, &records); err != nil {
		return nil, fmt.Errorf("protect sweep %s: decoding array: %w", redactURL(&u), err)
	}

	out := make([]DeviceState, 0, len(records))
	for _, rec := range records {
		// Per record, so that one device with an unexpected field costs that
		// device and not the whole site.
		var d struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			MAC   string `json:"mac"`
			State string `json:"state"`
		}
		if err := json.Unmarshal(rec, &d); err != nil {
			continue
		}
		if d.ID == "" {
			continue
		}
		out = append(out, DeviceState{
			ID:    d.ID,
			Name:  d.Name,
			Kind:  kind,
			MAC:   d.MAC,
			State: d.State,
		})
	}
	return out, nil
}

// setAPIKey writes the header with the exact casing working clients use.
//
// Assigned into the map rather than through Header.Set, which canonicalises to
// "X-Api-Key". Header names are case-insensitive by specification and this
// console is behind a reverse proxy nobody here controls, so the casing that
// is known to work in the field is the casing that gets sent. The key travels
// in a header and NEVER in a URL.
func setAPIKey(h http.Header, key secret.Secret) {
	h["X-API-KEY"] = []string{key.Reveal()}
}

// newRESTReader builds the default sweep source.
func newRESTReader(base *url.URL, key secret.Secret, hc *http.Client, pace func(context.Context) error) *restReader {
	httpBase := *base
	switch httpBase.Scheme {
	case "wss":
		httpBase.Scheme = "https"
	case "ws":
		httpBase.Scheme = "http"
	}
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &restReader{base: &httpBase, key: key, hc: hc, pace: pace, maxBody: maxBodyBytes}
}
