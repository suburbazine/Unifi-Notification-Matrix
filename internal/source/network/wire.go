package network

import (
	"encoding/json"
	"strings"
)

// page is the Network Integration API's list envelope.
//
// Every field is tolerant. Unlike Protect and Access, NO prior in-house client
// for this API exists to copy shapes from, and the pagination fields are taken
// from documentation rather than from a console anybody here has queried. A
// strict decode that is wrong about one of them does not lose that field -- it
// loses the whole device list, and a site with no devices reads as a site
// where nothing is wrong.
type page struct {
	Offset     json.Number     `json:"offset"`
	Limit      json.Number     `json:"limit"`
	Count      json.Number     `json:"count"`
	TotalCount json.Number     `json:"totalCount"`
	Data       json.RawMessage `json:"data"`
}

// decodePage reads a list response in either shape it might arrive in.
//
// The documented shape wraps the array in an object with pagination fields.
// A bare array is accepted too, because that is what the sibling APIs on this
// same console do and being wrong about which one this is should cost nothing.
func decodePage(raw []byte) (items []json.RawMessage, total int, err error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, 0, nil
	}

	if trimmed[0] == '[' {
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			return nil, 0, err
		}
		return arr, len(arr), nil
	}

	var p page
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, 0, err
	}
	var arr []json.RawMessage
	if strings.TrimSpace(string(p.Data)) != "" && strings.TrimSpace(string(p.Data)) != "null" {
		if err := json.Unmarshal(p.Data, &arr); err != nil {
			return nil, 0, err
		}
	}
	total = len(arr)
	if n, err := p.TotalCount.Int64(); err == nil && int(n) > total {
		total = int(n)
	}
	return arr, total, nil
}

// site is one Network site.
type site struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	InternalReference string `json:"internalReference"`
}

func (s site) label() string {
	if n := strings.TrimSpace(s.Name); n != "" {
		return n
	}
	if r := strings.TrimSpace(s.InternalReference); r != "" {
		return r
	}
	return s.ID
}

// device is one Network device.
type device struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Model string `json:"model"`

	// MACAddress and IPAddress are read under both spellings seen in the
	// documentation, because this API has not been observed here.
	MACAddress string `json:"macAddress"`
	MAC        string `json:"mac"`
	IPAddress  string `json:"ipAddress"`

	// State is the connection enum. Raw, because the vocabulary is not
	// established -- see classifyState.
	State json.RawMessage `json:"state"`
}

func (d device) mac() string {
	if m := strings.TrimSpace(d.MACAddress); m != "" {
		return m
	}
	return strings.TrimSpace(d.MAC)
}

func (d device) label() string {
	if n := strings.TrimSpace(d.Name); n != "" {
		return n
	}
	if m := d.mac(); m != "" {
		return m
	}
	return d.ID
}

// State is what this source believes about a device's reachability.
type State string

const (
	// StateUnknown is a state string this build has no rule for, or none at
	// all. A real value, never collapsed into online -- reporting a switch as
	// healthy because a field was unreadable is reporting health on no
	// evidence.
	StateUnknown State = ""

	StateOnline  State = "online"
	StateOffline State = "offline"

	// StateTransitional is a device mid-adoption, updating or provisioning.
	// Not online, and deliberately not an outage: a switch being upgraded at
	// 3am is doing what it was told to do.
	StateTransitional State = "transitional"
)

// onlineStates, offlineStates and transitionalStates are the vocabulary this
// build recognises.
//
// TAKEN FROM DOCUMENTATION, NOT FROM A CONSOLE. No prior in-house client for
// this API exists, so unlike Protect's event table these lists have never been
// checked against hardware. That is why anything absent from all three is
// StateUnknown, counted by name in Health, and NEVER alarmed on.
//
// The trade is real and it goes the uncomfortable way: if a future firmware
// invents a state that means "down", this build will not alarm on it and an
// outage will pass unreported. The alternative -- treating every unrecognised
// state as an outage -- pages the operator every time Ubiquiti adds a value,
// and an alarm product that cries wolf is switched off, which costs more than
// it saves. So the unknown state is made VISIBLE instead: it appears in Health
// and in `notifymatrix probe`, which is how the list gets corrected.
var (
	onlineStates = map[string]State{
		"ONLINE":    StateOnline,
		"CONNECTED": StateOnline,
	}
	offlineStates = map[string]State{
		"OFFLINE":                StateOffline,
		"DISCONNECTED":           StateOffline,
		"CONNECTION_INTERRUPTED": StateOffline,
		"ISOLATED":               StateOffline,
		"HEARTBEAT_MISSED":       StateOffline,
	}
	transitionalStates = map[string]State{
		"PENDING_ADOPTION": StateTransitional,
		"ADOPTING":         StateTransitional,
		"ADOPTION_FAILED":  StateTransitional,
		"PROVISIONING":     StateTransitional,
		"UPDATING":         StateTransitional,
		"UPGRADING":        StateTransitional,
		"GETTING_READY":    StateTransitional,
		"RESTARTING":       StateTransitional,
		"DELETING":         StateTransitional,
		"MANAGED_BY_OTHER": StateTransitional,
	}
)

// classifyState maps a console state string, and reports the raw value so an
// unrecognised one can be counted by name.
func classifyState(raw json.RawMessage) (State, string) {
	v := strings.ToUpper(strings.TrimSpace(scalarString(raw)))
	if v == "" {
		return StateUnknown, ""
	}
	if s, ok := onlineStates[v]; ok {
		return s, v
	}
	if s, ok := offlineStates[v]; ok {
		return s, v
	}
	if s, ok := transitionalStates[v]; ok {
		return s, v
	}
	return StateUnknown, v
}

// scalarString reads a JSON scalar as text regardless of which scalar it is.
//
// `state` is documented as a string, but this API has not been observed here
// and a numeric enum would otherwise silently read as absent -- which this
// package treats as "unknown", so the failure would be quiet rather than loud.
func scalarString(raw json.RawMessage) string {
	t := strings.TrimSpace(string(raw))
	if t == "" || t == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		return n.String()
	}
	return ""
}
