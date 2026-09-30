package setup

import (
	"strings"
	"testing"
)

// THE SITE WHERE NO ACKNOWLEDGEMENT BUTTON HAD EVER WORKED.
//
// web.ack_base_url was http://<public name>, the ack-only listener was on
// 50001, and every link went to port 80. Each half looked right, and this
// step fell through to "public over plain http", optional -- so Setup read as
// all but done. The channel test found it, as a phone that could not connect.
func TestAnAckLinkWithNoPortIsATodoThatSaysTheFix(t *testing.T) {
	in := workable()
	in.Listen = "127.0.0.1:8322"
	in.AckBaseURL = "http://fpcbr.xtremission.com"
	in.PublicAckURL = true
	in.AckScoped = true
	in.AckListen = "0.0.0.0:50001"

	got := step(t, in, "acknowledgement")
	if got.Status != Todo {
		t.Fatalf("status = %q (%s), want todo: every acknowledgement link goes to a "+
			"port nothing answers on", got.Status, got.State)
	}
	if !strings.Contains(got.State, "http://fpcbr.xtremission.com:50001") {
		t.Errorf("state = %q, want it to name the address to set, port and all", got.State)
	}
}

// What it must and must not say, decided without a step around it.
func TestAckPortProblem(t *testing.T) {
	for _, tc := range []struct {
		name, url, listen, ackListen string
		want                         string // "" = silent; else the fixed address
	}{
		{"the field case", "http://fpcbr.xtremission.com", "127.0.0.1:8322", "0.0.0.0:50001",
			"http://fpcbr.xtremission.com:50001"},
		{"no ack listener: the main one answers", "http://192.168.1.50", "0.0.0.0:8322", "",
			"http://192.168.1.50:8322"},
		{"a path is kept", "http://nm.example.com/alarm", "127.0.0.1:8322", "0.0.0.0:50001",
			"http://nm.example.com:50001/alarm"},
		{"IPv6 keeps its brackets", "http://[fd00::5]", "0.0.0.0:8322", "[::]:50001",
			"http://[fd00::5]:50001"},
		{"https with no port is a TLS proxy on 443", "https://alerts.example.com",
			"127.0.0.1:8322", "0.0.0.0:50001", ""},
		{"an explicit port may be a NAT remap", "http://nm.example.com:8080",
			"127.0.0.1:8322", "0.0.0.0:50001", ""},
		{"the ack listener is on 80", "http://nm.example.com", "127.0.0.1:8322", "0.0.0.0:80", ""},
		{"the main listener on 80 answers too", "http://nm.example.com", "0.0.0.0:80",
			"0.0.0.0:50001", ""},
		{"loopback-only is reported by its own case", "http://192.168.1.50",
			"127.0.0.1:8322", "", ""},
		{"not set", "", "0.0.0.0:8322", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := AckPortProblem(tc.url, tc.listen, tc.ackListen)
			if tc.want == "" {
				if got != "" {
					t.Errorf("said %q; want nothing", got)
				}
				return
			}
			if !strings.Contains(got, "set web.ack_base_url to "+tc.want) &&
				!strings.Contains(got, "Set web.ack_base_url to "+tc.want+" ") {
				t.Errorf("said %q; want it to give %s", got, tc.want)
			}
		})
	}
}
