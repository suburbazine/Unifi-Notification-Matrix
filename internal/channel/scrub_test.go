package channel

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestScrubTransportErrorDropsTheURL(t *testing.T) {
	err := &url.Error{
		Op:  "Put",
		URL: "https://ntfy.sh/my-secret-topic",
		Err: errors.New("dial tcp 159.203.148.75:443: i/o timeout"),
	}
	got := ScrubTransportError(err).Error()
	if strings.Contains(got, "my-secret-topic") {
		t.Errorf("the topic survived scrubbing: %s", got)
	}
	if !strings.Contains(got, "i/o timeout") {
		t.Errorf("the cause was lost: %s", got)
	}
}

func TestScrubTransportErrorLeavesOtherErrorsAlone(t *testing.T) {
	err := errors.New("something else entirely")
	if got := ScrubTransportError(err); got != err {
		t.Errorf("a non-transport error was altered: %v", got)
	}
}
