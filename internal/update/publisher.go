package update

import "errors"

// ErrNoPublisherIdentity means this platform cannot establish who signed a
// file, as opposed to establishing that nobody did.
//
// The distinction is the whole reason this error exists. "Unsigned" is a
// finding worth raising; "I cannot tell" is a limitation worth stating once
// and then staying quiet about, and a caller that conflates them either cries
// wolf on every Linux start or says nothing on a Windows machine running an
// unsigned binary.
var ErrNoPublisherIdentity = errors.New("update: this platform cannot identify who signed a file")
