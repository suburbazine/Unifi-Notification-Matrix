//go:build windows

package update

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CanVerifyPublisher reports whether this platform can pin a replacement to
// the publisher of the binary already installed.
func CanVerifyPublisher() bool { return true }

// Only the two calls x/sys/windows does not already wrap are bound by hand.
// Everything else goes through the wrapped functions, which return TYPED
// pointers -- the hand-rolled version of this converted a uintptr straight
// back into a struct pointer, which go vet rejects and is right to.
var (
	wintrust           = windows.NewLazySystemDLL("wintrust.dll")
	crypt32            = windows.NewLazySystemDLL("crypt32.dll")
	procWinVerifyTrust = wintrust.NewProc("WinVerifyTrust")
	procCryptMsgGetPar = crypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose  = crypt32.NewProc("CryptMsgClose")
)

// WINTRUST_ACTION_GENERIC_VERIFY_V2: the Authenticode policy.
var actionGenericVerifyV2 = windows.GUID{
	Data1: 0x00aac56b,
	Data2: 0xcd44,
	Data3: 0x11d0,
	Data4: [8]byte{0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee},
}

type wintrustFileInfo struct {
	cbStruct       uint32
	pcwszFilePath  *uint16
	hFile          windows.Handle
	pgKnownSubject *windows.GUID
}

type wintrustData struct {
	cbStruct            uint32
	pPolicyCallbackData uintptr
	pSIPClientData      uintptr
	dwUIChoice          uint32
	fdwRevocationChecks uint32
	dwUnionChoice       uint32
	pFile               *wintrustFileInfo
	dwStateAction       uint32
	hWVTStateData       windows.Handle
	pwszURLReference    *uint16
	dwProvFlags         uint32
	dwUIContext         uint32
	pSignatureSettings  uintptr
}

const (
	wtdUINone                          = 2
	wtdRevokeWholeChain                = 1
	wtdChoiceFile                      = 1
	wtdStateActionVerify               = 1
	wtdStateActionClose                = 2
	wtdRevocationCheckChainExcludeRoot = 0x00000040
)

// verifyTrust asks Windows whether the file carries a valid, trusted,
// unrevoked Authenticode signature.
//
// The whole chain: the signature matches the bytes, the certificate chains to
// a root this machine trusts, and it has not been revoked. A file that fails
// is not installed.
func verifyTrust(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	fi := wintrustFileInfo{
		cbStruct:      uint32(unsafe.Sizeof(wintrustFileInfo{})),
		pcwszFilePath: p,
	}
	data := wintrustData{
		cbStruct:            uint32(unsafe.Sizeof(wintrustData{})),
		dwUIChoice:          wtdUINone,
		fdwRevocationChecks: wtdRevokeWholeChain,
		dwUnionChoice:       wtdChoiceFile,
		pFile:               &fi,
		dwStateAction:       wtdStateActionVerify,
		// Revocation IS checked. Excluding the root is the standard middle
		// ground: a machine that cannot reach the CA's responder must not
		// therefore install an unverified binary, nor refuse every update for
		// ever. The leaf and intermediates are still checked.
		dwProvFlags: wtdRevocationCheckChainExcludeRoot,
	}

	rc, _, _ := procWinVerifyTrust.Call(0,
		uintptr(unsafe.Pointer(&actionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&data)))

	// Close the state whatever the verdict, or every check leaks a handle.
	data.dwStateAction = wtdStateActionClose
	_, _, _ = procWinVerifyTrust.Call(0,
		uintptr(unsafe.Pointer(&actionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&data)))

	if rc != 0 {
		return fmt.Errorf("its Authenticode signature did not verify (0x%08x)", uint32(rc))
	}
	return nil
}

const (
	certQueryObjectFile                  = 1
	certQueryContentFlagPKCS7SignedEmbed = 1 << 10
	certQueryFormatFlagBinary            = 1 << 1
	cmsgSignerInfoParam                  = 6
	certFindSubjectCert                  = 11 << 16
	certNameSimpleDisplayType            = 4
)

// signerInfoHeader is the front of CMSG_SIGNER_INFO: the issuer and serial
// number, which together name the signing certificate inside the file's own
// certificate store.
type signerInfoHeader struct {
	dwVersion    uint32
	_            uint32 // alignment before the first pointer-bearing blob
	Issuer       windows.CertNameBlob
	SerialNumber windows.CryptIntegerBlob
}

// signerName returns the display name of the certificate that signed the file
// -- "Xtremission LLC".
//
// The simple display name rather than the full X.500 string: it is what
// Windows shows in the file's properties, so an operator comparing this
// against what they see is comparing the same thing.
func signerName(path string) (string, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}

	var store, msg windows.Handle
	var encoding, contentType, formatType uint32
	err = windows.CryptQueryObject(
		certQueryObjectFile,
		unsafe.Pointer(p),
		certQueryContentFlagPKCS7SignedEmbed,
		certQueryFormatFlagBinary,
		0,
		&encoding, &contentType, &formatType,
		&store, &msg, nil,
	)
	if err != nil {
		return "", fmt.Errorf("it carries no Authenticode signature (%w)", err)
	}
	defer windows.CertCloseStore(store, 0)
	defer procCryptMsgClose.Call(uintptr(msg))

	// Twice: once for the size, once for the bytes.
	var size uint32
	if rc, _, e := procCryptMsgGetPar.Call(uintptr(msg), cmsgSignerInfoParam, 0, 0,
		uintptr(unsafe.Pointer(&size))); rc == 0 {
		return "", fmt.Errorf("its signature could not be read (%v)", e)
	}
	if size < uint32(unsafe.Sizeof(signerInfoHeader{})) {
		return "", fmt.Errorf("its signature is malformed")
	}
	buf := make([]byte, size)
	if rc, _, e := procCryptMsgGetPar.Call(uintptr(msg), cmsgSignerInfoParam, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size))); rc == 0 {
		return "", fmt.Errorf("its signature could not be read (%v)", e)
	}

	si := (*signerInfoHeader)(unsafe.Pointer(&buf[0]))
	find := windows.CertInfo{Issuer: si.Issuer, SerialNumber: si.SerialNumber}

	ctx, err := windows.CertFindCertificateInStore(
		store,
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
		0,
		certFindSubjectCert,
		unsafe.Pointer(&find),
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("its signing certificate could not be found (%w)", err)
	}
	defer windows.CertFreeCertificateContext(ctx)

	n := windows.CertGetNameString(ctx, certNameSimpleDisplayType, 0, nil, nil, 0)
	if n <= 1 {
		return "", fmt.Errorf("its signing certificate has no subject name")
	}
	out := make([]uint16, n)
	windows.CertGetNameString(ctx, certNameSimpleDisplayType, 0, nil, &out[0], n)
	return strings.TrimSpace(windows.UTF16ToString(out)), nil
}

// VerifyPublisher refuses a replacement that is not signed by whoever signed
// the binary currently installed.
//
// Pinned to the RUNNING binary rather than to a certificate written in here.
// A hardcoded subject breaks when the certificate is reissued under a slightly
// different name; a hardcoded thumbprint breaks on every renewal -- and a
// bricked updater on a security tool is how machines end up years behind.
// Comparing against what the operator already chose to run survives renewals
// and stops dead the moment the publisher changes, which is the event actually
// worth stopping for.
func VerifyPublisher(candidate, installed string) error {
	if err := verifyTrust(candidate); err != nil {
		return fmt.Errorf("update: the downloaded file was rejected: %s -- nothing "+
			"was installed", err)
	}

	got, err := signerName(candidate)
	if err != nil {
		return fmt.Errorf("update: the downloaded file was rejected: %s -- nothing "+
			"was installed", err)
	}

	want, err := signerName(installed)
	if err != nil {
		if _, statErr := os.Stat(installed); statErr != nil {
			return fmt.Errorf("update: cannot read the installed binary at %s: %w",
				installed, statErr)
		}
		// The running binary is unsigned: a local build, or one somebody
		// compiled themselves. There is no publisher to pin to, so there is no
		// check to make -- and installing anyway while calling it verified
		// would be the lie this whole package exists to avoid.
		return fmt.Errorf("update: the binary now running is not signed, so there is "+
			"no publisher to check the download against (%s). Install it by hand, or "+
			"reinstall from a signed release first", err)
	}

	if !strings.EqualFold(got, want) {
		return fmt.Errorf("update: the downloaded file is signed by %q, but the binary "+
			"now running is signed by %q. That is not a certificate renewal, it is a "+
			"different publisher -- nothing was installed", got, want)
	}
	return nil
}

// SignerOf verifies a file's Authenticode signature and returns who signed it.
//
// Exported so the daemon can ask the same question about ITSELF at startup
// that the updater asks about a download. The two are the same question --
// "who signed this, and does the signature hold?" -- separated only by which
// file is being asked about.
func SignerOf(path string) (string, error) {
	if err := verifyTrust(path); err != nil {
		return "", err
	}
	return signerName(path)
}
