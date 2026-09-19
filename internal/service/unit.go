package service

import (
	"fmt"
	"strings"
	"text/template"
)

// UnitPath is where the generated unit is installed.
const UnitPath = "/etc/systemd/system/" + Name + ".service"

// unitTemplate is built on any platform so it can be rendered and tested from
// a developer machine, and shown by the CLI before anything is written.
//
// Every non-obvious directive below carries its reason. The two that decide
// whether this product works are StartLimitIntervalSec and Restart.
var unitTemplate = template.Must(template.New("unit").Parse(
	`[Unit]
Description={{.Description}}
Documentation=https://github.com/suburbazine/Unifi-Notification-Matrix
After=network-online.target
Wants=network-online.target

# Never give up restarting.
#
# systemd's DEFAULT is to stop trying after 5 starts in 10 seconds, which is
# the wrong polarity for this product: a daemon that has crash-looped five
# times still needs to be trying at 4am. 0 disables the rate limiter entirely,
# so Restart=always genuinely means always. A slow restart loop is survivable;
# a service that quietly gave up at 02:00 is not.
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart={{.ExePath}} run --data-dir {{.DataDir}}
{{- if .User}}
User={{.User}}
{{- end}}

{{- if .Appliance}}

# RUNNING ON THE DEVICE IT WATCHES. See internal/service/unifios.go.
#
# The state directory is /data, the partition UniFi OS documents as persistent.
# StateDirectory cannot say that -- it is always relative to /var/lib -- so the
# hole in ProtectSystem=strict is punched directly instead. The daemon creates
# the directory itself at 0700 on first run.
ReadWritePaths={{.DataDir}}

# A memory fence, because this box also routes.
#
# Not a tuning knob: it is a backstop so a fault in this process cannot take
# capacity from the routing and inspection paths on the same hardware. The
# steady state is far below the soft limit. Being throttled is survivable;
# being killed stops the alerting, which is why the hard limit is well clear of
# the soft one.
MemoryHigh={{.MemoryHighMB}}M
MemoryMax={{.MemoryMaxMB}}M

# No SupplementaryGroups=tss here. There is no TPM on these devices, and
# systemd FAILS a unit whose SupplementaryGroups names a group that does not
# exist -- so the line that protects the secret store elsewhere would stop the
# daemon from starting at all here.
{{- else}}

# TPM access for the secret store.
#
# The daemon runs unprivileged, so it cannot use systemd-creds' host key --
# that is root-only. --with-key=tpm2 needs /dev/tpmrm0, which is typically
# root:tss 0660. Without this line a machine WITH a TPM silently falls to the
# key-file tier, which is not machine-bound. Harmless on a machine without one.
SupplementaryGroups=tss

# Creates and owns {{.DataDir}} as the service user.
StateDirectory={{.StateDirectory}}
StateDirectoryMode=0700
{{- end}}

Restart=always
RestartSec=5
TimeoutStopSec=30

# Administrator-provisioned credentials. systemd decrypts these as ROOT at
# start, before dropping to {{if .User}}{{.User}}{{else}}the service user{{end}}, so a credential seeded this
# way gets a binding the daemon could never have produced for itself -- it
# cannot write a host-key credential, only read one. Uncomment and seed with:
#
#   systemd-creds encrypt --name=unifi-api-key key.txt \
#       /etc/{{.Name}}/unifi-api-key.cred
#
# A credential provisioned this way cannot be rotated from the web UI; that is
# the trade. See ARCHITECTURE.md §9a.
#
#LoadCredentialEncrypted=unifi-api-key:/etc/{{.Name}}/unifi-api-key.cred

# Hardening. This process holds console API keys and reaches the network; it
# has no business anywhere else on the filesystem.
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=false
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

[Install]
WantedBy=multi-user.target
`))

// unitData is the template's input.
type unitData struct {
	Name           string
	Description    string
	ExePath        string
	DataDir        string
	StateDirectory string
	User           string

	Appliance    bool
	MemoryHighMB int
	MemoryMaxMB  int
}

// RenderUnit produces the systemd unit for these options.
//
// PrivateDevices is explicitly FALSE, which is the one hardening directive
// turned off on purpose: it would hide /dev/tpmrm0 and silently demote the
// secret store to the key-file tier on every machine with a TPM. A hardening
// option that quietly weakens the thing being hardened is worse than not
// setting it.
func RenderUnit(o InstallOptions) (string, error) {
	if o.ExePath == "" {
		return "", fmt.Errorf("service: no executable path for the unit")
	}
	if o.DataDir == "" {
		return "", fmt.Errorf("service: no data directory for the unit")
	}
	var stateDir string
	if o.Appliance {
		// ReadWritePaths takes an absolute path and needs no /var/lib
		// relationship, but it must still be absolute and free of traversal:
		// it is the one hole in an otherwise read-only filesystem.
		if !strings.HasPrefix(o.DataDir, "/") || strings.Contains(o.DataDir, "..") {
			return "", fmt.Errorf(
				"service: --data-dir must be an absolute path with no \"..\" "+
					"for the appliance unit (got %q)", o.DataDir)
		}
	} else {
		// ProtectSystem=strict makes everything read-only except what
		// StateDirectory grants, and StateDirectory is relative to /var/lib. A
		// data directory outside it would leave the daemon unable to write its
		// own store -- which fails at the first incident, not at start.
		var ok bool
		stateDir, ok = strings.CutPrefix(o.DataDir, "/var/lib/")
		if !ok || stateDir == "" || strings.Contains(stateDir, "..") {
			return "", fmt.Errorf(
				"service: --data-dir must be under /var/lib for the systemd unit "+
					"(got %q); ProtectSystem=strict makes the rest of the "+
					"filesystem read-only, so the daemon could not write its "+
					"incident store there", o.DataDir)
		}
	}

	var sb strings.Builder
	err := unitTemplate.Execute(&sb, unitData{
		Name:           Name,
		Description:    Description,
		ExePath:        o.ExePath,
		DataDir:        o.DataDir,
		StateDirectory: stateDir,
		User:           o.User,
		Appliance:      o.Appliance,
		MemoryHighMB:   MemoryHighMB,
		MemoryMaxMB:    MemoryMaxMB,
	})
	if err != nil {
		return "", fmt.Errorf("service: rendering unit: %w", err)
	}
	return sb.String(), nil
}

// DefaultDataDir is where the service keeps its state on each platform.
func DefaultDataDir() string { return defaultDataDir() }
