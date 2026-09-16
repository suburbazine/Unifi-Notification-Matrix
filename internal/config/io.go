package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/ack"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
	"sigs.k8s.io/yaml"
)

// FileName is the config inside the data directory.
const FileName = "config.yaml"

var (
	// ErrNotFound means there is no config yet — a fresh install, not a fault.
	ErrNotFound = errors.New("no configuration file yet")

	// ErrNewerSchema means the file was written by a newer build.
	ErrNewerSchema = errors.New("configuration was written by a newer version")

	// ErrForeignConfig means the file's secrets were protected on a different
	// machine and cannot be decrypted here.
	ErrForeignConfig = errors.New("configuration was written on a different machine")
)

// Path returns the config path inside a data directory.
func Path(dataDir string) string { return filepath.Join(dataDir, FileName) }

// Load reads and validates the config.
func Load(dataDir string) (*Config, error) {
	path := Path(dataDir)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w at %s", ErrNotFound, path)
	}
	if err != nil {
		return nil, fmt.Errorf("config: reading %s: %w", path, err)
	}

	// Version first, from a permissive decode. A newer file must be refused
	// with a clear message rather than failing on whatever unknown field the
	// strict decode happens to hit first -- "unknown field voice_provider" is
	// a much worse explanation than "this was written by a newer version".
	var probe struct {
		Version int         `json:"version"`
		Secrets SecretsMeta `json:"secrets"`
	}
	if err := yaml.Unmarshal(b, &probe); err != nil {
		return nil, fmt.Errorf("config: %s is not valid YAML: %w", path, err)
	}
	if probe.Version > SchemaVersion {
		return nil, fmt.Errorf("%w (file is version %d, this build understands %d); "+
			"upgrade notifymatrix rather than downgrading the file",
			ErrNewerSchema, probe.Version, SchemaVersion)
	}

	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		// THE FAILURE THIS BRANCH EXISTS FOR.
		//
		// secret.Secret decrypts inside UnmarshalJSON, so a config carried
		// from another machine fails HERE -- and without this check the
		// operator is told their file is malformed YAML. They then go looking
		// for a syntax error in a file that is perfectly well formed, while
		// the actual problem is that these secrets belong to another host.
		var ue *secret.UnprotectError
		if errors.As(err, &ue) {
			where := ""
			if !probe.Secrets.MatchesThisHost() {
				where = fmt.Sprintf(" (written on host %s, this is host %s)",
					probe.Secrets.HostFingerprint, HostFingerprint())
			}
			// %w on BOTH: callers branch on ErrForeignConfig, and keeping the
			// underlying UnprotectError reachable means a caller that wants the
			// mechanism name does not have to re-parse the message.
			return nil, fmt.Errorf("%w%s.\n\n%w\n\nThe rest of %s is intact; only "+
				"the credentials need re-entering.", ErrForeignConfig, where, ue, path)
		}
		return nil, fmt.Errorf("config: reading %s: %w", path, err)
	}

	cfg.applyDefaults()
	cfg.PlaintextFields = PlaintextSecrets(b)
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: %s is not usable: %w", path, err)
	}
	return &cfg, nil
}

// applyDefaults fills in what the operator left out.
func (c *Config) applyDefaults() {
	if c.Version == 0 {
		c.Version = SchemaVersion
	}
	if c.Web.Listen == "" {
		c.Web.Listen = "127.0.0.1:8322"
	}
	if c.Channels.Ntfy != nil && c.Channels.Ntfy.ServerURL == "" {
		c.Channels.Ntfy.ServerURL = "https://ntfy.sh"
	}
	if e := c.Channels.Email; e != nil {
		if e.TLS == "" {
			e.TLS = "auto"
		}
		if e.Port == 0 {
			switch e.TLS {
			case "implicit":
				e.Port = 465
			default:
				e.Port = 587
			}
		}
	}
}

// Save writes the config atomically.
//
// Atomic because the web UI rewrites this file while the daemon is running,
// and a torn write during a power cut would leave a site with no console, no
// channels and no way to know why. Write-then-rename means a reader sees
// either the old file or the new one.
func Save(dataDir string, cfg *Config) error {
	if cfg == nil {
		return errors.New("config: refusing to write a nil config")
	}
	if err := cfg.Validate(); err != nil {
		// Refusing to persist an invalid config is the point: the daemon
		// reloads from this file, and writing something it will refuse to load
		// turns a bad form submission into a service that cannot start.
		return fmt.Errorf("config: refusing to write an invalid configuration: %w", err)
	}

	cfg.Version = SchemaVersion
	// Minted on first save rather than at install, so a config hand-written
	// from scratch still gets one. Without a key no acknowledgement link can
	// be signed, and every alert would repeat until the web UI stopped it.
	if cfg.Web.AckKey.IsZero() {
		k, err := ack.NewSecret()
		if err != nil {
			return err
		}
		cfg.Web.AckKey = k
	}
	cfg.Secrets.HostFingerprint = HostFingerprint()
	if p, err := secret.SelectWriter(); err == nil {
		cfg.Secrets.Mechanism = p.Prefix()
	}

	b, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("config: encoding: %w", err)
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("config: creating %s: %w", dataDir, err)
	}
	path := Path(dataDir)

	// Same directory as the target, so the rename is on one filesystem and is
	// therefore atomic. A temp file in /tmp would make this a copy.
	tmp, err := os.CreateTemp(dataDir, ".config-*.yaml")
	if err != nil {
		return fmt.Errorf("config: creating a temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	// 0600 before any content is written: the file holds encrypted secrets,
	// and even encrypted they are nobody else's business. Chmod AFTER writing
	// would leave a window where they are readable.
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, os.ErrInvalid) {
		_ = tmp.Close()
		return fmt.Errorf("config: securing the temporary file: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: writing: %w", err)
	}
	// fsync before rename. Without it the rename can land while the contents
	// are still in the page cache, and a power cut leaves a correctly-named,
	// empty config -- which is worse than a torn one, because it looks valid.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: flushing: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("config: closing: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("config: replacing %s: %w", path, err)
	}
	return nil
}

// LoadOrCreate reads the config, writing a default one if none exists.
func LoadOrCreate(dataDir string) (*Config, error) {
	cfg, err := Load(dataDir)
	if err == nil {
		return cfg, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	def := Default()
	if err := Save(dataDir, &def); err != nil {
		return nil, err
	}
	return &def, nil
}
