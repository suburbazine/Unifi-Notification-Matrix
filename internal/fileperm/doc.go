// Package fileperm restricts who can read a file that holds secrets.
//
// It exists as its own package because chmod is a no-op on Windows ACLs, and
// every place this product writes credentials needs the same real answer: the
// configuration, the setup token, and the audit record. Keeping one
// implementation means a new file cannot quietly get the weaker treatment,
// which is exactly what happened when only the setup token was hardened and
// the configuration -- which holds far more -- was left inheriting read access
// for every local account.
package fileperm
