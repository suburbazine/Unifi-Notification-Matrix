//go:build !windows

package service

// suggestedDir names where a Linux service binary belongs.
func suggestedDir() string { return "/usr/local/bin" }
