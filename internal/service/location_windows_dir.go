//go:build windows

package service

// suggestedDir names where a Windows service binary belongs.
func suggestedDir() string { return `C:\Program Files\NotifyMatrix\` }
