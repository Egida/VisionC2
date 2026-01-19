// debug.go
package main

import (
	"fmt"
	"time"
)

// ==================== GLOBAL DEBUG LOGGING ====================
// Set to true to enable debug logging, false to disable
var DEBUG_ENABLED = true

// Debug logging
func debugLog(format string, args ...interface{}) {
	if DEBUG_ENABLED {
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		message := fmt.Sprintf(format, args...)
		fmt.Printf("[DEBUG %s] %s\n", timestamp, message)
	}
}
