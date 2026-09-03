package mcp

import (
	"io"
	"log/slog"
)

// discardLogger keeps fence output readable. The isolation shell logs at WARN
// on every shed request, and 1.F3 sheds deliberately — without this, a passing
// run prints hundreds of lines and the one that matters is lost.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
