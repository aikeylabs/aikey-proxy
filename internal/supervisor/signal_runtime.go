package supervisor

import (
	"fmt"
	"sync"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

// runtimeRefreshTokenSource prevents the process-owned signal reporter from
// retaining a generation-owned vault Reader. The active vault location is
// swapped at the same activation boundary as the reporter configuration; a
// credential rebuild opens it only long enough to read the refresh token.
type runtimeRefreshTokenSource struct {
	mu       sync.RWMutex
	path     string
	password string
}

func newRuntimeRefreshTokenSource(path, password string) *runtimeRefreshTokenSource {
	return &runtimeRefreshTokenSource{path: path, password: password}
}

func (s *runtimeRefreshTokenSource) update(path, password string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.path = path
	s.password = password
	s.mu.Unlock()
}

func (s *runtimeRefreshTokenSource) GetPlatformRefreshToken() (string, error) {
	if s == nil {
		return "", fmt.Errorf("signal refresh-token source is unavailable")
	}
	s.mu.RLock()
	path, password := s.path, s.password
	s.mu.RUnlock()
	if path == "" {
		return "", fmt.Errorf("signal refresh-token vault path is empty")
	}
	r, err := vault.Open(path, password)
	if err != nil {
		return "", fmt.Errorf("open signal refresh-token vault: %w", err)
	}
	defer r.Close()
	return r.GetPlatformRefreshToken()
}
