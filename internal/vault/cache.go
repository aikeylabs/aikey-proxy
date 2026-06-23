package vault

import "sync"

// cache provides thread-safe in-memory caching of decrypted secrets.
// Keys are cached for the lifetime of the daemon process.
type cache struct {
	secrets map[string]string
	mu      sync.RWMutex
}

func newCache() *cache {
	return &cache{
		secrets: make(map[string]string),
	}
}

func (c *cache) get(alias string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.secrets[alias]
	return v, ok
}

func (c *cache) set(alias, secret string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.secrets[alias] = secret
}

// clear wipes all cached secrets.
func (c *cache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.secrets {
		c.secrets[k] = ""
		delete(c.secrets, k)
	}
}
