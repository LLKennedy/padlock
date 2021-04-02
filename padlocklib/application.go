package padlocklib

import (
	"fmt"
	"sync"

	"github.com/miekg/pkcs11/p11"
)

// Application is a Padlock application, maintaining module and session state for an entire multi-threaded application.
type Application struct {
	modulesMx *sync.RWMutex
	modules   map[string]p11.Module
}

// NewApplication creates a new Application
func NewApplication() *Application {
	return &Application{
		modulesMx: new(sync.RWMutex),
		modules:   make(map[string]p11.Module, 1),
	}
}

// Connect connects to an HSM
func (p *Application) Connect(path string) error {
	if p == nil || p.modulesMx == nil {
		return fmt.Errorf("nil padlock handle")
	}
	if p.modules != nil {
		p.modulesMx.RLock()
		_, exists := p.modules[path]
		p.modulesMx.RUnlock()
		if exists {
			// Already connected to this path
			return nil
		}
	}
	p.modulesMx.Lock()
	defer p.modulesMx.Unlock()
	module, err := p11.OpenModule(path)
	if err != nil {
		return err
	}
	if p.modules == nil {
		p.modules = make(map[string]p11.Module, 1)
	}
	p.modules[path] = module
	return nil
}
