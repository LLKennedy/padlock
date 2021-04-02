package padlocklib

import (
	"fmt"
	"sync"

	"github.com/miekg/pkcs11/p11"
)

// Application is a Padlock application, maintaining module and session state for an entire multi-threaded application.
type Application struct {
	modulesMx *sync.RWMutex
	Modules   map[string]p11.Module
}

// NewApplication creates a new Application
func NewApplication() *Application {
	return &Application{
		modulesMx: new(sync.RWMutex),
		Modules:   make(map[string]p11.Module, 1),
	}
}

// Connect connects to an HSM
func (p *Application) Connect(path string) (p11.Module, error) {
	if p == nil || p.modulesMx == nil {
		return p11.Module{}, fmt.Errorf("nil padlock handle")
	}
	if p.Modules != nil {
		p.modulesMx.RLock()
		module, exists := p.Modules[path]
		p.modulesMx.RUnlock()
		if exists {
			// Already connected to this path
			return module, nil
		}
	}
	p.modulesMx.Lock()
	defer p.modulesMx.Unlock()
	module, err := p11.OpenModule(path)
	if err != nil {
		return p11.Module{}, err
	}
	if p.Modules == nil {
		p.Modules = make(map[string]p11.Module, 1)
	}
	p.Modules[path] = module
	return module, nil
}
