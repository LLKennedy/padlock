package server

import (
	"github.com/miekg/pkcs11/p11"
)

// Padlock is a padlock server
type Padlock struct{}

// Connect connects to an HSM
func (p *Padlock) Connect() {
	module, err := p11.OpenModule(`D:\Downloads\SecurityServerEvaluation-V4.40.0.2\Software\Windows\x86-64\Crypto_APIs\PKCS11_R3\lib\cs_pkcs11_R3.dll`)
	if err != nil {
		panic(err)
	}
	module.Info()
}
