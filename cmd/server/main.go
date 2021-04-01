package main

import (
	"log"

	"github.com/LLKennedy/padlock/server"
)

func main() {
	srv := &server.Padlock{}
	err := srv.Connect(`D:\Downloads\SecurityServerEvaluation-V4.40.0.2\Software\Windows\x86-64\Crypto_APIs\PKCS11_R3\lib\cs_pkcs11_R3.dll`)
	if err != nil {
		log.Fatalln(err)
	}
}
