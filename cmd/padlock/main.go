package main

import (
	"encoding/json"
	"io/fs"
	"log"
	"os"

	"github.com/LLKennedy/padlock/internal/server"
)

func main() {
	osfs := os.DirFS(".")
	configData, err := fs.ReadFile(osfs, "cfg.json")
	if err != nil {
		log.Fatalln(err)
	}
	otherFS := os.DirFS("C:\\ProgramData")
	cfg := server.Config{}
	err = json.Unmarshal(configData, &cfg)
	if err != nil {
		log.Fatalln(err)
	}
	cfg.FS = otherFS
	err = server.Serve(cfg)
	if err != nil {
		log.Fatalln(err)
	}
}
