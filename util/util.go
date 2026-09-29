package util

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/joho/godotenv"
)

func LoadEnvFile() {

	path, err := loadFromPar()
	if err != nil {
		log.Fatalf("Failed load env file %v\n", err)
	}

	godotenv.Load(path)
}

func loadFromPar() (string, error) {

	path, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		possible := filepath.Join(path, ".env")
		fmt.Printf("%v\n", possible)
		if _, err := os.Stat(possible); err == nil {
			return possible, nil
		}

		parent := filepath.Dir(path)

		if path == parent {
			return  "", os.ErrNotExist
		}

		path = parent
	}
}