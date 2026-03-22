package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"os"
)

func loadConfig(path string) *Config {
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("failed to open config: %v", err)
	}
	defer f.Close()

	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		log.Fatalf("failed to decode config: %v", err)
	}
	return &cfg
}

func readInput(r io.Reader) *HookInput {
	var input HookInput
	if err := json.NewDecoder(r).Decode(&input); err != nil {
		log.Fatalf("failed to decode input: %v", err)
	}
	return &input
}

func main() {
	configPath := flag.String("config", "", "path to rules JSON")
	flag.Parse()

	if *configPath == "" {
		log.Fatal("--config is required")
	}

	cfg := loadConfig(*configPath)
	input := readInput(os.Stdin)

	result := cfg.Evaluate(input)
	if result != nil {
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			log.Fatalf("failed to encode result: %v", err)
		}
	}
}
