package config

import "os"

type Config struct {
	ListenAddress string
	DataDirectory string
}

func FromEnvironment() Config {
	return Config{
		ListenAddress: valueOrDefault("MNEME_LISTEN", ":8080"),
		DataDirectory: valueOrDefault("MNEME_DATA_DIR", "./data"),
	}
}

func valueOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
