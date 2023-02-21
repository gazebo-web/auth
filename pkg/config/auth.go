package config

import "github.com/caarlos0/env/v7"

// Auth contains configuration values for the Auth application.
type Auth struct {
	// GRPCPort is the gRPC server port to serve from.
	GRPCPort uint `env:"GRPC_PORT" envDefault:"3030"`
	// Backend defines the authorization backend used to process authorization requests.
	// Additional configuration might be required depending on the selected authorization backend.
	// Refer to the documentation of the specific authorization backend implementation for configuration information.
	Backend string `env:"BACKEND,required"`
}

// ParseAuthFromEnvVars parses and returns an Auth configuration from environment variables.
// All environment variables must have the "AUTH_" prefix added to them in order to be picked up by this function.
func ParseAuthFromEnvVars() (Auth, error) {
	var cfg Auth

	err := env.Parse(&cfg, env.Options{
		Prefix: "AUTH_",
	})

	return cfg, err
}
