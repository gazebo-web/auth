package main

import (
	"auth/internal/database"
	"auth/pkg/config"
	"auth/pkg/repository"
	"auth/pkg/service"
	"github.com/caarlos0/env/v7"
	"github.com/gazebo-web/gz-go/v7"
	"github.com/gazebo-web/gz-go/v7/net"
	"github.com/gazebo-web/gz-go/v7/telemetry"
	"github.com/jinzhu/gorm"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	cfg, err := config.ParseAuthFromEnvVars()
	if err != nil {
		log.Fatalln("Failed to get configuration from environment variables. Error:", err)
		return
	}

	// Setup database connection
	db := setupDB()

	// Initialize logging system
	logger := setupLogger()

	// Initialize repositories
	userRepository := repository.NewUser(db)
	orgRepository := repository.NewOrganization(db)

	// Initialize services
	userService := service.NewUser()
	orgService := service.NewOrganization()
	authService := service.NewAuth()

	// Initialize tracing
	propagator, tracerProvider := setupTracing()

	// Unary and stream interceptors for gRPC server
	var unaries []grpc.UnaryServerInterceptor
	var streams []grpc.StreamServerInterceptor
	unaries, streams = telemetry.AppendServerInterceptors(unaries, streams, propagator, tracerProvider)

	// Initialize server with the given router
	s := net.NewServer(
		net.GRPC(userService.Register, streams, unaries),
		net.GRPC(orgService.Register, streams, unaries),
		net.GRPC(authService.Register, streams, unaries),
		net.ListenerTCP(cfg.GRPCPort),
	)

	// Listening to incoming server requests returns an errors channel where any of the servers can publish errors
	errs := s.ListenAndServe()
	// Once done, close the underlying servers.
	defer s.Close()

	// Listen for Interrupt and Terminate signals
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	log.Printf("Auth is listening on ports %d (gRPC).", cfg.GRPCPort)

	// Block until an error or a signal is received.
	select {
	case sig := <-sigs:
		log.Fatalln("Signal received:", sig.String())
		return
	case err := <-errs:
		log.Fatalln("Failed to listen and serve. Error:", err)
		return
	}
}

func setupLogger() gz.Logger {
	// Log flags and prefix
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.SetPrefix("[Auth] ")

	return gz.NewLogger("", true, gz.VerbosityDebug)
}

func setupDB() *gorm.DB {
	log.Println("Initializing database.")
	db, err := database.SetupDB()
	if err != nil {
		log.Fatalln("Failed to open database connection:", err)
		return nil
	}
	if err := database.MigrateTables(db); err != nil {
		log.Fatalln("Failed to migrate models:", err)
		return nil
	}
	return db
}

// setupTracing initializes tracing services.
// Tracing configuration is currently done through environment variables with the "TRACING_" prefix.
// Refer to telemetry.TracingConfig documentation to see available configuration values.
func setupTracing() (propagation.TextMapPropagator, trace.TracerProvider) {
	log.Println("Initializing tracing.")

	// Load config from environment variables
	var cfg telemetry.TracingConfig
	if err := env.Parse(cfg); err != nil {
		log.Fatalln("Failed to initialize tracing:", err)
	}

	propagator, tracerProvider, err := telemetry.InitializeTracing(cfg)
	if err != nil {
		log.Fatalln("Failed to initialize tracing:", err)
	}

	if !cfg.Enabled {
		log.Println("Tracing is disabled.")
	} else if propagator == nil || tracerProvider == nil {
		log.Println("Tracing was not initialized.")
	}

	return propagator, tracerProvider
}
