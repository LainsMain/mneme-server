package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/lainsmain/mneme-server/internal/config"
	"github.com/lainsmain/mneme-server/internal/httpapi"
	"github.com/lainsmain/mneme-server/internal/store"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mneme:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	command := "serve"
	if len(arguments) > 0 {
		command, arguments = arguments[0], arguments[1:]
	}
	config := config.FromEnvironment()
	switch command {
	case "serve":
		return serve(config)
	case "token":
		return tokenCommand(config, arguments)
	case "healthcheck":
		return healthcheck(config)
	case "help", "--help", "-h":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", command)
	}
}

func serve(config config.Config) error {
	dataStore, err := store.Open(config.DataDirectory)
	if err != nil {
		return err
	}
	defer dataStore.Close()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	server := &http.Server{
		Addr: config.ListenAddress,
		Handler: httpapi.New(
			dataStore,
			logger,
			httpapi.WithVersion(version),
		).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	shutdownContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-shutdownContext.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	logger.Info("starting Mneme server", "address", config.ListenAddress)
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func tokenCommand(config config.Config, arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("usage: mneme token create|list|revoke")
	}
	dataStore, err := store.Open(config.DataDirectory)
	if err != nil {
		return err
	}
	defer dataStore.Close()

	switch arguments[0] {
	case "create":
		flags := flag.NewFlagSet("token create", flag.ContinueOnError)
		name := flags.String("name", "Android device", "recognizable device name")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		plain, token, err := dataStore.CreateToken(context.Background(), strings.TrimSpace(*name))
		if err != nil {
			return err
		}
		fmt.Printf("Created token %s (%s). It will only be shown once.\n\n%s\n", token.ID, token.Name, plain)
		return nil
	case "list":
		tokens, err := dataStore.ListTokens(context.Background())
		if err != nil {
			return err
		}
		writer := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(writer, "ID\tNAME\tCREATED\tSTATUS")
		for _, token := range tokens {
			status := "active"
			if token.RevokedAt != nil {
				status = "revoked"
			}
			fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", token.ID, token.Name, token.CreatedAt.Format(time.RFC3339), status)
		}
		return writer.Flush()
	case "revoke":
		if len(arguments) != 2 {
			return errors.New("usage: mneme token revoke <token-id>")
		}
		if err := dataStore.RevokeToken(context.Background(), arguments[1]); err != nil {
			return err
		}
		fmt.Println("Revoked token", arguments[1])
		return nil
	default:
		return fmt.Errorf("unknown token command %q", arguments[0])
	}
}

func healthcheck(config config.Config) error {
	address := config.ListenAddress
	if strings.HasPrefix(address, ":") {
		address = "127.0.0.1" + address
	}
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get("http://" + address + "/v1/health")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned %s", response.Status)
	}
	return nil
}

func usage() {
	fmt.Println(`Mneme encrypted backup server

Usage:
  mneme serve
  mneme token create --name "Pixel"
  mneme token list
  mneme token revoke <token-id>
  mneme healthcheck`)
}
