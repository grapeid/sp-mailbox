package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/grapeid/sp-mailbox/internal/api"
	"github.com/grapeid/sp-mailbox/internal/protocol"
	"github.com/grapeid/sp-mailbox/internal/store"
	"github.com/grapeid/sp-common/verify"
)

func main() {
	var (
		addr      = flag.String("addr", defaultAddr(), "listen address")
		dbPath    = flag.String("db", envOr("MAILBOX_DB", "mailbox.db"), "sqlite database path")
		apex      = flag.String("apex", os.Getenv("MAILBOX_APEX"), "public origin, e.g. https://mailbox.example.org")
		aid       = flag.String("aid", os.Getenv("MAILBOX_AID"), "this operator's own AID")
		retention = flag.Duration("retention", protocol.DefaultRetention, "how long an uncollected message is kept")
		trustXFF  = flag.Bool("trust-proxy", os.Getenv("MAILBOX_TRUST_PROXY") == "1",
			"trust X-Forwarded-For; only behind a proxy that sets it")
		allowUnverified = flag.Bool("allow-unverified-enrollment",
			os.Getenv("MAILBOX_ALLOW_UNVERIFIED") == "1",
			"accept enrollments without checking the key belongs to the AID (development only)")
	)
	flag.Parse()

	if *apex == "" {
		// Refused rather than guessed from the first request's Host header.
		// The apex is baked into every deposit URL this service hands out, so
		// inferring it from something a caller controls would let somebody
		// redirect other people's deposits.
		log.Fatal("-apex is required: it is the origin written into every deposit URL, " +
			"and inferring it from request headers would let a caller redirect deposits")
	}

	// Every enrolment is checked: the enrolling identity sends its signed key
	// event log, and keri-go confirms in this process that the log derives the
	// AID and names the key presented. Turning that off is a development choice
	// that has to be made out loud, because without it anybody can take any
	// identifier and deny its real owner the use of this operator.
	var verifier verify.Verifier = verify.KeyLog{}
	if *allowUnverified {
		verifier = verify.Unverified{}
		log.Print("[mailbox] WARNING: running with unverified enrollment. Anyone can claim " +
			"any AID and deny its real owner the use of this operator. Development only.")
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("could not open the store: %v", err)
	}
	defer st.Close()

	srv := api.New(api.Config{
		Store:             st,
		Apex:              *apex,
		AID:               *aid,
		Retention:         *retention,
		TrustProxyHeaders: *trustXFF,
		Verifier:          verifier,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Retention that only applies when somebody happens to look is not
	// retention, so an abandoned mailbox is emptied on a timer.
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n, err := st.Sweep(); err != nil {
					log.Printf("[mailbox] sweep failed: %v", err)
				} else if n > 0 {
					log.Printf("[mailbox] swept %d expired messages", n)
				}
			}
		}
	}()

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Printf("[mailbox] listening on %s, serving %s (retention %s)", *addr, *apex, *retention)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server failed: %v", err)
		}
	}()

	<-ctx.Done()
	log.Print("[mailbox] shutting down")

	// Deliberate grace period: a collection in flight should finish rather than
	// be cut off, because a recipient that half-collects and never acknowledges
	// leaves messages it thinks it has.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[mailbox] shutdown was not clean: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// defaultAddr resolves the listen address.
//
// PORT is checked because the hosts these services run on supply it and expect
// the process to obey; MAILBOX_ADDR wins when both are set, since it is the
// more specific instruction. A PORT that is not a number is ignored rather than
// concatenated into an address that would fail to bind with a confusing error.
func defaultAddr() string {
	if explicit := os.Getenv("MAILBOX_ADDR"); explicit != "" {
		return explicit
	}
	if p := os.Getenv("PORT"); p != "" {
		if _, err := strconv.Atoi(p); err == nil {
			return ":" + p
		}
		log.Printf("[mailbox] ignoring PORT=%q, which is not a number", p)
	}
	return ":8090"
}
