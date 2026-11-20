package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rawqubit/wirecut/internal/ca"
	"github.com/rawqubit/wirecut/internal/demo"
	"github.com/rawqubit/wirecut/internal/proxy"
	"github.com/rawqubit/wirecut/internal/rules"
	"github.com/rawqubit/wirecut/internal/session"
	"github.com/rawqubit/wirecut/internal/ui"
)

const version = "0.1.0"

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, "; ") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	sub := os.Args[1]
	switch sub {
	case "proxy":
		if err := runProxy(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "wirecut proxy: %v\n", err)
			os.Exit(1)
		}
	case "demo":
		if err := runDemo(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "wirecut demo: %v\n", err)
			os.Exit(1)
		}
	case "ui":
		if err := runUI(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "wirecut ui: %v\n", err)
			os.Exit(1)
		}
	case "version", "-v", "--version":
		fmt.Printf("wirecut %s\n", version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", sub)
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Print(`wirecut — HTTP/1.1 & HTTPS-intercepting debugging proxy

Usage:
  wirecut <command> [flags]

Commands:
  proxy    Start the HTTP/HTTPS intercepting proxy (and optional web UI)
  demo     Run a self-contained headless MITM + rules + redaction demo
  ui       Serve the web inspector UI against a saved JSONL session
  version  Print wirecut version
  help     Show this help message

Run "wirecut <command> --help" for command-specific flags.
`)
}

func loadRules(rulesFile string, inlineSpecs []string) (*rules.Engine, error) {
	var all []rules.Rule
	if rulesFile != "" {
		loaded, err := rules.LoadFile(rulesFile)
		if err != nil {
			return nil, err
		}
		all = append(all, loaded...)
	}
	for _, spec := range inlineSpecs {
		r, err := rules.ParseRule(spec)
		if err != nil {
			return nil, err
		}
		all = append(all, r)
	}
	return rules.NewEngine(all)
}

func runProxy(args []string) error {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	listenAddr := fs.String("listen", ":8080", "proxy listen address")
	uiAddr := fs.String("ui", ":8099", "web UI listen address (empty to disable)")
	caDir := fs.String("ca-dir", "", "directory for ca.pem and ca-key.pem (default ~/.wirecut)")
	sessionPath := fs.String("session", "", "JSONL session file path (default ~/.wirecut/sessions/session-<timestamp>.jsonl)")
	rulesFile := fs.String("rules", "", "path to JSON rules file")
	var inlineRules multiFlag
	fs.Var(&inlineRules, "rule", "inline rule JSON or shorthand (repeatable)")
	maxBody := fs.Int64("max-body", proxy.DefaultMaxBodyBytes, "max request/response body bytes to capture")
	noRedact := fs.Bool("no-redact", false, "write raw Authorization, Cookie, and x-api-key headers to session")
	insecure := fs.Bool("insecure", false, "skip TLS verification for upstream HTTPS connections")

	if err := fs.Parse(args); err != nil {
		return err
	}

	localCA, err := ca.LoadOrCreate(*caDir)
	if err != nil {
		return err
	}

	if *sessionPath == "" {
		*sessionPath = filepath.Join(localCA.Dir(), "sessions",
			fmt.Sprintf("session-%s.jsonl", time.Now().UTC().Format("20060102-150405")))
	}

	sw, err := session.NewWriter(*sessionPath)
	if err != nil {
		return err
	}
	defer sw.Close()

	eng, err := loadRules(*rulesFile, inlineRules)
	if err != nil {
		return err
	}

	logger := log.New(os.Stderr, "[wirecut] ", log.LstdFlags)

	var uiSrv *ui.Server
	if strings.TrimSpace(*uiAddr) != "" {
		uiSrv = ui.New(ui.Config{
			Addr:     *uiAddr,
			CA:       localCA,
			Rules:    eng,
			ErrorLog: logger,
		})
	}

	px, err := proxy.New(proxy.Config{
		Addr:               *listenAddr,
		CA:                 localCA,
		Rules:              eng,
		Session:            sw,
		MaxBodyBytes:       *maxBody,
		NoRedact:           *noRedact,
		InsecureSkipVerify: *insecure,
		ErrorLog:           logger,
		OnExchange: func(ex session.Exchange) {
			if uiSrv != nil {
				uiSrv.Publish(ex)
			}
			tag := ""
			if ex.Blocked {
				tag = " [BLOCKED]"
			}
			fmt.Printf("%s %-6s %s -> %d (%.1fms)%s\n",
				ex.Timestamp.Format("15:04:05"), ex.Method, ex.URL, ex.StatusCode, ex.DurationMS, tag)
		},
	})
	if err != nil {
		return err
	}

	actualProxyAddr, err := px.Start()
	if err != nil {
		return err
	}

	var actualUIAddr string
	if uiSrv != nil {
		uiSrv.SetProxyAddr(actualProxyAddr)
		actualUIAddr, err = uiSrv.Start()
		if err != nil {
			shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = px.Shutdown(shutCtx)
			cancel()
			return err
		}
	}

	fmt.Printf("wirecut proxy listening on http://%s\n", actualProxyAddr)
	if actualUIAddr != "" {
		fmt.Printf("wirecut web UI:    http://%s\n", actualUIAddr)
	}
	fmt.Printf("CA certificate:    %s\n", localCA.CertPath())
	fmt.Printf("Session JSONL:     %s (redact=%v, max-body=%dB, rules=%d)\n",
		*sessionPath, !*noRedact, *maxBody, len(eng.Rules()))

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-sigCtx.Done()

	fmt.Println("\nshutting down...")
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if uiSrv != nil {
		_ = uiSrv.Shutdown(shutCtx)
	}
	return px.Shutdown(shutCtx)
}

func runDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	sessionPath := fs.String("session", "wirecut-demo.jsonl", "path to write the demo JSONL session file")
	caDir := fs.String("ca-dir", "", "optional CA directory (default temporary directory)")
	maxBody := fs.Int64("max-body", 512, "max body capture bytes during demo")
	noRedact := fs.Bool("no-redact", false, "disable sensitive header redaction")

	if err := fs.Parse(args); err != nil {
		return err
	}

	_, err := demo.Run(context.Background(), demo.Options{
		SessionPath:  *sessionPath,
		CADir:        *caDir,
		MaxBodyBytes: *maxBody,
		NoRedact:     *noRedact,
		Out:          os.Stdout,
	})
	return err
}

func runUI(args []string) error {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	uiAddr := fs.String("ui", ":8099", "web UI listen address")
	sessionPath := fs.String("session", "", "optional JSONL session file to load")
	proxyAddr := fs.String("proxy", "", "optional proxy address for Replay requests (e.g. 127.0.0.1:8080)")
	caDir := fs.String("ca-dir", "", "CA directory for ca.pem download and HTTPS replay (default ~/.wirecut)")
	rulesFile := fs.String("rules", "", "optional JSON rules file to show in /api/rules")
	var inlineRules multiFlag
	fs.Var(&inlineRules, "rule", "optional inline rule (repeatable)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	localCA, err := ca.LoadOrCreate(*caDir)
	if err != nil {
		return err
	}
	eng, err := loadRules(*rulesFile, inlineRules)
	if err != nil {
		return err
	}

	var initial []session.Exchange
	if *sessionPath != "" {
		initial, err = session.ReadFile(*sessionPath)
		if err != nil {
			return err
		}
	}

	srv := ui.New(ui.Config{
		Addr:      *uiAddr,
		ProxyAddr: *proxyAddr,
		CA:        localCA,
		Rules:     eng,
		Initial:   initial,
		ErrorLog:  log.New(os.Stderr, "[wirecut-ui] ", log.LstdFlags),
	})
	actualAddr, err := srv.Start()
	if err != nil {
		return err
	}

	fmt.Printf("wirecut web UI listening on http://%s\n", actualAddr)
	if *sessionPath != "" {
		fmt.Printf("Loaded %d exchanges from %s\n", len(initial), *sessionPath)
	}
	if *proxyAddr != "" {
		fmt.Printf("Replay proxy: %s\n", *proxyAddr)
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-sigCtx.Done()

	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutCtx)
}
