package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func TestCLIProcess(t *testing.T) {
	if os.Getenv("COCOON_TEST_CLI_PROCESS") != "1" {
		return
	}
	if version := os.Getenv("COCOON_TEST_CLI_VERSION"); version != "" {
		Version = version
	}
	os.Args = append([]string{"cocoon"}, os.Args[3:]...)
	main()
}

func TestCLILifecycle(t *testing.T) {
	for _, mode := range []string{"sigterm", "sigint", "bind-failure", "browser-dev", "browser-production"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			assets, err := filepath.Abs("../../server")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(assets, filepath.Join(dir, "server")); err != nil {
				t.Fatal(err)
			}
			rotation, err := atcrypto.GeneratePrivateKeyK256()
			if err != nil {
				t.Fatal(err)
			}
			private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			key, err := jwk.FromRaw(private)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(key)
			if err != nil {
				t.Fatal(err)
			}
			for name, data := range map[string][]byte{"rotation": rotation.Bytes(), "jwk": encoded} {
				if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			addr := listener.Addr().String()
			if mode != "bind-failure" {
				listener.Close()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCLIProcess$", "--",
				"--addr", addr, "--db-name", filepath.Join(dir, "test.db"), "--db-type", "sqlite",
				"--did", "did:web:pds.test", "--hostname", "pds.test", "--contact-email", "admin@pds.test",
				"--admin-password", "synthetic-admin-password", "--session-secret", "synthetic-session-secret",
				"--rotation-key-path", filepath.Join(dir, "rotation"), "--jwk-path", filepath.Join(dir, "jwk"),
				"--spaces-enabled=false", "--kem-backfill-enabled=false", "--metrics-listen-address", "", "run")
			cmd.Dir = dir
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "COCOON_") && !strings.HasPrefix(entry, "DATABASE_URL=") {
					cmd.Env = append(cmd.Env, entry)
				}
			}
			cmd.Env = append(cmd.Env, "COCOON_TEST_CLI_PROCESS=1")
			if mode == "browser-production" {
				cmd.Env = append(cmd.Env, "COCOON_TEST_CLI_VERSION=test-release")
			}
			output, err := os.Create(filepath.Join(dir, "output"))
			if err != nil {
				t.Fatal(err)
			}
			defer output.Close()
			cmd.Stdout, cmd.Stderr = output, output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			if mode != "bind-failure" {
				for {
					conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
					if err == nil {
						conn.Close()
						break
					}
					select {
					case err := <-done:
						logs, _ := os.ReadFile(output.Name())
						t.Fatalf("CLI exited before listening: %v\n%s", err, logs)
					case <-time.After(10 * time.Millisecond):
					}
				}
				if strings.HasPrefix(mode, "browser-") {
					checkCLIBrowserCookies(t, addr, filepath.Join(dir, "test.db"), mode == "browser-production")
				}
				signal := syscall.SIGTERM
				if mode == "sigint" {
					signal = syscall.SIGINT
				}
				if err := cmd.Process.Signal(signal); err != nil {
					t.Fatal(err)
				}
			}
			err = <-done
			logs, _ := os.ReadFile(output.Name())
			if ctx.Err() != nil {
				t.Fatalf("CLI did not exit before deadline: %s", logs)
			}
			if mode == "bind-failure" {
				if err == nil || !strings.Contains(string(logs), "address already in use") {
					t.Fatalf("bind failure must exit unsuccessfully: %v\n%s", err, logs)
				}
			} else if err != nil {
				t.Fatalf("signal must gracefully stop CLI: %v\n%s", err, logs)
			}
		})
	}
}
