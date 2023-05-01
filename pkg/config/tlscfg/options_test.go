// Copyright (c) 2019 The Jaeger Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tlscfg

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/rand"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

var testCertKeyLocation = "./testdata"

func TestOptionsToConfig(t *testing.T) {
	tests := []struct {
		name        string
		options     Options
		fakeSysPool bool
		expectError string
	}{
		{
			name:    "should load system CA",
			options: Options{CAPath: ""},
		},
		{
			name:        "should fail with fake system CA",
			fakeSysPool: true,
			options:     Options{CAPath: ""},
			expectError: "fake system pool",
		},
		{
			name:    "should load custom CA",
			options: Options{CAPath: testCertKeyLocation + "/example-CA-cert.pem"},
		},
		{
			name:        "should fail with invalid CA file path",
			options:     Options{CAPath: testCertKeyLocation + "/not/valid"},
			expectError: "failed to load CA",
		},
		{
			name:        "should fail with invalid CA file content",
			options:     Options{CAPath: testCertKeyLocation + "/bad-CA-cert.txt"},
			expectError: "failed to parse CA",
		},
		{
			name: "should load valid TLS Client settings",
			options: Options{
				CAPath:   testCertKeyLocation + "/example-CA-cert.pem",
				CertPath: testCertKeyLocation + "/example-client-cert.pem",
				KeyPath:  testCertKeyLocation + "/example-client-key.pem",
			},
		},
		{
			name: "should fail with missing TLS Client Key",
			options: Options{
				CAPath:   testCertKeyLocation + "/example-CA-cert.pem",
				CertPath: testCertKeyLocation + "/example-client-cert.pem",
			},
			expectError: "both client certificate and key must be supplied",
		},
		{
			name: "should fail with invalid TLS Client Key",
			options: Options{
				CAPath:   testCertKeyLocation + "/example-CA-cert.pem",
				CertPath: testCertKeyLocation + "/example-client-cert.pem",
				KeyPath:  testCertKeyLocation + "/not/valid",
			},
			expectError: "failed to load server TLS cert and key",
		},
		{
			name: "should fail with missing TLS Client Cert",
			options: Options{
				CAPath:  testCertKeyLocation + "/example-CA-cert.pem",
				KeyPath: testCertKeyLocation + "/example-client-key.pem",
			},
			expectError: "both client certificate and key must be supplied",
		},
		{
			name: "should fail with invalid TLS Client Cert",
			options: Options{
				CAPath:   testCertKeyLocation + "/example-CA-cert.pem",
				CertPath: testCertKeyLocation + "/not/valid",
				KeyPath:  testCertKeyLocation + "/example-client-key.pem",
			},
			expectError: "failed to load server TLS cert and key",
		},
		{
			name: "should fail with invalid TLS Client CA",
			options: Options{
				ClientCAPath: testCertKeyLocation + "/not/valid",
			},
			expectError: "failed to load CA",
		},
		{
			name: "should fail with invalid TLS Client CA pool",
			options: Options{
				ClientCAPath: testCertKeyLocation + "/bad-CA-cert.txt",
			},
			expectError: "failed to parse CA",
		},
		{
			name: "should pass with valid TLS Client CA pool",
			options: Options{
				ClientCAPath: testCertKeyLocation + "/example-CA-cert.pem",
			},
		},
		{
			name: "should fail with invalid TLS Cipher Suite",
			options: Options{
				CipherSuites: []string{"TLS_INVALID_CIPHER_SUITE"},
			},
			expectError: "failed to get cipher suite ids from cipher suite names: cipher suite TLS_INVALID_CIPHER_SUITE not supported or doesn't exist",
		},
		{
			name: "should fail with invalid TLS Min Version",
			options: Options{
				MinVersion: "Invalid",
			},
			expectError: "failed to get minimum tls version",
		},
		{
			name: "should fail with invalid TLS Max Version",
			options: Options{
				MaxVersion: "Invalid",
			},
			expectError: "failed to get maximum tls version",
		},
		{
			name: "should fail with TLS Min Version greater than TLS Max Version error",
			options: Options{
				MinVersion: "1.2",
				MaxVersion: "1.1",
			},
			expectError: "minimum tls version can't be greater than maximum tls version",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.fakeSysPool {
				saveSystemCertPool := systemCertPool
				systemCertPool = func() (*x509.CertPool, error) {
					return nil, fmt.Errorf("fake system pool")
				}
				defer func() {
					systemCertPool = saveSystemCertPool
				}()
			}
			cfg, err := test.options.Config(zap.NewNop())
			if test.expectError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.expectError)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, cfg)

				if test.options.CertPath != "" && test.options.KeyPath != "" {
					c, e := tls.LoadX509KeyPair(filepath.Clean(test.options.CertPath), filepath.Clean(test.options.KeyPath))
					require.NoError(t, e)
					cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
					require.NoError(t, err)
					assert.Equal(t, &c, cert)
					cert, err = cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
					require.NoError(t, err)
					assert.Equal(t, &c, cert)
				}
			}
			assert.NoError(t, test.options.Close())
		})
	}
}

func TestOptionsToConfigRaceCondition(t *testing.T) {
	var cfg *tls.Config
	var mu sync.Mutex
	options := &Options{
		CAPath:   testCertKeyLocation + "/example-CA-cert.pem",
		CertPath: testCertKeyLocation + "/example-client-cert.pem",
		KeyPath:  testCertKeyLocation + "/example-client-key.pem",
	}

	cfg, err := options.Config(zap.NewNop())
	require.NoError(t, err)
	assert.NotNil(t, cfg)

	if options.CertPath != "" && options.KeyPath != "" {
		c, e := tls.LoadX509KeyPair(filepath.Clean(options.CertPath), filepath.Clean(options.KeyPath))
		require.NoError(t, e)
		cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
		cert, err = cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
		require.NoError(t, err)
		assert.Equal(t, &c, cert)
	}

	server := &http.Server{
		Addr:         ":8443",
		TLSConfig:    cfg,
		Handler:      http.HandlerFunc(helloHandler),
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)), // Disable HTTP/2

	}

	var wgServe sync.WaitGroup
	wgServe.Add(1)
	go func(wgServe *sync.WaitGroup) {
		defer wgServe.Done()
		if err := server.ListenAndServeTLS("", ""); err != nil {
			fmt.Println(err)
		}

	}(&wgServe)

	//In one goroutine, periodically generate new certificates and reload them for the server.
	var wgTls sync.WaitGroup
	wgTls.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			output, err := exec.Command("/bin/sh", testCertKeyLocation+"/gen-certs.sh").CombinedOutput()
			if err != nil {
				fmt.Printf("Error executing script: %v\n", err)
				return
			}
			result := strings.TrimSpace(string(output))
			fmt.Println(result)
			options := &Options{
				CAPath:   testCertKeyLocation + "/example-CA-cert.pem",
				CertPath: testCertKeyLocation + "/example-client-cert.pem",
				KeyPath:  testCertKeyLocation + "/example-client-key.pem",
			}
			cfg, err = options.Config(zap.NewNop())

			require.NoError(t, err)
			assert.NotNil(t, cfg)
			if options.CertPath != "" && options.KeyPath != "" {
				c, e := tls.LoadX509KeyPair(filepath.Clean(options.CertPath), filepath.Clean(options.KeyPath))
				require.NoError(t, e)
				cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
				cert, err = cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
				require.NoError(t, err)
				assert.Equal(t, &c, cert)
			}
			//reload server
			mu.Lock()
			server.TLSConfig = cfg
			time.Sleep(1 * time.Second)
			mu.Unlock()

		}
	}(&wgTls)

	var wgGet sync.WaitGroup

	go func() {
		for i := 0; i < 100; i++ {
			cfg.InsecureSkipVerify = true
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: cfg,
				},
			}
			wgGet.Add(1)
			go func(i int) {
				defer wgGet.Done()
				resp, err := client.Get("https://localhost:8443")
				if err != nil {
					fmt.Printf("Error making GET request: %v", err)
					return
				}
				defer resp.Body.Close()

				fmt.Printf("GET request succeeded with status: %d\n", resp.StatusCode)
				rand.Seed(time.Now().UnixNano())
				randomDuration := time.Duration(500+rand.Intn(5000)) * time.Millisecond
				time.Sleep(randomDuration)
			}(i)
		}
	}()

	wgTls.Wait()
	wgGet.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		fmt.Println("Error shutting down the server:", err)
	}
	fmt.Println("Server shut down gracefully")
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "test server")
}
