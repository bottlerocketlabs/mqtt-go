// Copyright 2026 The mqtt-go authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/at-wat/mqtt-go"
)

// loadCertificate loads the client certificate (and any intermediate CA
// certificates following it) and replaces the private key by a crypto.Signer.
//
// In a real application, the certificate would typically be read from
// the key store, and the crypto.Signer would be provided by a library
// for the key store (YubiKey, TPM, PKCS#11 or cloud KMS) instead of
// wrapping a private key loaded from a file.
func loadCertificate(certFile, privateKeyFile string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, privateKeyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	key, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return tls.Certificate{}, errors.New("private key does not implement crypto.Signer")
	}
	cert.PrivateKey = &loggingSigner{signer: key}
	return cert, nil
}

// loggingSigner is a crypto.Signer which logs each signing operation.
// crypto/tls calls Sign once on every TLS handshake, including reconnects,
// so the key store must be kept available while the client is running.
type loggingSigner struct {
	signer crypto.Signer
}

func (s *loggingSigner) Public() crypto.PublicKey {
	return s.signer.Public()
}

func (s *loggingSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	fmt.Printf("Signing TLS handshake (hash: %v)\n", opts.HashFunc())
	return s.signer.Sign(rand, digest, opts)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("   usage: %s server-host.domain\n", os.Args[0])
		fmt.Printf("requires: certificate.crt, private.key, root-CA.crt\n")
		os.Exit(1)
	}
	host := os.Args[1]

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
	defer cancel()

	cert, err := loadCertificate("certificate.crt", "private.key")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	cas, err := os.ReadFile("root-CA.crt")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	tlsConfig, err := newTLSConfig(host, cas, cert)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	println("Connecting to", host)

	cli, err := mqtt.NewReconnectClient(
		// Dialer to connect/reconnect to the server.
		&mqtt.URLDialer{
			URL: fmt.Sprintf("mqtts://%s:8883", host),
			Options: []mqtt.DialOption{
				mqtt.WithTLSConfig(tlsConfig),
				mqtt.WithConnStateHandler(func(s mqtt.ConnState, err error) {
					// Register ConnState callback to low level client
					fmt.Printf("State changed to %s (err: %v)\n", s, err)
				}),
			},
		},
		mqtt.WithPingInterval(10*time.Second),
		mqtt.WithTimeout(5*time.Second),
		mqtt.WithReconnectWait(1*time.Second, 15*time.Second),
	)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	_, err = cli.Connect(ctx,
		"sample", // Client ID
		mqtt.WithKeepAlive(30),
		mqtt.WithWill(
			&mqtt.Message{
				Topic:   "test",
				QoS:     mqtt.QoS1,
				Payload: []byte("{\"message\": \"Bye\"}"),
			},
		),
	)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	mux := &mqtt.ServeMux{} // Multiplex message handlers by topic name.
	cli.Handle(mux)         // Register mux as a low-level handler.

	mux.Handle("#", // Handle all topics by this handler.
		mqtt.HandlerFunc(func(msg *mqtt.Message) {
			fmt.Printf("Wildcard (%s): %s (QoS: %d)\n", msg.Topic, []byte(msg.Payload), int(msg.QoS))
		}),
	)
	mux.Handle("stop", // Handle 'stop' topic by this handler.
		mqtt.HandlerFunc(func(msg *mqtt.Message) {
			fmt.Printf("Stop: %s (QoS: %d)\n", []byte(msg.Payload), int(msg.QoS))
			cancel()
		}),
	)

	// Subscribe two topics.
	if _, err := cli.Subscribe(ctx,
		mqtt.Subscription{
			Topic: "test",
			QoS:   mqtt.QoS1,
		},
		mqtt.Subscription{
			Topic: "stop",
			QoS:   mqtt.QoS1,
		},
	); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	println("Publishing one message to 'test' topic")

	if err := cli.Publish(ctx, &mqtt.Message{
		Topic:   "test",
		QoS:     mqtt.QoS1,
		Payload: []byte("{\"message\": \"Hello\"}"),
	}); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	println("Waiting message on 'stop' topic")
	<-ctx.Done()

	println("Disconnecting")

	if err := cli.Disconnect(ctx); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

// newTLSConfig creates TLS configuration with a client certificate
// whose private key is held by a crypto.Signer.
func newTLSConfig(host string, caPEM []byte, cert tls.Certificate) (*tls.Config, error) {
	certpool := x509.NewCertPool()
	if !certpool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("failed to parse root CA certificate")
	}

	return &tls.Config{
		ServerName:   host,
		RootCAs:      certpool,
		Certificates: []tls.Certificate{cert},
	}, nil
}

