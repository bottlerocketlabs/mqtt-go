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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/at-wat/mqtt-go"
)

const (
	envCA         = "MQTT_ROOT_CA"
	envCert       = "MQTT_CERTIFICATE"
	envPrivateKey = "MQTT_PRIVATE_KEY"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("   usage: %s server-host.domain\n", os.Args[0])
		fmt.Printf("requires: PEM contents in %s, %s, %s environment variables\n",
			envCert, envPrivateKey, envCA)
		fmt.Printf("    note: %s may include intermediate CA certificates after the client certificate\n",
			envCert)
		fmt.Printf(" warning: environment variables are visible to child processes and via /proc/<pid>/environ\n")
		os.Exit(1)
	}
	host := os.Args[1]

	// Passing a private key via an environment variable is convenient for
	// containers and CI, but the value is inherited by child processes and
	// readable by the same user (and root) via /proc/<pid>/environ.
	// Prefer a secret file, a hardware key or a KMS in production.
	caPEM, certPEM, privateKeyPEM := os.Getenv(envCA), os.Getenv(envCert), os.Getenv(envPrivateKey)
	if caPEM == "" || certPEM == "" || privateKeyPEM == "" {
		fmt.Printf("Error: %s, %s and %s must be set\n", envCA, envCert, envPrivateKey)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
	defer cancel()

	tlsConfig, err := newTLSConfig(host, caPEM, certPEM, privateKeyPEM)
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

// newTLSConfig creates TLS configuration with client certificates
// from PEM encoded contents.
// All certificates in certPEM are sent to the server as the client certificate chain.
func newTLSConfig(host, caPEM, certPEM, privateKeyPEM string) (*tls.Config, error) {
	certpool := x509.NewCertPool()
	if !certpool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, errors.New("failed to parse root CA certificate")
	}

	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(privateKeyPEM))
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		ServerName:   host,
		RootCAs:      certpool,
		Certificates: []tls.Certificate{cert},
	}, nil
}
