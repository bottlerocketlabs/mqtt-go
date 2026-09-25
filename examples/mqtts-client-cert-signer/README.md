# MQTTs with client certificate and crypto.Signer

Connects to an MQTT broker over TLS using a client certificate whose private key
is accessed only through the [`crypto.Signer`](https://pkg.go.dev/crypto#Signer) interface.

mqtt-go uses the standard `crypto/tls` package, so nothing specific to mqtt-go is required.
Any `crypto.Signer` set as `tls.Certificate.PrivateKey` is used to sign the TLS handshake:

```go
cert := tls.Certificate{
	Certificate: [][]byte{leaf.Raw}, // followed by intermediate CA certificates, if any
	PrivateKey:  signer,             // crypto.Signer
	Leaf:        leaf,
}
cli, err := mqtt.NewReconnectClient(
	&mqtt.URLDialer{
		URL: "mqtts://server-host.domain:8883",
		Options: []mqtt.DialOption{
			mqtt.WithTLSConfig(&tls.Config{
				RootCAs:      certpool,
				Certificates: []tls.Certificate{cert},
			}),
		},
	},
)
```

This allows the private key to stay in a hardware key or a key management service
and never be loaded into the process memory.

To keep this example free of cgo and external dependencies, the private key is loaded from a file
and wrapped by a `crypto.Signer` which logs each signing operation.
Replace `loadCertificate` with one of the libraries below to use a real key store.

## Usage

Place these files in the working directory:

- `certificate.crt`: client certificate, optionally followed by intermediate CA certificates
- `private.key`: private key of the client certificate
- `root-CA.crt`: CA certificate(s) to verify the broker

```shell
go run . server-host.domain
```

`Signing TLS handshake` is printed on each connection, including reconnects.

## Key stores

| Key store | Library | Notes |
| --- | --- | --- |
| YubiKey (PIV) | [github.com/go-piv/piv-go](https://github.com/go-piv/piv-go) | `(*piv.YubiKey).PrivateKey` returns a key implementing `crypto.Signer`. Requires cgo and PC/SC (`libpcsclite-dev` on Linux). |
| PKCS#11 (HSM, smartcard, SoftHSM, YubiKey via `ykcs11`, TPM via `tpm2-pkcs11`) | [github.com/ThalesGroup/crypto11](https://github.com/ThalesGroup/crypto11) | `(*crypto11.Context).FindKeyPair` returns a `crypto.Signer`. Requires cgo and the vendor's PKCS#11 module. |
| TPM 2.0 | [github.com/google/go-tpm-tools](https://github.com/google/go-tpm-tools) | `(*client.Key).GetSigner` returns a `crypto.Signer`. |
| AWS KMS, Google Cloud KMS, Azure Key Vault, etc. | Cloud SDKs, or [github.com/sigstore/sigstore](https://github.com/sigstore/sigstore) `pkg/signature/kms` (`CryptoSigner` method) | Remote signing adds latency to each TLS handshake. |

When using a key store:

- Keep the key store session open while the client is running.
  `crypto/tls` calls `Sign` on every handshake, and `ReconnectClient` handshakes again on each reconnect.
- If the key requires a PIN, provide it without blocking on a terminal when running unattended,
  e.g. from a secret file or a service manager credential.
- Include intermediate CA certificates in `tls.Certificate.Certificate`
  if the broker doesn't already have them.
- The key must be usable for TLS signatures: RSA (PKCS#1 v1.5 or PSS) or ECDSA.
  Some key stores restrict the algorithms or require specific `crypto.SignerOpts`.
