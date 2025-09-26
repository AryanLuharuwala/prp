#!/bin/bash

# Generate a private key
openssl genrsa -out server.key 2048

# Generate a self-signed certificate with SAN (Subject Alternative Names)
openssl req -new -x509 -key server.key -out server.crt -days 365 \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1,IP:::1"

echo "Generated server.key and server.crt with SAN for localhost and 127.0.0.1"
