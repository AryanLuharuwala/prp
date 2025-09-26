#!/bin/bash

# Example script to demonstrate the P2P file transfer system

echo "Setting up P2P File Transfer Demo..."

# Generate certificates if they don't exist
if [ ! -f "server.crt" ] || [ ! -f "server.key" ]; then
    echo "Generating SSL certificates..."
    ./generate_certs.sh
fi

# Create directories and sample files
echo "Creating test files..."
mkdir -p files server_files

echo "This is a test file from peer" > files/peer_test.txt
echo "Another file from peer with some content" > files/peer_document.txt
echo "Server-side file for testing" > server_files/server_test.txt

echo "Files created:"
echo "Peer files:"
ls -la files/
echo "Server files:"
ls -la server_files/

echo ""
echo "To run the demo:"
echo ""
echo "1. Start the server in one terminal:"
echo "   RUST_LOG=info cargo run -- server --key server.key --cert server.crt"
echo ""
echo "2. Start a peer in another terminal:"
echo "   Option A - Using server certificate (secure):"
echo "   RUST_LOG=info cargo run -- peer --server-addr 127.0.0.1:8080 --server-cert server.crt"
echo ""
echo "   Option B - Skip TLS verification (insecure, for development):"
echo "   RUST_LOG=info cargo run -- peer --server-addr 127.0.0.1:8080 --no-verify-tls"
echo ""
echo "3. Watch the logs to see:"
echo "   - Peer connecting to server"
echo "   - File announcements"
echo "   - Bidirectional communication"
echo ""
echo "Note: The --no-verify-tls flag is used to bypass certificate validation for self-signed certificates."
echo "In production, you would use proper certificates from a trusted CA and omit this flag."
