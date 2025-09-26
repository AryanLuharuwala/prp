# P2P File Transfer System

This is a peer-to-peer file transfer system implemented in Rust using QUIC transport protocol.

## Features

- **Bidirectional Communication**: Both peers and servers can initiate requests
- **QUIC Transport**: Fast, secure, and reliable UDP-based transport
- **File Transfer**: Chunked file transfer with proper acknowledgments
- **Presence Announcement**: Peers announce their presence to the server
- **File Discovery**: Peers can announce available files to the server

## Architecture

### Components

1. **PeerClient**: Connects to a server and can:
   - Announce its presence
   - Share files with other peers
   - Respond to file requests from the server
   - Handle bidirectional communication

2. **Server**: Accepts connections from peers and can:
   - Track connected peers
   - Accept file announcements
   - Send requests to peers independently
   - Coordinate file transfers between peers

### Communication Protocol

The system uses a `Communication` enum with the following message types:

- `PresenceAnnounce/PresenceResponse`: Peer registration
- `FileAnnounce/FileAcknowledge`: File availability announcement
- `FileList`: List available files from a peer
- `FileRequest/FileResponse`: Request specific files
- `FileChunk/FileChunkAck`: Actual file data transfer
- `FileTransferComplete`: Transfer completion notification
- `Error`: Error messages

## Usage

### Prerequisites

1. Generate SSL certificates:
```bash
./generate_certs.sh
```

2. Create file directories:
```bash
mkdir -p files server_files
```

3. Add some test files to transfer:
```bash
echo "Hello from peer!" > files/test.txt
echo "Server file content" > server_files/server_test.txt
```

### Running the Server

```bash
RUST_LOG=info cargo run -- server --key server.key --cert server.crt
```

### Running a Peer

```bash
RUST_LOG=info cargo run -- peer --server-addr 127.0.0.1:8080 --no-verify-tls
```

**Note**: The `--no-verify-tls` flag disables TLS certificate verification, which is useful when using self-signed certificates for development. In production, use proper certificates from a trusted CA and omit this flag.

## Implementation Details

### Key Features Implemented

1. **Bidirectional QUIC Streams**: The system uses QUIC's bidirectional streams to enable both client and server to initiate requests.

2. **Async Event Loop**: The peer runs an async event loop that:
   - Processes incoming QUIC packets
   - Handles stream data
   - Responds to server requests
   - Maintains connection health

3. **File Chunking**: Large files are transferred in chunks to handle network limitations and provide progress tracking.

4. **Request/Response Matching**: Uses stream IDs to match requests with responses for proper async handling.

### Protocol Flow

1. **Connection Establishment**:
   - Peer connects to server using QUIC
   - TLS handshake (requires valid certificates)
   - Connection establishment verification

2. **Presence Announcement**:
   - Peer announces its presence to server
   - Server acknowledges and tracks the peer

3. **File Announcement**:
   - Peer scans local files directory
   - Announces each file to server with metadata
   - Server acknowledges file availability

4. **Request Processing**:
   - Server can independently send requests to peer
   - Peer processes requests and sends responses
   - Both sides handle timeouts and errors

### Current Limitations

1. **TLS Certificate Validation**: Currently disabled for development
2. **Error Recovery**: Basic error handling implemented
3. **File Transfer Resumption**: Not implemented
4. **Peer Discovery**: Centralized through server only
5. **Authentication**: No peer authentication mechanism

## Future Enhancements

1. **Direct Peer-to-Peer**: Allow peers to connect directly
2. **DHT Integration**: Distributed hash table for peer discovery
3. **File Integrity**: Checksums and verification
4. **Bandwidth Management**: Transfer rate limiting
5. **Advanced Security**: Peer authentication and authorization

## Dependencies

- `quiche`: QUIC implementation
- `tokio`: Async runtime
- `clap`: CLI argument parsing
- `serde`/`bincode`: Message serialization
- `anyhow`: Error handling
- `log`/`env_logger`: Logging

## Notes

The implementation demonstrates the core concepts of a P2P file transfer system:
- The peer can both initiate connections to servers AND accept incoming requests
- The server can send requests to peers without waiting for peer-initiated requests
- QUIC provides the bidirectional, reliable transport layer
- The architecture supports scaling to multiple peers and distributed file sharing

This is a working foundation that can be extended with additional features like peer discovery, authentication, and advanced file transfer capabilities.
