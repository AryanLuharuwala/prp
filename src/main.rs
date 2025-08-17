use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use log::{debug, error, info, warn, trace};
use ring::rand::{SystemRandom,SecureRandom};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use tokio::time::timeout;
use url::Url;

/// P2P File Transfer CLI
#[derive(Parser, Debug)]
#[command(name = "p2p-transfer")]
#[command(about = "A peer-to-peer file transfer system using QUIC")]
struct Command {
    #[command(subcommand)]
    subcommand: SubCommands,
}

#[derive(Subcommand, Debug)]
enum SubCommands {
    /// Run as a peer
    Peer {
        #[arg(long, help = "Server address to connect to (e.g., 127.0.0.1:8080)")]
        server_addr: String,
        #[arg(long, help = "Local files directory", default_value = "./files")]
        files_dir: String,
        #[arg(long, help = "Local listen port", default_value = "0")]
        port: u16,
        #[arg(long, help = "Path to server certificate file for TLS verification")]
        server_cert: Option<String>,
        #[arg(
            long,
            help = "Disable TLS certificate verification (insecure, for development only)"
        )]
        no_verify_tls: bool,
    },
    /// Run as a server
    Server {
        #[arg(long, help = "Server listen address", default_value = "127.0.0.1:8080")]
        addr: String,
        #[arg(long, help = "Server key file path")]
        key: String,
        #[arg(long, help = "Server certificate file path")]
        cert: String,
        #[arg(long, help = "Local files directory", default_value = "./server_files")]
        files_dir: String,
    },
}

const MAX_DATAGRAM_SIZE: usize = 1350;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
const FILE_CHUNK_SIZE: usize = 8192;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicConfig {
    pub max_idle_timeout_ms: u64,
    pub max_recv_udp_payload_size: usize,
    pub max_send_udp_payload_size: usize,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            max_idle_timeout_ms: 30000,
            max_recv_udp_payload_size: MAX_DATAGRAM_SIZE,
            max_send_udp_payload_size: MAX_DATAGRAM_SIZE,
            initial_max_data: 10_000_000,
            initial_max_stream_data_bidi_local: 1_000_000,
            initial_max_stream_data_bidi_remote: 1_000_000,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum Communication {
    PresenceAnnounce {
        peer_addr: String,
    },
    PresenceResponse {
        peer_addr: String,
    },
    FileAnnounce {
        file_id: String,
        file_name: String,
        file_size: u64,
    },
    FileAcknowledge {
        file_id: String,
        peer_addr: String,
    },
    FileList {
        peer_addr: String,
        files: Vec<(String, String, u64)>, // (file_id, file_name, file_size)
    },
    FileRequest {
        file_id: String,
        peer_addr: String,
    },
    FileResponse {
        file_id: String,
        available: bool,
        peer_addr: String,
    },
    FileChunk {
        file_id: String,
        chunk_index: u64,
        chunk_data: Vec<u8>,
        is_last: bool,
    },
    FileChunkAck {
        file_id: String,
        chunk_index: u64,
        peer_addr: String,
    },
    FileTransferComplete {
        file_id: String,
        peer_addr: String,
    },
    Error {
        message: String,
    },
}

impl Communication {
    fn serialize(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow!("Serialization error: {}", e))
    }

    fn deserialize(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| anyhow!("Deserialization error: {}", e))
    }
}

#[derive(Debug, Clone)]
struct FileInfo {
    id: String,
    name: String,
    size: u64,
    path: String,
}

struct PeerClient {
    conn: quiche::Connection,
    socket: std::net::UdpSocket,
    read_buf: [u8; 65535],
    scid: Vec<u8>,
    peer_addr: SocketAddr,
    stream_responses: HashMap<u64, Vec<u8>>,
    pending_requests: HashMap<u64, oneshot::Sender<Vec<u8>>>,
    request_counter: Arc<AtomicU64>,
    files: HashMap<String, FileInfo>,
    files_dir: String,
    local_addr: String,
}

impl PeerClient {
    fn new(
        server_addr: &str,
        files_dir: String,
        port: u16,
        server_cert: Option<String>,
        no_verify_tls: bool,
    ) -> Result<Self> {
        let server_url = if server_addr.starts_with("http") {
            Url::parse(server_addr)?
        } else {
            Url::parse(&format!("https://{}", server_addr))?
        };

        let peer_addr = server_url
            .socket_addrs(|| None)?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("No valid address found"))?;

        let bind_addr = match peer_addr {
            SocketAddr::V4(_) => format!("0.0.0.0:{}", port),
            SocketAddr::V6(_) => format!("[::]:{}", port),
        };

        let socket = std::net::UdpSocket::bind(bind_addr)?;
        socket.set_nonblocking(true)?;

        let mut quic_config = Self::create_quic_config(server_cert, no_verify_tls)?;
        // Generate a random source connection ID for the connection.
        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        SystemRandom::new().fill(&mut scid[..]).unwrap();

        let local_addr = socket.local_addr()?;

        let conn = quiche::connect(
            server_url.domain(),
            &quiche::ConnectionId::from_ref(&scid),
            local_addr,
            peer_addr,
            &mut quic_config,
        )?;

        let local_addr_str = format!("{}", local_addr);
        info!("{}:",hex::encode(&scid));
        Ok(Self {
            conn,
            socket,
            read_buf: [0; 65535],
            scid: scid.to_vec(),
            peer_addr,
            stream_responses: HashMap::new(),
            pending_requests: HashMap::new(),
            request_counter: Arc::new(AtomicU64::new(0)),
            files: HashMap::new(),
            files_dir,
            local_addr: local_addr_str,
        })
    }

    fn create_quic_config(
        server_cert: Option<String>,
        no_verify_tls: bool,
    ) -> Result<quiche::Config> {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
        let quic_config = QuicConfig::default();

        // Set application protocols (ALPN)
        config
            .set_application_protos(&[b"hq-interop", b"hq-29", b"hq-28", b"hq-27", b"http/0.9"])
            .unwrap();

        config.set_max_idle_timeout(quic_config.max_idle_timeout_ms);
        config.set_max_recv_udp_payload_size(quic_config.max_recv_udp_payload_size);
        config.set_max_send_udp_payload_size(quic_config.max_send_udp_payload_size);
        config.set_initial_max_data(quic_config.initial_max_data);
        config
            .set_initial_max_stream_data_bidi_local(quic_config.initial_max_stream_data_bidi_local);
        config.set_initial_max_stream_data_bidi_remote(
            quic_config.initial_max_stream_data_bidi_remote,
        );
        config.set_initial_max_streams_bidi(quic_config.initial_max_streams_bidi);
        config.set_initial_max_streams_uni(quic_config.initial_max_streams_uni);
        config.set_disable_active_migration(true);

        if no_verify_tls {
            // Disable peer verification (insecure, for development only)
            config.verify_peer(false);
            info!("TLS certificate verification disabled - this is insecure!");
        } else {
            if let Some(cert_path) = server_cert {
                // Load the server certificate for verification
                config.load_verify_locations_from_file(&cert_path)?;
                info!("Using server certificate: {}", cert_path);
            }
            // Always enable peer verification when not explicitly disabled
            config.verify_peer(true);
        }

        Ok(config)
    }

    fn scan_files(&mut self) -> Result<()> {
        self.files.clear();

        if !Path::new(&self.files_dir).exists() {
            fs::create_dir_all(&self.files_dir)?;
            return Ok(());
        }

        for entry in fs::read_dir(&self.files_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                let metadata = fs::metadata(&path)?;
                let file_name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();

                let file_id = format!("{}-{}", self.local_addr, file_name);
                let file_info = FileInfo {
                    id: file_id.clone(),
                    name: file_name,
                    size: metadata.len(),
                    path: path.to_string_lossy().to_string(),
                };

                self.files.insert(file_id, file_info);
            }
        }

        info!("Scanned {} files from {}", self.files.len(), self.files_dir);
        Ok(())
    }

    async fn wait_for_connection(&mut self) -> Result<()> {
        let start_time = Instant::now();

        info!("Establishing QUIC connection...");

        // Trigger initial handshake by processing events first
        self.process_events()?;

        while !self.conn.is_established() {
            if start_time.elapsed() >= CONNECTION_TIMEOUT {
                return Err(anyhow!("Connection timeout"));
            }

            self.process_events()?;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        info!("QUIC connection established");
        Ok(())
    }

    fn process_events(&mut self) -> Result<()> {
        // Send outgoing packets first (important for initial handshake)
        let mut write_buf = [0; MAX_DATAGRAM_SIZE];
        loop {
            let (write, send_info) = match self.conn.send(&mut write_buf) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    debug!("Send error: {:?}", e);
                    return Err(anyhow!("Send error: {:?}", e));
                }
            };

            debug!("Sending {} bytes to {}", write, send_info.to);
            self.socket.send_to(&write_buf[..write], send_info.to)?;
        }

        // Read incoming packets
        loop {
            let (len, from) = match self.socket.recv_from(&mut self.read_buf) {
                Ok(v) => v,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(anyhow!("Receive error: {}", e)),
            };

            debug!("Received {} bytes from {}", len, from);

            let recv_info = quiche::RecvInfo {
                to: self.socket.local_addr()?,
                from,
            };

            if let Err(e) = self.conn.recv(&mut self.read_buf[..len], recv_info) {
                warn!("Failed to process packet: {:?}", e);
                continue;
            }
        }

        // Read streams
        for stream_id in self.conn.readable() {
            let mut temp_buf = [0; 65535];
            while let Ok((read, fin)) = self.conn.stream_recv(stream_id, &mut temp_buf) {
                let data = &temp_buf[..read];

                self.stream_responses
                    .entry(stream_id)
                    .or_insert_with(Vec::new)
                    .extend_from_slice(data);

                if fin {
                    if let Some(response_data) = self.stream_responses.remove(&stream_id) {
                        // Check if this is a response to a pending request
                        if let Some(sender) = self.pending_requests.remove(&stream_id) {
                            let _ = sender.send(response_data);
                        } else {
                            // This is an incoming request from the server
                            self.handle_incoming_request(stream_id, &response_data)?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_incoming_request(&mut self, stream_id: u64, data: &[u8]) -> Result<()> {
        let communication = Communication::deserialize(data)?;
        debug!("Received request: {:?}", communication);

        let response = match communication {
            Communication::FileRequest { file_id, peer_addr } => {
                info!("Received file request for {} from {}", file_id, peer_addr);

                if let Some(file_info) = self.files.get(&file_id).cloned() {
                    // Start file transfer
                    match self.send_file_response(stream_id, &file_info) {
                        Ok(_) => return Ok(()), // File transfer handled separately
                        Err(e) => {
                            error!("Failed to send file: {}", e);
                            Communication::Error {
                                message: format!("Failed to send file: {}", e),
                            }
                        }
                    }
                } else {
                    Communication::FileResponse {
                        file_id,
                        available: false,
                        peer_addr: self.local_addr.clone(),
                    }
                }
            }
            Communication::FileList { peer_addr, .. } => {
                info!("Received file list request from {}", peer_addr);
                let files: Vec<(String, String, u64)> = self
                    .files
                    .values()
                    .map(|f| (f.id.clone(), f.name.clone(), f.size))
                    .collect();

                Communication::FileList {
                    peer_addr: self.local_addr.clone(),
                    files,
                }
            }
            _ => {
                warn!("Unhandled incoming request: {:?}", communication);
                Communication::Error {
                    message: "Unhandled request type".to_string(),
                }
            }
        };

        self.send_response(stream_id, &response)?;
        Ok(())
    }

    fn send_file_response(&mut self, stream_id: u64, file_info: &FileInfo) -> Result<()> {
        info!("Starting file transfer for: {}", file_info.name);

        let file_data = fs::read(&file_info.path)?;
        let total_chunks = (file_data.len() + FILE_CHUNK_SIZE - 1) / FILE_CHUNK_SIZE;

        for (chunk_index, chunk) in file_data.chunks(FILE_CHUNK_SIZE).enumerate() {
            let is_last = chunk_index == total_chunks - 1;

            let chunk_msg = Communication::FileChunk {
                file_id: file_info.id.clone(),
                chunk_index: chunk_index as u64,
                chunk_data: chunk.to_vec(),
                is_last,
            };

            self.send_response(stream_id, &chunk_msg)?;
        }

        info!("File transfer completed for: {}", file_info.name);
        Ok(())
    }

    fn send_response(&mut self, stream_id: u64, communication: &Communication) -> Result<()> {
        let data = communication.serialize()?;
        self.conn.stream_send(stream_id, &data, true)?;
        Ok(())
    }

    async fn send_request(&mut self, communication: &Communication) -> Result<Vec<u8>> {
        let stream_id = self.conn.stream_send(
            self.request_counter.fetch_add(1, Ordering::Relaxed),
            &communication.serialize()?,
            true,
        )? as u64;

        let (tx, rx) = oneshot::channel();
        self.pending_requests.insert(stream_id, tx);

        self.process_events()?;

        match timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(anyhow!("Request channel closed")),
            Err(_) => Err(anyhow!("Request timeout")),
        }
    }

    async fn announce_presence(&mut self) -> Result<()> {
        info!("Announcing presence to server...");
        let msg = Communication::PresenceAnnounce {
            peer_addr: self.local_addr.clone(),
        };

        self.send_request(&msg).await?;
        info!("Presence announced successfully");
        Ok(())
    }

    async fn announce_files(&mut self) -> Result<()> {
        info!("Announcing files to server...");

        let file_list: Vec<(String, String, u64)> = self
            .files
            .values()
            .map(|f| (f.id.clone(), f.name.clone(), f.size))
            .collect();

        for (file_id, file_name, file_size) in file_list {
            let msg = Communication::FileAnnounce {
                file_id,
                file_name,
                file_size,
            };

            self.send_request(&msg).await?;
        }

        info!("All files announced successfully");
        Ok(())
    }

    async fn run(&mut self) -> Result<()> {
        self.scan_files()?;
        self.wait_for_connection().await?;
        self.announce_presence().await?;
        self.announce_files().await?;

        info!("Peer is running and listening for requests...");

        loop {
            self.process_events()?;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

struct Client {
    conn: quiche::Connection,
    partial_responses: HashMap<u64, Vec<u8>>,
}

type ClientMap = HashMap<Vec<u8>, Client>;

struct Server {
    socket: std::net::UdpSocket,
    clients: ClientMap,
    read_buf: [u8; 65535],
    out_buf: [u8; 1350],
    config: quiche::Config,
    peers: HashMap<String, Vec<(String, String, u64)>>, // peer_addr -> files
    files_dir: String,
    conn_id_seed: ring::hmac::Key,
}

impl Server {
    fn new(addr: &str, cert_path: &str, key_path: &str, files_dir: String) -> Result<Self> {
        let socket = std::net::UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;

        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
        let quic_config = QuicConfig::default();

        // Set application protocols (ALPN)
        config.set_application_protos(&[
            b"hq-interop", b"hq-29", b"hq-28", b"hq-27", b"http/0.9"
        ])?;

        config.set_max_idle_timeout(quic_config.max_idle_timeout_ms);
        config.set_max_recv_udp_payload_size(quic_config.max_recv_udp_payload_size);
        config.set_max_send_udp_payload_size(quic_config.max_send_udp_payload_size);
        config.set_initial_max_data(quic_config.initial_max_data);
        config
            .set_initial_max_stream_data_bidi_local(quic_config.initial_max_stream_data_bidi_local);
        config.set_initial_max_stream_data_bidi_remote(
            quic_config.initial_max_stream_data_bidi_remote,
        );
        config.set_initial_max_streams_bidi(quic_config.initial_max_streams_bidi);
        config.set_initial_max_streams_uni(quic_config.initial_max_streams_uni);
        config.verify_peer(false);
        config.load_cert_chain_from_pem_file(cert_path)?;
        config.load_priv_key_from_pem_file(key_path)?;
        config.enable_early_data();

        if !Path::new(&files_dir).exists() {
            fs::create_dir_all(&files_dir)?;
        }

        // Generate connection ID seed for HMAC
        let rng = SystemRandom::new();
        let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng)
            .map_err(|_| anyhow!("Failed to generate connection ID seed"))?;

        Ok(Self {
            socket,
            clients: HashMap::new(),
            read_buf: [0; 65535],
            out_buf: [0; 1350],
            config,
            peers: HashMap::new(),
            files_dir,
            conn_id_seed,
        })
    }

    fn run(&mut self) -> Result<()> {
        info!("Server starting...");
        let local_addr = self.socket.local_addr()?;

        loop {
            // Read incoming UDP packets from the socket and feed them to quiche
            loop {
                let (len, from) = match self.socket.recv_from(&mut self.read_buf) {
                    Ok(v) => v,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(anyhow!("Receive error: {}", e)),
                };

                debug!("Server received {} bytes from {}", len, from);

                let pkt_buf = &mut self.read_buf[..len];

                // Parse the QUIC packet's header
                let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("Parsing packet header failed: {:?}", e);
                        continue;
                    }
                };

                debug!("Got packet {:?}", hdr);

                // Generate a connection ID based on the packet's DCID
                let conn_id = ring::hmac::sign(&self.conn_id_seed, &hdr.dcid);
                let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
                let conn_id = conn_id.to_vec();

                // Lookup a connection based on the packet's connection ID
                let client = if !self.clients.contains_key(&hdr.dcid.to_vec()) &&
                    !self.clients.contains_key(&conn_id)
                {
                    if hdr.ty != quiche::Type::Initial {
                        error!("Packet is not Initial");
                        continue;
                    }

                    if !quiche::version_is_supported(hdr.version) {
                        warn!("Doing version negotiation");

                        let len = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut self.out_buf)
                            .map_err(|e| anyhow!("Version negotiation failed: {:?}", e))?;

                        let out = &self.out_buf[..len];

                        if let Err(e) = self.socket.send_to(out, from) {
                            if e.kind() != io::ErrorKind::WouldBlock {
                                return Err(anyhow!("Send failed: {:?}", e));
                            }
                        }
                        continue;
                    }

                    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                    scid.copy_from_slice(&conn_id);
                    let scid = quiche::ConnectionId::from_ref(&scid);

                    // Token is always present in Initial packets
                    let token = hdr.token.as_ref().unwrap();

                    // Do stateless retry if the client didn't send a token
                    if token.is_empty() {
                        warn!("Doing stateless retry");

                        let new_token = mint_token(&hdr, &from);

                        let len = quiche::retry(
                            &hdr.scid,
                            &hdr.dcid,
                            &scid,
                            &new_token,
                            hdr.version,
                            &mut self.out_buf,
                        )
                        .map_err(|e| anyhow!("Retry failed: {:?}", e))?;

                        let out = &self.out_buf[..len];

                        if let Err(e) = self.socket.send_to(out, from) {
                            if e.kind() != io::ErrorKind::WouldBlock {
                                return Err(anyhow!("Send failed: {:?}", e));
                            }
                        }
                        continue;
                    }

                    let odcid = validate_token(&from, token);

                    // The token was not valid, meaning the retry failed
                    if odcid.is_none() {
                        error!("Invalid address validation token");
                        continue;
                    }

                    if scid.len() != hdr.dcid.len() {
                        error!("Invalid destination connection ID");
                        continue;
                    }

                    // Reuse the source connection ID we sent in the Retry packet
                    let scid = hdr.dcid.clone();

                    debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                    let conn = quiche::accept(
                        &scid,
                        odcid.as_ref().map(|v| quiche::ConnectionId::from_ref(v)).as_ref(),
                        local_addr,
                        from,
                        &mut self.config,
                    )
                    .map_err(|e| anyhow!("Connection accept failed: {:?}", e))?;

                    let client = Client {
                        conn,
                        partial_responses: HashMap::new(),
                    };

                    self.clients.insert(scid.to_vec(), client);
                    info!("New connection from {}", from);

                    self.clients.get_mut(&scid.to_vec()).unwrap()
                } else {
                    match self.clients.get_mut(&hdr.dcid.to_vec()) {
                        Some(v) => v,
                        None => self.clients.get_mut(&conn_id).unwrap(),
                    }
                };

                let recv_info = quiche::RecvInfo {
                    to: local_addr,
                    from,
                };

                // Process potentially coalesced packets
                let read = match client.conn.recv(pkt_buf, recv_info) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                        continue;
                    }
                };

                debug!("{} processed {} bytes", client.conn.trace_id(), read);

                if client.conn.is_in_early_data() || client.conn.is_established() {
                    // Process all readable streams
                    for stream_id in client.conn.readable() {
                        let mut response_data = Vec::new();
                        let mut temp_buf = [0; 65535];

                        loop {
                            match client.conn.stream_recv(stream_id, &mut temp_buf) {
                                Ok((read, fin)) => {
                                    response_data.extend_from_slice(&temp_buf[..read]);
                                    if fin {
                                        break;
                                    }
                                }
                                Err(quiche::Error::Done) => break,
                                Err(e) => {
                                    warn!("Stream recv error: {:?}", e);
                                    break;
                                }
                            }
                        }

                        if !response_data.is_empty() {
                            if let Ok(communication) = Communication::deserialize(&response_data) {
                                debug!("Received from peer: {:?}", communication);
                                
                                match communication {
                                    Communication::PresenceAnnounce { peer_addr } => {
                                        info!("Peer {} announced presence", peer_addr);
                                        // Note: We can't modify self.peers here due to borrow checker
                                        // This would need to be handled after the loop
                                        
                                        let response = Communication::PresenceResponse { peer_addr };
                                        if let Ok(data) = response.serialize() {
                                            let _ = client.conn.stream_send(stream_id, &data, true);
                                        }
                                    }
                                    Communication::FileAnnounce { file_id, file_name, file_size } => {
                                        info!("File announced: {} ({} bytes)", file_name, file_size);
                                        
                                        let response = Communication::FileAcknowledge {
                                            file_id,
                                            peer_addr: "server".to_string(),
                                        };
                                        if let Ok(data) = response.serialize() {
                                            let _ = client.conn.stream_send(stream_id, &data, true);
                                        }
                                    }
                                    _ => {
                                        warn!("Unhandled message type: {:?}", communication);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Generate outgoing QUIC packets for all active connections
            for client in self.clients.values_mut() {
                loop {
                    let (write, send_info) = match client.conn.send(&mut self.out_buf) {
                        Ok(v) => v,
                        Err(quiche::Error::Done) => {
                           
                            break;
                        }
                        Err(e) => {
                            error!("{} send failed: {:?}", client.conn.trace_id(), e);
                            client.conn.close(false, 0x1, b"fail").ok();
                            break;
                        }
                    };

                    if let Err(e) = self.socket.send_to(&self.out_buf[..write], send_info.to) {
                        if e.kind() != io::ErrorKind::WouldBlock {
                            return Err(anyhow!("Send failed: {:?}", e));
                        }
                        break;
                    }

                    debug!("{} written {} bytes", client.conn.trace_id(), write);
                }
            }

            // Garbage collect closed connections
            self.clients.retain(|_, client| {
                if client.conn.is_closed() {
                    info!("{} connection collected {:?}", client.conn.trace_id(), client.conn.stats());
                }
                !client.conn.is_closed()
            });

            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn process_connection(&mut self, conn: &mut quiche::Connection) -> Result<()> {
        for stream_id in conn.readable() {
            let mut response_data = Vec::new();
            let mut temp_buf = [0; 65535];

            loop {
                match conn.stream_recv(stream_id, &mut temp_buf) {
                    Ok((read, fin)) => {
                        response_data.extend_from_slice(&temp_buf[..read]);
                        if fin {
                            break;
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        warn!("Stream recv error: {:?}", e);
                        break;
                    }
                }
            }

            if !response_data.is_empty() {
                self.handle_peer_message(conn, stream_id, &response_data)?;
            }
        }

        Ok(())
    }

    fn handle_peer_message(
        &mut self,
        conn: &mut quiche::Connection,
        stream_id: u64,
        data: &[u8],
    ) -> Result<()> {
        let communication = Communication::deserialize(data)?;
        debug!("Received from peer: {:?}", communication);

        match communication {
            Communication::PresenceAnnounce { peer_addr } => {
                info!("Peer {} announced presence", peer_addr);
                self.peers.entry(peer_addr.clone()).or_insert_with(Vec::new);

                let response = Communication::PresenceResponse { peer_addr };
                self.send_response(conn, stream_id, &response)?;
            }
            Communication::FileAnnounce {
                file_id,
                file_name,
                file_size,
            } => {
                info!("File announced: {} ({} bytes)", file_name, file_size);

                let response = Communication::FileAcknowledge {
                    file_id,
                    peer_addr: "server".to_string(),
                };
                self.send_response(conn, stream_id, &response)?;
            }
            _ => {
                warn!("Unhandled message type: {:?}", communication);
            }
        }

        Ok(())
    }

    fn send_response(
        &self,
        conn: &mut quiche::Connection,
        stream_id: u64,
        communication: &Communication,
    ) -> Result<()> {
        let data = communication.serialize()?;
        conn.stream_send(stream_id, &data, true)?;
        Ok(())
    }
}

async fn start_peer(
    server_addr: String,
    files_dir: String,
    port: u16,
    server_cert: Option<String>,
    no_verify_tls: bool,
) -> Result<()> {
    let mut peer = PeerClient::new(&server_addr, files_dir, port, server_cert, no_verify_tls)?;
    peer.run().await
}

fn start_server(
    addr: String,
    cert_path: String,
    key_path: String,
    files_dir: String,
) -> Result<()> {
    let mut server = Server::new(&addr, &cert_path, &key_path, files_dir)?;
    server.run()
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let cmd = Command::parse();

    match cmd.subcommand {
        SubCommands::Peer {
            server_addr,
            files_dir,
            port,
            server_cert,
            no_verify_tls,
        } => {
            info!("Starting peer, connecting to server: {}", server_addr);
            start_peer(server_addr, files_dir, port, server_cert, no_verify_tls).await
        }
        SubCommands::Server {
            addr,
            key,
            cert,
            files_dir,
        } => {
            info!("Starting server on: {}", addr);
            start_server(addr, cert, key, files_dir)
        }
    }
}

// Token validation and connection ID management functions
fn mint_token(hdr: &quiche::Header, src: &SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();
    token.extend_from_slice(b"quiche");
    // Add the length of DCID first, then the DCID itself
    token.push(hdr.dcid.len() as u8);
    token.extend_from_slice(&hdr.dcid);
    token.extend_from_slice(&src.ip().to_string().as_bytes());
    token.extend_from_slice(&src.port().to_be_bytes());
    token
}

fn validate_token(src: &SocketAddr, token: &[u8]) -> Option<Vec<u8>> {
    if token.len() < 7 {  // "quiche" (6) + dcid_len (1) 
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let dcid_len = token[6] as usize;
    if token.len() < 7 + dcid_len {
        return None;
    }

    // Extract the original DCID
    let dcid = &token[7..7 + dcid_len];
    
    // The rest should contain IP address and port
    let addr_port_data = &token[7 + dcid_len..];
    
    // Parse the IP address part (everything except the last 2 bytes which are the port)
    if addr_port_data.len() < 2 {
        return None;
    }
    
    let ip_data = &addr_port_data[..addr_port_data.len() - 2];
    let stored_ip = std::str::from_utf8(ip_data).ok()?;
    
    // Verify the IP address matches
    if stored_ip != src.ip().to_string() {
        return None;
    }
    
    // Extract and verify the port
    let port_bytes = &addr_port_data[addr_port_data.len() - 2..];
    let stored_port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
    
    if stored_port != src.port() {
        return None;
    }

    // Return the original DCID
    Some(dcid.to_vec())
}
