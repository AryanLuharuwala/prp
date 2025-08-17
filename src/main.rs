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
use log::{debug, error, info, warn};
use ring::rand::{SystemRandom,SecureRandom};
use serde::{Deserialize, Serialize};

use tokio::sync::oneshot;
use tokio::io::{self as tokio_io, AsyncBufReadExt, AsyncWriteExt, BufReader};
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


/// Communication protocol enum that defines all message types exchanged between peers.
/// Each request type has a corresponding response type for clear request/response mapping.
/// 
/// ## Request/Response Pairs:
/// - `PresenceAnnounce` → `PresenceResponse` 
/// - `FileAnnounce` → `FileAnnounceResponse` (FileAcknowledge)
/// - `FileRequest` → `FileResponse`
/// - `FileChunk` → `FileChunkAck`
/// 
/// ## Adding New Communication Types:
/// 1. Add the request variant with a descriptive name ending in "Request" or describing the action
/// 2. Add the corresponding response variant ending in "Response" or "Ack"
/// 3. Update the appropriate handler in the MessageHandler implementations
/// 4. Ensure serialization/deserialization works by testing both directions
///
/// ## Example:
/// ```rust
/// // New request type
/// NewFeatureRequest {
///     param1: String,
///     param2: u64,
/// },
/// // Corresponding response type  
/// NewFeatureResponse {
///     success: bool,
///     result_data: Vec<u8>,
/// },
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
enum Communication {
    // === PRESENCE COMMUNICATION ===
    /// Request: Announce this peer's presence to the network
    PresenceAnnounce {
        peer_addr: String,
    },
    /// Response: Acknowledge presence announcement
    PresenceResponse {
        peer_addr: String,
    },

    // === FILE ANNOUNCEMENT COMMUNICATION ===
    /// Request: Announce that this peer has a file available
    FileAnnounce {
        file_id: String,
        file_name: String,
        file_size: u64,
    },
    /// Response: Acknowledge file announcement (also serves as FileAnnounceResponse)
    FileAcknowledge {
        file_id: String,
        peer_addr: String,
    },

    // === FILE DISCOVERY COMMUNICATION ===
    /// Response: List of files available from a peer (sent in response to discovery)
    FileList {
        peer_addr: String,
        files: Vec<(String, String, u64)>, // (file_id, file_name, file_size)
    },

    // === FILE TRANSFER COMMUNICATION ===
    /// Request: Request a specific file from a peer
    FileRequest {
        file_id: String,
        peer_addr: String,
    },
    /// Response: Indicate whether the requested file is available
    FileResponse {
        file_id: String,
        available: bool,
        peer_addr: String,
    },

    // === FILE GET COMMUNICATION ===
    /// Request: Get (download) a specific file from a peer
    FileGet {
        file_id: String,
        peer_addr: String,
    },
    /// Response: Return the requested file data or error
    FileGetResponse {
        file_id: String,
        success: bool,
        file_data: Option<Vec<u8>>,
        error_message: Option<String>,
        peer_addr: String,
    },

    // === FILE CHUNK TRANSFER COMMUNICATION ===
    /// Request/Data: Send a chunk of file data
    FileChunk {
        file_id: String,
        chunk_index: u64,
        chunk_data: Vec<u8>,
        is_last: bool,
    },
    /// Response: Acknowledge receipt of a file chunk
    FileChunkAck {
        file_id: String,
        chunk_index: u64,
        peer_addr: String,
    },

    // === FILE TRANSFER COMPLETION ===
    /// Notification: File transfer completed successfully
    FileTransferComplete {
        file_id: String,
        peer_addr: String,
    },

    // === ERROR HANDLING ===
    /// Error response: Generic error message for any failed operation
    Error {
        message: String,
    },
}

impl Communication {
    fn serialize(&self) -> Result<Vec<u8>> {
        bincode::encode_to_vec(self, bincode::config::standard()).map_err(|e| anyhow!("Serialization error: {}", e))
    }

    fn deserialize(data: &[u8]) -> Result<Self> {
        let (result, _): (Self, usize) = bincode::decode_from_slice(data, bincode::config::standard()).map_err(|e| anyhow!("Deserialization error: {}", e))?;
        Ok(result)
    }
}



/// Message handler trait for processing different types of communication messages.
/// Each handler is responsible for a specific category of messages (e.g., presence, files).
/// 
/// ## Handler Architecture:
/// - Handlers are stateless and operate on the provided context
/// - Each handler should focus on a single concern (Single Responsibility Principle)
/// - Handlers return `None` for messages they don't handle, allowing other handlers to process them
/// - Handlers return `Some(response)` when they handle a message and want to send a response
/// 
/// ## Creating New Handlers:
/// 1. Implement the `MessageHandler` trait
/// 2. Add the handler to the `MessageRouter` in `new()` method
/// 3. Handle relevant request types and return appropriate responses
/// 
/// ## Example Handler:
/// ```rust
/// struct MyNewHandler;
/// 
/// impl MessageHandler for MyNewHandler {
///     fn handle_peer_request(&mut self, message: &Communication, context: &mut HandlerContext) -> Result<Option<Communication>> {
///         match message {
///             Communication::MyNewRequest { param } => {
///                 // Process the request
///                 Ok(Some(Communication::MyNewResponse { result: "processed".to_string() }))
///             }
///             _ => Ok(None) // Don't handle other message types
///         }
///     }
///     fn handle_server_side(&mut self, message: &Communication, context: &mut HandlerContext) -> Result<Option<Communication>> {
///         match message {
///             Communication::MyNewRequest { param } => {
///                 // Process the request
///                 Ok(Some(Communication::MyNewResponse { result: "processed".to_string() }))
///             }
///             _ => Ok(None) // Don't handle other message types
///         }
///     }
/// }
/// ```


trait MessageHandler {
    fn handle_peer_request(&mut self, message: &Communication, context: &mut HandlerContext) -> Result<Option<Communication>>;
    fn handle_server_request(&mut self, message: &Communication, context: &mut HandlerContext) -> Result<Option<Communication>>;
}

/// Context passed to handlers containing transport and session information.
/// This provides handlers with access to peer state and configuration.
pub struct HandlerContext {
    pub local_addr: String,
    pub files: HashMap<String, FileInfo>,
    pub files_dir: String,
}


// Handler for presence announcements
struct PresenceHandler;

impl MessageHandler for PresenceHandler {
    fn handle_peer_request(&mut self, message: &Communication, context: &mut HandlerContext) -> Result<Option<Communication>> {
        match message {
            Communication::PresenceAnnounce { peer_addr } => {
                info!("Peer {} announced presence", peer_addr);
                Ok(Some(Communication::PresenceResponse {
                    peer_addr: context.local_addr.clone(),
                }))
            }
            _ => Ok(None)
        }
    }
    fn handle_server_request(&mut self, message: &Communication, context: &mut HandlerContext) -> Result<Option<Communication>> {
        match message {
            Communication::PresenceAnnounce { peer_addr } => {
                info!("Server received presence announcement from {}", peer_addr);
                Ok(Some(Communication::PresenceResponse {
                    peer_addr: context.local_addr.clone(),
                }))
            }
            _ => Ok(None)
        }
    }
}

// Handler for file announcements and requests
struct FileHandler;

impl MessageHandler for FileHandler {
    fn handle_peer_request(&mut self, message: &Communication, context: &mut HandlerContext) -> Result<Option<Communication>> {
        match message {
            Communication::FileAnnounce { file_id, file_name, file_size } => {
                info!("File announced: {} ({} bytes)", file_name, file_size);
                Ok(Some(Communication::FileAcknowledge {
                    file_id: file_id.clone(),
                    peer_addr: context.local_addr.clone(),
                }))
            }
            Communication::FileRequest { file_id, peer_addr } => {
                info!("Received file request for {} from {}", file_id, peer_addr);
                
                if context.files.contains_key(file_id) {
                    // TODO: Implement actual file transfer using chunks
                    Ok(Some(Communication::FileResponse {
                        file_id: file_id.clone(),
                        available: true,
                        peer_addr: context.local_addr.clone(),
                    }))
                } else {
                    Ok(Some(Communication::FileResponse {
                        file_id: file_id.clone(),
                        available: false,
                        peer_addr: context.local_addr.clone(),
                    }))
                }
            }
            Communication::FileList { peer_addr, .. } => {
                info!("Received file list request from {}", peer_addr);
                let files: Vec<(String, String, u64)> = context.files
                    .values()
                    .map(|f| (f.id.clone(), f.name.clone(), f.size))
                    .collect();

                Ok(Some(Communication::FileList {
                    peer_addr: context.local_addr.clone(),
                    files,
                }))
            }
            Communication::FileGet { file_id, peer_addr } => {
                info!("Received file get request for {} from {}", file_id, peer_addr);
                
                if let Some(file_info) = context.files.get(file_id) {
                    // Read the actual file data
                    match fs::read(&file_info.path) {
                        Ok(file_data) => Ok(Some(Communication::FileGetResponse {
                            file_id: file_id.clone(),
                            success: true,
                            file_data: Some(file_data),
                            error_message: None,
                            peer_addr: context.local_addr.clone(),
                        })),
                        Err(e) => Ok(Some(Communication::FileGetResponse {
                            file_id: file_id.clone(),
                            success: false,
                            file_data: None,
                            error_message: Some(format!("Failed to read file: {}", e)),
                            peer_addr: context.local_addr.clone(),
                        }))
                    }
                } else {
                    Ok(Some(Communication::FileGetResponse {
                        file_id: file_id.clone(),
                        success: false,
                        file_data: None,
                        error_message: Some("File not found".to_string()),
                        peer_addr: context.local_addr.clone(),
                    }))
                }
            }
            _ => Ok(None)
        }
    }
    fn handle_server_request(&mut self, message: &Communication, context: &mut HandlerContext) -> Result<Option<Communication>> {
        // For server-side file handling, we can reuse the same logic as client-side
        self.handle_peer_request(message, context)
    }
}

// Handler for peer lifecycle management including file scanning and announcements
struct PeerLifecycleHandler;

impl MessageHandler for PeerLifecycleHandler {
    fn handle_peer_request(&mut self, _message: &Communication, _context: &mut HandlerContext) -> Result<Option<Communication>> {
        // This handler doesn't handle incoming requests, it's used for utility functions
        // Other handlers handle the actual incoming requests
        Ok(None)
    }
    fn handle_server_request(&mut self, message: &Communication, context: &mut HandlerContext) -> Result<Option<Communication>> {
        match message {
            Communication::PresenceAnnounce { peer_addr } => {
                info!("Server received presence announcement from {}", peer_addr);
                // Scan files and announce them
                Self::scan_files(context)?;
                let announcements = Self::get_file_announcements(context);
                Ok(Some(Communication::FileList {
                    peer_addr: context.local_addr.clone(),
                    files: announcements.into_iter().map(|f| {
                        match f {
                            Communication::FileAnnounce { file_id, file_name, file_size } => (file_id, file_name, file_size),
                            _ => unreachable!(), // get_file_announcements only returns FileAnnounce variants
                        }
                    }).collect(),
                }))
            }
            _ => Ok(None)
        }
    }
}

impl PeerLifecycleHandler {
    /// Scan files in the peer's directory and update the context
    pub fn scan_files(context: &mut HandlerContext) -> Result<()> {
        context.files.clear();

        if context.files_dir.is_empty() {
            return Ok(());
        }

        if !Path::new(&context.files_dir).exists() {
            fs::create_dir_all(&context.files_dir)?;
            return Ok(());
        }

        for entry in fs::read_dir(&context.files_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                let metadata = fs::metadata(&path)?;
                let file_name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();

                let file_id = format!("{}-{}", context.local_addr, file_name);
                let file_info = FileInfo {
                    id: file_id.clone(),
                    name: file_name,
                    size: metadata.len(),
                    path: path.to_string_lossy().to_string(),
                };

                context.files.insert(file_id, file_info);
            }
        }

        info!("Scanned {} files from {}", context.files.len(), context.files_dir);
        Ok(())
    }

    /// Generate file announcement messages for all scanned files
    fn get_file_announcements(context: &HandlerContext) -> Vec<Communication> {
        context.files
            .values()
            .map(|f| Communication::FileAnnounce {
                file_id: f.id.clone(),
                file_name: f.name.clone(),
                file_size: f.size,
            })
            .collect()
    }
}

pub struct MessageRouter {
    handlers: Vec<Box<dyn MessageHandler>>,
}

/// Configure a MessageRouter with all the standard handlers
/// This function adds all the necessary handlers to the router in the correct order
fn configure_router(router: &mut MessageRouter) {
    // Add handlers in order of priority/specificity
    router.add_handlers(PresenceHandler);
    router.add_handlers(FileHandler);
    router.add_handlers(PeerLifecycleHandler);
}

/// Message router that delegates incoming messages to appropriate handlers.
/// The router tries each handler in sequence until one handles the message.
/// 
/// ## Router Pattern:
/// - Handlers are processed in the order they were added
/// - First handler that returns `Some(response)` wins
/// - If no handler processes the message, an error response is sent
/// 
/// ## Adding New Handlers:
/// Add new handlers by adding them as fields and calling their handle_peer_request method
/// in the handle_message method. For a more extensible approach, consider using
/// a Vec<Box<dyn MessageHandler>> pattern.

impl MessageRouter {
    fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }
    fn add_handlers<H: MessageHandler + 'static>(&mut self, handler: H) {
        self.handlers.push(Box::new(handler));
    }


    fn handle_peer_message(
        &mut self,
        message: &Communication,
        context: &mut HandlerContext,
    ) -> Result<Option<Communication>> {
        for handler in &mut self.handlers {
            if let Some(response) = handler.handle_peer_request(message, context)? {
                return Ok(Some(response));
            }
        }
        warn!("No handler found for message: {:?}", message);
        Ok(Some(Communication::Error {
            message: "Unhandled message type".to_string(),
        }))
    }

    fn handle_server_side(
        &mut self,
        message: &Communication,
        context: &mut HandlerContext,
    ) -> Result<Option<Communication>> {
        for handler in &mut self.handlers {
            if let Some(response) = handler.handle_server_request(message, context)? {
                return Ok(Some(response));
            }
        }
        warn!("No handler found for server message: {:?}", message);
        Ok(Some(Communication::Error {
            message: "Unhandled server message type".to_string(),
        }))
    }
}




// Transport layer abstraction for QUIC communication
pub struct QuicTransport {
    conn: quiche::Connection,
    socket: std::net::UdpSocket,
    read_buf: [u8; 65535],
    stream_responses: HashMap<u64, Vec<u8>>,
    pending_requests: HashMap<u64, oneshot::Sender<Vec<u8>>>,
    request_counter: Arc<AtomicU64>,
}

impl QuicTransport {
    fn new(conn: quiche::Connection, socket: std::net::UdpSocket) -> Self {
        Self {
            conn,
            socket,
            read_buf: [0; 65535],
            stream_responses: HashMap::new(),
            pending_requests: HashMap::new(),
            request_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    fn process_events(&mut self) -> Result<Vec<(u64, Vec<u8>)>> {
        // Handle ip changes
        if !self.is_established() && self.conn.local_error().is_some() {
            let bind_addr = std::net::SocketAddr::new(
                self.socket.local_addr()?.ip(),
                self.socket.local_addr()?.port(),
            );
            debug!("Rebinding socket to {}", bind_addr);
            self.socket = std::net::UdpSocket::bind(bind_addr)?;
            self.conn.migrate_source(bind_addr)?;
            debug!("Socket rebound to {}", bind_addr);
        }

        let mut incoming_messages = Vec::new();

        // Send outgoing packets first
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

        // Read streams and collect complete messages
        for stream_id in self.conn.readable() {
            debug!("Stream {} is readable", stream_id);
            let mut temp_buf = [0; 65535];
            while let Ok((read, fin)) = self.conn.stream_recv(stream_id, &mut temp_buf) {
                let data = &temp_buf[..read];
                debug!("Received {} bytes on stream {}", read, stream_id);
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
                            // This is an incoming request
                            incoming_messages.push((stream_id, response_data));
                        }
                    }
                }
            }
        }

        Ok(incoming_messages)
    }

    async fn send_request(&mut self, message: &Communication) -> Result<Vec<u8>> {
        // Generate client-initiated bidirectional stream ID
        let stream_id = self.request_counter.fetch_add(4, Ordering::Relaxed) * 4;
        self.conn.stream_send(
            stream_id,
            &message.serialize()?,
            true,
        )?;

        let (tx, mut rx) = oneshot::channel();
        self.pending_requests.insert(stream_id, tx);

        // Process events initially to send the request
        self.process_events()?;

        // Keep processing events while waiting for response
        let start_time = Instant::now();
        loop {
            // Process any incoming events
            self.process_events()?;
            
            // Check if we have a response (non-blocking check)
            match rx.try_recv() {
                Ok(response) => {
                    debug!("Received response: {} bytes", response.len());
                    return Ok(response);
                }
                Err(oneshot::error::TryRecvError::Empty) => {
                    // No response yet, continue waiting
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    return Err(anyhow!("Request channel closed"));
                }
            }
            
            // Check for timeout
            if start_time.elapsed() >= REQUEST_TIMEOUT {
                return Err(anyhow!("Request timeout"));
            }
            
            // Small delay to avoid busy waiting
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn send_response(&mut self, stream_id: u64, message: &Communication) -> Result<()> {
        let data = message.serialize()?;
        self.conn.stream_send(stream_id, &data, true)?;
        Ok(())
    }

    fn is_established(&self) -> bool {
        self.conn.is_established()
    }
}



/// The main peer client using the handler-based architecture.
/// 
/// This struct delegates all message handling to the MessageRouter, which in turn
/// uses specialized handlers for different types of communication.
/// 
/// ## Architecture:
/// - `transport`: Handles QUIC communication
/// - `router`: Routes messages to appropriate handlers  
/// - `context`: Shared state accessible by all handlers
pub struct PeerClient {
    pub transport: QuicTransport,
    pub router: MessageRouter,
    pub context: HandlerContext,
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
        info!("Connection ID: {}", hex::encode(&scid));
        
        let transport = QuicTransport::new(conn, socket);
        let mut router = MessageRouter::new();

        // Configure router with all standard handlers
        configure_router(&mut router);


        let context = HandlerContext {
            local_addr: local_addr_str,
            files: HashMap::new(),
            files_dir,
        };

        Ok(Self {
            transport,
            router,
            context,
        })
    }

    fn create_quic_config(
        server_cert: Option<String>,
        no_verify_tls: bool,
    ) -> Result<quiche::Config> {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
        let quic_config = QuicConfig::default();

        config.set_application_protos(&[b"hq-interop", b"hq-29", b"hq-28", b"hq-27", b"http/0.9"])?;
        config.set_max_idle_timeout(quic_config.max_idle_timeout_ms);
        config.set_max_recv_udp_payload_size(quic_config.max_recv_udp_payload_size);
        config.set_max_send_udp_payload_size(quic_config.max_send_udp_payload_size);
        config.set_initial_max_data(quic_config.initial_max_data);
        config.set_initial_max_stream_data_bidi_local(quic_config.initial_max_stream_data_bidi_local);
        config.set_initial_max_stream_data_bidi_remote(quic_config.initial_max_stream_data_bidi_remote);
        config.set_initial_max_streams_bidi(quic_config.initial_max_streams_bidi);
        config.set_initial_max_streams_uni(quic_config.initial_max_streams_uni);
        config.set_disable_active_migration(true);

        if no_verify_tls {
            config.verify_peer(false);
            info!("TLS certificate verification disabled - this is insecure!");
        } else {
            if let Some(cert_path) = server_cert {
                config.load_verify_locations_from_file(&cert_path)?;
                info!("Using server certificate: {}", cert_path);
            }
            config.verify_peer(true);
        }

        Ok(config)
    }

   
    async fn wait_for_connection(&mut self) -> Result<()> {
        let start_time = Instant::now();
        info!("Establishing QUIC connection...");

        self.transport.process_events()?;

        while !self.transport.is_established() {
            if start_time.elapsed() >= CONNECTION_TIMEOUT {
                return Err(anyhow!("Connection timeout"));
            }

            self.transport.process_events()?;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        info!("QUIC connection established");
        Ok(())
    }

    fn process_events(&mut self) -> Result<()> {
        let incoming_messages = self.transport.process_events()?;
        
        // Handle incoming messages using the router
        for (stream_id, data) in incoming_messages {
            if let Ok(message) = Communication::deserialize(&data) {
                debug!("Received incoming message: {:?}", message);
                
                if let Some(response) = self.router.handle_peer_message(&message, &mut self.context)? {
                    self.transport.send_response(stream_id, &response)?;
                }
            }
        }
        
        Ok(())
    }

    }


#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct FileInfo {
    id: String,
    name: String,
    size: u64,
    path: String,
}


struct Client {
    conn: quiche::Connection,
    partial_responses: HashMap<u64, Vec<u8>>,
}

type ClientMap = HashMap<Vec<u8>, Client>;

/// Server using the same handler-based architecture as the peer client.
/// This ensures consistent message processing across both client and server.
struct Server {
    socket: std::net::UdpSocket,
    clients: ClientMap,
    read_buf: [u8; 65535],
    out_buf: [u8; 1350],
    config: quiche::Config,
    conn_id_seed: ring::hmac::Key,
    // Handler architecture components
    router: MessageRouter,
    context: HandlerContext,
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

        let mut router = MessageRouter::new();

        // Configure router with all standard handlers
        configure_router(&mut router);
        let context = HandlerContext {
            local_addr: addr.to_string(),
            files: HashMap::new(),
            files_dir: files_dir.clone(),
        };

        Ok(Self {
            socket,
            clients: HashMap::new(),
            read_buf: [0; 65535],
            out_buf: [0; 1350],
            config,
            conn_id_seed,
            router,
            context,
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
                                
                                // Use the handler-based architecture for consistent message processing
                                if let Ok(Some(response)) = self.router.handle_server_side(&communication, &mut self.context) {
                                    if let Ok(data) = response.serialize() {
                                        debug!("Sending response on stream {}", stream_id);
                                        match client.conn.stream_send(stream_id, &data, true) {
                                            Ok(_) => debug!("Successfully sent response"),
                                            Err(e) => warn!("Failed to send response: {:?}", e),
                                        }
                                    }
                                } else {
                                    warn!("No response generated for message: {:?}", communication);
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

}

async fn start_peer(
    server_addr: String,
    files_dir: String,
    port: u16,
    server_cert: Option<String>,
    no_verify_tls: bool,
) -> Result<()> {
    let peer = PeerClient::new(&server_addr, files_dir, port, server_cert, no_verify_tls)?;
    
    // Wait for connection to be established
    let mut peer_client = peer;
    peer_client.wait_for_connection().await?;
    peer_client.announce_presence().await?;
    
    // Start the interactive user interface
    let mut ui = UserInterface::new(peer_client, QuicTransport::new(peer.transport.conn, peer.transport.socket));
    ui.run().await
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

/// User interface for interactive peer operations
/// Provides commands for users to interact with the P2P network
struct UserInterface {
    peer_client: PeerClient,
    transport: QuicTransport,
}

impl UserInterface {
    fn new(peer_client: PeerClient, transport: QuicTransport) -> Self {
        Self { peer_client, transport }
    }

    /// Start the interactive user interface
    async fn run(&mut self) -> Result<()> {
        println!("=== P2P File Transfer Client ===");
        println!("Available commands:");
        println!("  help                    - Show this help message");
        println!("  announce                - Announce presence to server");
        println!("  scan                    - Scan local files");
        println!("  list                    - List local files");
        println!("  request <file_id>       - Request file availability from network");
        println!("  get <file_id>           - Download a file from a peer");
        println!("  status                  - Show connection status");
        println!("  quit                    - Exit the application");
        println!();

        let stdin = tokio_io::stdin();
        let reader = BufReader::new(stdin);
        let mut lines = reader.lines();

        // Print initial prompt
        print!("p2p> ");
        let _ = tokio_io::stdout().flush().await;

        loop {
            // Process events to handle incoming messages
            if let Err(e) = self.peer_client.process_events() {
                warn!("Error processing events: {}", e);
            }

            // Check for user input with timeout
            tokio::select! {
                line_result = lines.next_line() => {
                    match line_result {
                        Ok(Some(line)) => {
                            let trimmed = line.trim();
                            if trimmed.is_empty() {
                                // Print prompt again for empty input
                                print!("p2p> ");
                                let _ = tokio_io::stdout().flush().await;
                                continue;
                            }

                            if let Err(e) = self.handle_command(trimmed).await {
                                println!("Error: {}", e);
                            }

                            if trimmed == "quit" {
                                break;
                            }

                            // Print prompt again after handling command
                            print!("p2p> ");
                            let _ = tokio_io::stdout().flush().await;
                        }
                        Ok(None) => {
                            // EOF reached
                            break;
                        }
                        Err(e) => {
                            error!("Error reading input: {}", e);
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    // Timeout - just continue to process events, don't print prompt
                    continue;
                }
            }
        }

        println!("Goodbye!");
        Ok(())
    }

    /// Handle user commands
    async fn handle_command(&mut self, command: &str) -> Result<()> {
        let parts: Vec<&str> = command.split_whitespace().collect();
        let cmd = parts.first().unwrap_or(&"");

        match *cmd {
            "help" => {
                println!("Available commands:");
                println!("  help                    - Show this help message");
                println!("  announce                - Announce presence to server");
                println!("  scan                    - Scan local files");
                println!("  list                    - List local files");
                println!("  request <file_id>       - Request file availability from network");
                println!("  get <file_id>           - Download a file from a peer");
                println!("  status                  - Show connection status");
                println!("  quit                    - Exit the application");
            }
            "announce" => {
                self.announce_presence().await?;
            }
            "scan" => {
                self.scan_files().await?;
            }
            "list" => {
                self.list_files().await?;
            }
            "request" => {
                if let Some(file_id) = parts.get(1) {
                    self.request_file(file_id).await?;
                } else {
                    println!("Usage: request <file_id>");
                }
            }
            "get" => {
                if let Some(file_id) = parts.get(1) {
                    self.get_file(file_id).await?;
                } else {
                    println!("Usage: get <file_id>");
                }
            }
            "status" => {
                self.show_status().await?;
            }
            "quit" => {
                // Handle quit in the main loop
            }
            _ => {
                println!("Unknown command: {}. Type 'help' for available commands.", cmd);
            }
        }

        Ok(())
    }

    /// Announce presence to the server
    async fn announce_presence(&mut self) -> Result<()> {
        println!("Announcing presence to server...");
        self.transport.send_request(&Communication::PresenceAnnounce { peer_addr: self.peer_client.context.local_addr.clone() }).await?;
        println!("Presence announced successfully!");
        Ok(())
    }

    /// Scan local files
    async fn scan_files(&mut self) -> Result<()> {
        println!("Scanning local files...");
        PeerLifecycleHandler::scan_files(&mut self.peer_client.context)?;
        println!("Found {} files in local directory", self.peer_client.context.files.len());
        Ok(())
    }

    /// List local files
    async fn list_files(&mut self) -> Result<()> {
        if self.peer_client.context.files.is_empty() {
            println!("No files found. Run 'scan' to scan local directory.");
            return Ok(());
        }

        println!("Local files:");
        for (file_id, file_info) in &self.peer_client.context.files {
            println!("  {} - {} ({} bytes)", file_id, file_info.name, file_info.size);
        }
        Ok(())
    }

    /// Request file availability from the network
    async fn request_file(&mut self, file_id: &str) -> Result<()> {
        println!("Requesting file availability for: {}", file_id);
        
        let request = Communication::FileRequest {
            file_id: file_id.to_string(),
            peer_addr: self.peer_client.context.local_addr.clone(),
        };

        match self.transport.send_request(&request).await {
            Ok(response_data) => {
                if let Ok(response) = Communication::deserialize(&response_data) {
                    match response {
                        Communication::FileResponse { file_id, available, peer_addr } => {
                            if available {
                                println!("File '{}' is available from peer: {}", file_id, peer_addr);
                            } else {
                                println!("File '{}' is not available from peer: {}", file_id, peer_addr);
                            }
                        }
                        Communication::Error { message } => {
                            println!("Error response: {}", message);
                        }
                        _ => {
                            println!("Unexpected response type");
                        }
                    }
                } else {
                    println!("Failed to parse response");
                }
            }
            Err(e) => {
                println!("Failed to send request: {}", e);
            }
        }
        Ok(())
    }

    /// Download a file from a peer
    async fn get_file(&mut self, file_id: &str) -> Result<()> {
        println!("Downloading file: {}", file_id);
        
        let request = Communication::FileGet {
            file_id: file_id.to_string(),
            peer_addr: self.peer_client.context.local_addr.clone(),
        };

        match self.transport.send_request(&request).await {
            Ok(response_data) => {
                if let Ok(response) = Communication::deserialize(&response_data) {
                    match response {
                        Communication::FileGetResponse { file_id, success, file_data, error_message, peer_addr } => {
                            if success {
                                if let Some(data) = file_data {
                                    // Save the file to local directory
                                    let file_name = file_id.split('-').last().unwrap_or(&file_id);
                                    let file_path = format!("{}/{}", self.peer_client.context.files_dir, file_name);
                                    let data_len = data.len();
                                    
                                    match fs::write(&file_path, data) {
                                        Ok(_) => {
                                            println!("File '{}' downloaded successfully and saved to: {}", file_id, file_path);
                                            println!("Downloaded {} bytes from peer: {}", data_len, peer_addr);
                                        }
                                        Err(e) => {
                                            println!("Failed to save file: {}", e);
                                        }
                                    }
                                } else {
                                    println!("File data is empty");
                                }
                            } else {
                                let error = error_message.unwrap_or_else(|| "Unknown error".to_string());
                                println!("Failed to download file '{}': {}", file_id, error);
                            }
                        }
                        Communication::Error { message } => {
                            println!("Error response: {}", message);
                        }
                        _ => {
                            println!("Unexpected response type");
                        }
                    }
                } else {
                    println!("Failed to parse response");
                }
            }
            Err(e) => {
                println!("Failed to send download request: {}", e);
            }
        }
        Ok(())
    }

    /// Show connection status
    async fn show_status(&mut self) -> Result<()> {
        let is_connected = self.peer_client.transport.is_established();
        println!("Connection status: {}", if is_connected { "Connected" } else { "Disconnected" });
        println!("Local address: {}", self.peer_client.context.local_addr);
        println!("Files directory: {}", self.peer_client.context.files_dir);
        println!("Local files count: {}", self.peer_client.context.files.len());
        Ok(())
    }
}

