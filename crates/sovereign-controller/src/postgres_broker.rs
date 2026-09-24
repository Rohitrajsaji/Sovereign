//! Controller-owned PostgreSQL protocol broker for one managed-app generation.
//!
//! The untrusted app can reach only this loopback listener under Seatbelt. Every upstream
//! connection is freshly opened by the Controller against one pinned Unix socket, database and
//! least-privilege role. Startup claims from the app are checked but never forwarded. SQL bytes
//! are forwarded once; a broken connection is closed and is never replayed.

use sovereign_tools::process_group_leader_identity;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use std::time::Instant;

const DATABASE: &str = "sovereign_app";
const ROLE: &str = "sovereign_app_runtime";
const MAX_STARTUP_BYTES: usize = 4096;
const MAX_SERVER_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_PREFLIGHT_BYTES: usize = 256 * 1024;
const MAX_CLIENTS: usize = 8;
const MAX_STREAM_BYTES: u64 = 16 * 1024 * 1024;
const IO_POLL: Duration = Duration::from_millis(250);

const VERIFY_QUERY: &str = "SELECT current_user::text,current_database()::text,(SELECT oid::text FROM pg_catalog.pg_database WHERE datname=current_database()),(SELECT (NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND rolcanlogin AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=pg_roles.oid) AND pg_catalog.has_database_privilege(current_user,current_database(),'CONNECT') AND NOT pg_catalog.has_database_privilege(current_user,current_database(),'CREATE') AND NOT pg_catalog.has_database_privilege(current_user,current_database(),'TEMP') AND pg_catalog.has_schema_privilege(current_user,'app','USAGE') AND NOT pg_catalog.has_schema_privilege(current_user,'app','CREATE'))::text FROM pg_catalog.pg_roles WHERE rolname=current_user)";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
    owner: u32,
}

fn socket_identity(path: &Path) -> io::Result<SocketIdentity> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PostgreSQL endpoint is not a Unix socket",
        ));
    }
    Ok(SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
    })
}

#[derive(Debug, Clone)]
pub(crate) struct PostgresBrokerConfig {
    pub(crate) backend_socket: PathBuf,
    pub(crate) database_oid: u32,
}

/// One live Controller-owned broker. Dropping it closes the listener and all active connections.
pub(crate) struct ControllerPostgresBroker {
    port: u16,
    listener: Option<TcpListener>,
    config: PostgresBrokerConfig,
    identity: SocketIdentity,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

struct ProcessBinding {
    process_group_id: u32,
    leader_identity: String,
    deadline: Instant,
}

impl ControllerPostgresBroker {
    /// Reserves the exact port and proves backend identity, but accepts no app traffic yet.
    pub(crate) fn prepare(config: PostgresBrokerConfig) -> io::Result<Self> {
        if config.database_oid == 0 || !config.backend_socket.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PostgreSQL broker requires an exact socket and database OID",
            ));
        }
        let identity = socket_identity(&config.backend_socket)?;
        // Prove the target role and database before making an app-reachable listener available.
        let (probe, _) = open_verified_backend(&config, identity)?;
        let _ = probe.shutdown(Shutdown::Both);
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let stop = Arc::new(AtomicBool::new(false));
        Ok(Self {
            port,
            listener: Some(listener),
            config,
            identity,
            stop,
            thread: None,
        })
    }

    pub(crate) fn activate_for_process(
        &mut self,
        process_group_id: u32,
        leader_identity: String,
        deadline: Instant,
    ) -> io::Result<()> {
        if process_group_id == 0 || leader_identity.is_empty() || deadline <= Instant::now() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PostgreSQL broker process binding is invalid",
            ));
        }
        self.activate(Some(ProcessBinding {
            process_group_id,
            leader_identity,
            deadline,
        }))
    }

    fn activate(&mut self, process_binding: Option<ProcessBinding>) -> io::Result<()> {
        let listener = self
            .listener
            .take()
            .ok_or_else(|| io::Error::other("PostgreSQL broker was already activated"))?;
        let port = self.port;
        let thread_stop = Arc::clone(&self.stop);
        let config = self.config.clone();
        let identity = self.identity;
        let thread = thread::Builder::new()
            .name(format!("sovereign-postgres-broker-{port}"))
            .spawn(move || serve(listener, config, identity, process_binding, thread_stop))?;
        self.thread = Some(thread);
        Ok(())
    }

    #[cfg(test)]
    fn start(config: PostgresBrokerConfig) -> io::Result<Self> {
        let mut broker = Self::prepare(config)?;
        broker.activate(None)?;
        Ok(broker)
    }

    pub(crate) const fn port(&self) -> u16 {
        self.port
    }

    pub(crate) const fn backend_identity(&self) -> (u64, u64, u32) {
        (
            self.identity.device,
            self.identity.inode,
            self.identity.owner,
        )
    }

    pub(crate) fn stop(&mut self) -> io::Result<()> {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| io::Error::other("PostgreSQL broker thread panicked"))?;
        }
        Ok(())
    }
}

impl Drop for ControllerPostgresBroker {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn serve(
    listener: TcpListener,
    config: PostgresBrokerConfig,
    identity: SocketIdentity,
    process_binding: Option<ProcessBinding>,
    stop: Arc<AtomicBool>,
) {
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    while !stop.load(Ordering::Acquire) {
        if let Some(binding) = &process_binding {
            if Instant::now() >= binding.deadline
                || !matches!(process_group_leader_identity(binding.process_group_id), Ok(Some(ref actual)) if actual == &binding.leader_identity)
            {
                break;
            }
        }
        workers.retain(|worker| !worker.is_finished());
        match listener.accept() {
            Ok((client, _)) if workers.len() < MAX_CLIENTS => {
                if client.set_nonblocking(false).is_err() {
                    let _ = client.shutdown(Shutdown::Both);
                    continue;
                }
                let config = config.clone();
                let stop = Arc::clone(&stop);
                workers.push(thread::spawn(move || {
                    if handle_client(client, &config, identity, &stop).is_err() {
                        // Protocol, auth and transport failures are intentionally redacted.
                    }
                }));
            }
            Ok((client, _)) => {
                let _ = client.shutdown(Shutdown::Both);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(IO_POLL),
            Err(_) => break,
        }
    }
    stop.store(true, Ordering::Release);
    for worker in workers {
        let _ = worker.join();
    }
}

fn handle_client(
    mut client: TcpStream,
    config: &PostgresBrokerConfig,
    identity: SocketIdentity,
    stop: &AtomicBool,
) -> io::Result<()> {
    if stop.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "PostgreSQL broker generation stopped",
        ));
    }
    client.set_read_timeout(Some(Duration::from_secs(3)))?;
    client.set_write_timeout(Some(Duration::from_secs(3)))?;
    let startup = match read_client_startup(&mut client) {
        Ok(startup) => startup,
        Err(error) => {
            let _ = send_error(&mut client);
            return Err(error);
        }
    };
    if !startup {
        let _ = send_error(&mut client);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PostgreSQL startup identity denied",
        ));
    }
    if stop.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "PostgreSQL broker generation stopped",
        ));
    }
    let (mut backend, startup_reply) = match open_verified_backend(config, identity) {
        Ok(backend) => backend,
        Err(error) => {
            let _ = send_error(&mut client);
            return Err(error);
        }
    };
    if stop.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "PostgreSQL broker generation stopped",
        ));
    }
    // Only the preflight-approved AuthenticationOk/ParameterStatus/Ready packets reach the app.
    client.write_all(&startup_reply)?;
    client.set_read_timeout(Some(IO_POLL))?;
    client.set_write_timeout(Some(IO_POLL))?;
    backend.set_read_timeout(Some(IO_POLL))?;
    backend.set_write_timeout(Some(IO_POLL))?;
    let mut client_to_backend = client.try_clone()?;
    let mut backend_to_client = backend.try_clone()?;
    thread::scope(|scope| {
        let outbound = scope.spawn(|| {
            let result = pump(&mut client_to_backend, &mut backend, stop);
            let _ = client_to_backend.shutdown(Shutdown::Both);
            let _ = backend.shutdown(Shutdown::Both);
            result
        });
        let inbound = pump(&mut backend_to_client, &mut client, stop);
        let _ = backend_to_client.shutdown(Shutdown::Both);
        let _ = client.shutdown(Shutdown::Both);
        let _ = outbound.join();
        inbound
    })
}

fn pump<R: Read, W: Write>(
    source: &mut R,
    destination: &mut W,
    stop: &AtomicBool,
) -> io::Result<()> {
    let mut buffer = [0_u8; 8192];
    let mut transferred = 0_u64;
    while !stop.load(Ordering::Acquire) {
        match source.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(size) => {
                transferred =
                    transferred.saturating_add(u64::try_from(size).map_err(|_| invalid_packet())?);
                if transferred > MAX_STREAM_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "PostgreSQL broker stream byte ceiling exceeded",
                    ));
                }
                destination.write_all(&buffer[..size])?;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read_client_startup(client: &mut TcpStream) -> io::Result<bool> {
    for _ in 0..3 {
        let mut length_bytes = [0_u8; 4];
        client.read_exact(&mut length_bytes)?;
        let length =
            usize::try_from(u32::from_be_bytes(length_bytes)).map_err(|_| invalid_packet())?;
        if !(8..=MAX_STARTUP_BYTES).contains(&length) {
            return Err(invalid_packet());
        }
        let mut packet = vec![0_u8; length - 4];
        client.read_exact(&mut packet)?;
        let protocol = u32::from_be_bytes(packet[..4].try_into().map_err(|_| invalid_packet())?);
        match protocol {
            80877103 | 80877104 if length == 8 => client.write_all(b"N")?, // SSL/GSS negotiation
            196608 => return parse_startup_params(&packet[4..]),
            _ => return Err(invalid_packet()), // CancelRequest and unsupported versions never reach PostgreSQL.
        }
    }
    Err(invalid_packet())
}

fn parse_startup_params(params: &[u8]) -> io::Result<bool> {
    if params.len() < 3 || !params.ends_with(&[0, 0]) {
        return Err(invalid_packet());
    }
    let mut user = None;
    let mut database = None;
    let mut parts = params[..params.len() - 2].split(|byte| *byte == 0);
    while let Some(key) = parts.next() {
        let value = parts.next().ok_or_else(invalid_packet)?;
        if key.is_empty() || value.is_empty() {
            return Err(invalid_packet());
        }
        match key {
            b"user" if user.is_none() => user = Some(value),
            b"database" if database.is_none() => database = Some(value),
            b"client_encoding" | b"application_name" => {
                if value.len() > 128 || value.iter().any(|byte| *byte < 32 || *byte > 126) {
                    return Err(invalid_packet());
                }
            }
            _ => return Err(invalid_packet()),
        }
    }
    Ok(user == Some(ROLE.as_bytes()) && database == Some(DATABASE.as_bytes()))
}

fn open_verified_backend(
    config: &PostgresBrokerConfig,
    identity: SocketIdentity,
) -> io::Result<(UnixStream, Vec<u8>)> {
    if socket_identity(&config.backend_socket)? != identity {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PostgreSQL socket identity drifted",
        ));
    }
    let mut backend = UnixStream::connect(&config.backend_socket)?;
    if socket_identity(&config.backend_socket)? != identity {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PostgreSQL socket identity changed during connect",
        ));
    }
    backend.set_read_timeout(Some(Duration::from_secs(3)))?;
    backend.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut startup = Vec::new();
    startup.extend_from_slice(&196608_u32.to_be_bytes());
    startup.extend_from_slice(b"user\0");
    startup.extend_from_slice(ROLE.as_bytes());
    startup.push(0);
    startup.extend_from_slice(b"database\0");
    startup.extend_from_slice(DATABASE.as_bytes());
    startup.extend_from_slice(&[0, 0]);
    let length = u32::try_from(startup.len() + 4).map_err(|_| invalid_packet())?;
    backend.write_all(&length.to_be_bytes())?;
    backend.write_all(&startup)?;
    let startup_reply = verified_startup_reply(&mut backend, config.database_oid)?;
    Ok((backend, startup_reply))
}

fn verified_startup_reply(backend: &mut UnixStream, expected_oid: u32) -> io::Result<Vec<u8>> {
    // A caller may invoke this only once per backend connection. Buffer until proof completes.
    let mut startup_reply = Vec::new();
    let mut authentication_ok = false;
    loop {
        let (kind, payload, bytes) = read_message(backend)?;
        if startup_reply.len().saturating_add(bytes.len()) > MAX_PREFLIGHT_BYTES {
            return Err(invalid_packet());
        }
        match kind {
            b'R' if payload == [0, 0, 0, 0] && !authentication_ok => authentication_ok = true,
            b'S' | b'K' | b'N' if authentication_ok => {}
            b'Z' if authentication_ok && payload == [b'I'] => {
                startup_reply.extend(bytes);
                break;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "PostgreSQL backend authentication failed",
                ));
            }
        }
        startup_reply.extend(bytes);
    }
    let mut query = VERIFY_QUERY.as_bytes().to_vec();
    query.push(0);
    write_message(backend, b'Q', &query)?;
    let mut row = None;
    let mut observed = 0_usize;
    let mut phase = 0_u8;
    loop {
        let (kind, payload, bytes) = read_message(backend)?;
        observed = observed.saturating_add(bytes.len());
        if observed > MAX_PREFLIGHT_BYTES {
            return Err(invalid_packet());
        }
        match kind {
            b'T' if phase == 0 => phase = 1,
            b'D' if phase == 1 => {
                row = Some(parse_data_row(&payload)?);
                phase = 2;
            }
            b'C' if phase == 2 && payload == b"SELECT 1\0" => phase = 3,
            b'Z' if phase == 3 && payload == [b'I'] => break,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "PostgreSQL identity proof failed",
                ));
            }
        }
    }
    let expected_oid = expected_oid.to_string();
    if row.as_deref()
        != Some(
            &[
                ROLE.to_owned(),
                DATABASE.to_owned(),
                expected_oid,
                "true".to_owned(),
            ][..],
        )
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PostgreSQL identity or role privileges drifted",
        ));
    }
    Ok(startup_reply)
}

fn parse_data_row(payload: &[u8]) -> io::Result<Vec<String>> {
    if payload.len() < 2 || u16::from_be_bytes([payload[0], payload[1]]) != 4 {
        return Err(invalid_packet());
    }
    let mut offset = 2;
    let mut values = Vec::with_capacity(4);
    for _ in 0..4 {
        if payload.len() - offset < 4 {
            return Err(invalid_packet());
        }
        let len = i32::from_be_bytes(
            payload[offset..offset + 4]
                .try_into()
                .map_err(|_| invalid_packet())?,
        );
        offset += 4;
        let len = usize::try_from(len).map_err(|_| invalid_packet())?;
        if len > 128 || payload.len() - offset < len {
            return Err(invalid_packet());
        }
        values.push(
            std::str::from_utf8(&payload[offset..offset + len])
                .map_err(|_| invalid_packet())?
                .to_owned(),
        );
        offset += len;
    }
    if offset != payload.len() {
        return Err(invalid_packet());
    }
    Ok(values)
}

fn read_message<R: Read>(reader: &mut R) -> io::Result<(u8, Vec<u8>, Vec<u8>)> {
    let mut header = [0_u8; 5];
    reader.read_exact(&mut header)?;
    let length = usize::try_from(u32::from_be_bytes(
        header[1..].try_into().map_err(|_| invalid_packet())?,
    ))
    .map_err(|_| invalid_packet())?;
    if !(4..=MAX_SERVER_MESSAGE_BYTES).contains(&length) {
        return Err(invalid_packet());
    }
    let mut payload = vec![0_u8; length - 4];
    reader.read_exact(&mut payload)?;
    let mut bytes = header.to_vec();
    bytes.extend_from_slice(&payload);
    Ok((header[0], payload, bytes))
}

fn write_message<W: Write>(writer: &mut W, kind: u8, payload: &[u8]) -> io::Result<()> {
    writer.write_all(&[kind])?;
    writer.write_all(
        &u32::try_from(payload.len() + 4)
            .map_err(|_| invalid_packet())?
            .to_be_bytes(),
    )?;
    writer.write_all(payload)
}

fn send_error(client: &mut TcpStream) -> io::Result<()> {
    write_message(
        client,
        b'E',
        b"SERROR\0C28000\0MPostgreSQL broker denied connection\0\0",
    )
}

fn invalid_packet() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid PostgreSQL protocol packet",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn broker_caps_forwarded_bytes_per_direction() {
        let source = vec![0_u8; usize::try_from(MAX_STREAM_BYTES).unwrap() + 1];
        let mut source = io::Cursor::new(source);
        let mut destination = io::sink();
        let stop = AtomicBool::new(false);
        assert_eq!(
            pump(&mut source, &mut destination, &stop)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    fn startup(user: &str, database: &str) -> Vec<u8> {
        let mut payload = 196608_u32.to_be_bytes().to_vec();
        payload.extend_from_slice(b"user\0");
        payload.extend_from_slice(user.as_bytes());
        payload.push(0);
        payload.extend_from_slice(b"database\0");
        payload.extend_from_slice(database.as_bytes());
        payload.extend_from_slice(&[0, 0]);
        let mut packet = u32::try_from(payload.len() + 4)
            .unwrap()
            .to_be_bytes()
            .to_vec();
        packet.extend(payload);
        packet
    }

    fn data_row(oid: u32) -> Vec<u8> {
        data_row_values([ROLE, DATABASE, &oid.to_string(), "true"])
    }

    fn data_row_values(values: [&str; 4]) -> Vec<u8> {
        let mut payload = 4_u16.to_be_bytes().to_vec();
        for value in values {
            payload.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
            payload.extend_from_slice(value.as_bytes());
        }
        payload
    }

    fn fake_backend(connection: UnixStream, oid: u32, observed: Option<&mpsc::Sender<Vec<u8>>>) {
        fake_backend_with_row(connection, data_row(oid), observed);
    }

    fn fake_backend_with_row(
        mut connection: UnixStream,
        proof_row: Vec<u8>,
        observed: Option<&mpsc::Sender<Vec<u8>>>,
    ) {
        let mut length = [0_u8; 4];
        connection.read_exact(&mut length).unwrap();
        let mut packet = vec![0_u8; u32::from_be_bytes(length) as usize - 4];
        connection.read_exact(&mut packet).unwrap();
        assert!(
            packet
                .windows(ROLE.len())
                .any(|slice| slice == ROLE.as_bytes())
        );
        write_message(&mut connection, b'R', &[0, 0, 0, 0]).unwrap();
        write_message(&mut connection, b'S', b"server_version\0fake\0").unwrap();
        write_message(&mut connection, b'Z', b"I").unwrap();
        let (kind, _, _) = read_message(&mut connection).unwrap();
        assert_eq!(kind, b'Q');
        write_message(&mut connection, b'T', b"test").unwrap();
        write_message(&mut connection, b'D', &proof_row).unwrap();
        write_message(&mut connection, b'C', b"SELECT 1\0").unwrap();
        write_message(&mut connection, b'Z', b"I").unwrap();
        if let Some(observed) = observed {
            let (kind, payload, _) = read_message(&mut connection).unwrap();
            assert_eq!(kind, b'Q');
            observed.send(payload).unwrap();
            // A lost backend after a consequential query must close the client, never reconnect.
        }
    }

    #[test]
    fn preflight_denies_role_database_oid_and_privilege_drift_without_opening_a_port() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("sov-pg-proof-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).unwrap();
        for (index, proof) in [
            ["wrong_role", DATABASE, "42", "true"],
            [ROLE, "wrong_database", "42", "true"],
            [ROLE, DATABASE, "43", "true"],
            [ROLE, DATABASE, "42", "false"],
        ]
        .into_iter()
        .enumerate()
        {
            let socket = root.join(format!("pg-{index}.sock"));
            let listener = UnixListener::bind(&socket).unwrap();
            let fake = thread::spawn(move || {
                let (probe, _) = listener.accept().unwrap();
                fake_backend_with_row(probe, data_row_values(proof), None);
            });
            assert!(
                ControllerPostgresBroker::prepare(PostgresBrokerConfig {
                    backend_socket: socket.clone(),
                    database_oid: 42,
                })
                .is_err(),
                "preflight accepted drift case {index}"
            );
            fake.join().unwrap();
            fs::remove_file(socket).unwrap();
        }
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn missing_or_lost_backend_fails_closed_without_fallback_or_replay() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sov-pg-down-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let socket = root.join("pg.sock");
        assert!(
            ControllerPostgresBroker::prepare(PostgresBrokerConfig {
                backend_socket: socket.clone(),
                database_oid: 42,
            })
            .is_err(),
            "missing backend unexpectedly prepared a broker"
        );
        let listener = UnixListener::bind(&socket).unwrap();
        let fake = thread::spawn(move || {
            let (probe, _) = listener.accept().unwrap();
            fake_backend(probe, 42, None);
            // The one approved endpoint disappears after preflight. No alternate socket exists.
        });
        let mut broker = ControllerPostgresBroker::start(PostgresBrokerConfig {
            backend_socket: socket.clone(),
            database_oid: 42,
        })
        .unwrap();
        fake.join().unwrap();
        fs::remove_file(&socket).unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", broker.port())).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        client.write_all(&startup(ROLE, DATABASE)).unwrap();
        let (kind, _, _) = read_message(&mut client).unwrap();
        assert_eq!(kind, b'E');
        broker.stop().unwrap();
        assert!(TcpStream::connect(("127.0.0.1", broker.port())).is_err());
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn broker_pins_upstream_identity_rejects_startup_and_never_replays_after_loss() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("sov-pg-broker-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let socket = root.join("pg.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (observed_tx, observed_rx) = mpsc::channel();
        let fake = thread::spawn(move || {
            let (probe, _) = listener.accept().unwrap();
            fake_backend(probe, 42, None);
            let (app, _) = listener.accept().unwrap();
            fake_backend(app, 42, Some(&observed_tx));
        });
        let mut broker = ControllerPostgresBroker::start(PostgresBrokerConfig {
            backend_socket: socket.clone(),
            database_oid: 42,
        })
        .unwrap();
        let mut denied = TcpStream::connect(("127.0.0.1", broker.port())).unwrap();
        denied
            .write_all(&startup("rohitrajsaji", DATABASE))
            .unwrap();
        let (kind, _, _) = read_message(&mut denied).unwrap();
        assert_eq!(kind, b'E');
        let mut wrong_database = TcpStream::connect(("127.0.0.1", broker.port())).unwrap();
        wrong_database
            .write_all(&startup(ROLE, "postgres"))
            .unwrap();
        let (kind, _, _) = read_message(&mut wrong_database).unwrap();
        assert_eq!(kind, b'E');
        let mut app = TcpStream::connect(("127.0.0.1", broker.port())).unwrap();
        app.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        app.write_all(&startup(ROLE, DATABASE)).unwrap();
        loop {
            let (kind, _, _) = read_message(&mut app).unwrap();
            if kind == b'Z' {
                break;
            }
        }
        write_message(&mut app, b'Q', b"UPDATE inventory SET count=count+1\0").unwrap();
        assert_eq!(
            observed_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            b"UPDATE inventory SET count=count+1\0"
        );
        let mut one = [0_u8; 1];
        assert_eq!(app.read(&mut one).unwrap(), 0);
        fake.join().unwrap();
        broker.stop().unwrap();
        assert!(TcpStream::connect(("127.0.0.1", broker.port())).is_err());
        fs::remove_file(&socket).unwrap();
        fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn replaced_backend_socket_is_not_followed() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("sov-pg-drift-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let socket = root.join("pg.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let fake = thread::spawn(move || {
            let (probe, _) = listener.accept().unwrap();
            fake_backend(probe, 42, None);
        });
        let mut broker = ControllerPostgresBroker::start(PostgresBrokerConfig {
            backend_socket: socket.clone(),
            database_oid: 42,
        })
        .unwrap();
        fake.join().unwrap();
        fs::remove_file(&socket).unwrap();
        let replacement = UnixListener::bind(&socket).unwrap();
        let mut app = TcpStream::connect(("127.0.0.1", broker.port())).unwrap();
        app.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        app.write_all(&startup(ROLE, DATABASE)).unwrap();
        let (kind, _, _) = read_message(&mut app).unwrap();
        assert_eq!(kind, b'E');
        broker.stop().unwrap();
        drop(replacement);
        fs::remove_file(&socket).unwrap();
        fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn live_postgres_broker_proves_dedicated_role_and_database_when_requested() {
        let Ok(oid) = std::env::var("SOVEREIGN_TEST_LIVE_POSTGRES_OID") else {
            return;
        };
        let oid: u32 = oid.parse().unwrap();
        assert!(
            ControllerPostgresBroker::prepare(PostgresBrokerConfig {
                backend_socket: PathBuf::from("/tmp/.s.PGSQL.5432"),
                database_oid: oid + 1,
            })
            .is_err(),
            "broker accepted a drifted database OID"
        );
        let mut broker = ControllerPostgresBroker::start(PostgresBrokerConfig {
            backend_socket: PathBuf::from("/tmp/.s.PGSQL.5432"),
            database_oid: oid,
        })
        .unwrap();
        let output = std::process::Command::new("/opt/homebrew/opt/postgresql@16/bin/psql")
            .args([
                "-X",
                "-w",
                "-h",
                "127.0.0.1",
                "-p",
                &broker.port().to_string(),
                "-U",
                ROLE,
                "-d",
                DATABASE,
                "-Atqc",
                "SELECT current_user,current_database()",
            ])
            .env_clear()
            .env("PGPASSFILE", "/nonexistent")
            .env("PGCONNECT_TIMEOUT", "2")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "broker query failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "sovereign_app_runtime|sovereign_app"
        );
        broker.stop().unwrap();
    }

    #[test]
    fn broker_closes_when_its_bound_process_generation_exits() {
        use std::os::unix::process::CommandExt;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("sov-pg-process-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let socket = root.join("pg.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let fake = thread::spawn(move || {
            let (probe, _) = listener.accept().unwrap();
            fake_backend(probe, 42, None);
        });
        let mut broker = ControllerPostgresBroker::prepare(PostgresBrokerConfig {
            backend_socket: socket.clone(),
            database_oid: 42,
        })
        .unwrap();
        fake.join().unwrap();
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("5")
            .process_group(0)
            .spawn()
            .unwrap();
        let group = child.id();
        let leader = process_group_leader_identity(group).unwrap().unwrap();
        broker
            .activate_for_process(group, leader, Instant::now() + Duration::from_secs(3))
            .unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline
            && std::net::TcpStream::connect(("127.0.0.1", broker.port())).is_ok()
        {
            thread::sleep(Duration::from_millis(50));
        }
        assert!(std::net::TcpStream::connect(("127.0.0.1", broker.port())).is_err());
        broker.stop().unwrap();
        fs::remove_file(&socket).unwrap();
        fs::remove_dir(&root).unwrap();
    }
}
