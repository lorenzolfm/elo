use std::hash::BuildHasher;

const NETWORK: elo::chain::network::Network = elo::chain::network::Network::Regtest;
const PEER: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const LINGER: std::time::Duration = std::time::Duration::from_secs(2);

fn main() -> std::process::ExitCode {
    let mut args = std::env::args().skip(1);
    let network = args.next();
    let peer = args.next();
    match run(network.as_deref(), peer.as_deref()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("elo: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(network: Option<&str>, peer: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let network: elo::chain::network::Network = match network {
        Some(name) => name.parse()?,
        None => NETWORK,
    };
    let peer: std::net::SocketAddr = match peer {
        Some(address) => address.parse()?,
        None => std::net::SocketAddr::new(PEER, network.port()),
    };
    println!(
        "connecting to {peer} on {network} as {}",
        elo::p2p::version::USER_AGENT
    );
    let stream = std::net::TcpStream::connect_timeout(&peer, TIMEOUT)?;
    let mut connection =
        elo::p2p::connection::Connection::new(elo::p2p::link::Tcp::new(stream), network);
    connection.set_read_deadline(Some(connection.now() + TIMEOUT))?;

    let since_epoch = connection.wall().duration_since(std::time::UNIX_EPOCH)?;
    let timestamp = i64::try_from(since_epoch.as_secs())?;
    let version_nonce = std::hash::RandomState::new().hash_one(0u8);
    let our_version = elo::p2p::version::build(peer, timestamp, version_nonce);

    let mut chain = elo::chain::Chain::new(network);
    elo::peer::run(&mut connection, &mut chain, &our_version, LINGER, |event| {
        println!("{event}");
    })?;
    Ok(())
}
