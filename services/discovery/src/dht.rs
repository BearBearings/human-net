use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use libp2p::identity::ed25519::SecretKey;
use libp2p::identity::Keypair;
use libp2p::kad::{
    store::MemoryStore, Behaviour as Kademlia, Config as KademliaConfig, Event as KademliaEvent,
    GetRecordOk, QueryId, QueryResult, Quorum, Record, RecordKey, PROTOCOL_NAME,
};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::{identify, noise, tcp, yamux, Multiaddr, PeerId, SwarmBuilder};
use rand::Rng;
use std::time::Duration as StdDuration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::interval;
use tracing::{error, info};
use web_time::Instant;

use hn_cli::discovery::dht::{compute_did_hash, DhtHint};
use hn_cli::identity::IdentityRecord;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct DhtConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub listen: Vec<String>,
    #[serde(default)]
    pub bootstrap: Vec<String>,
}

#[derive(Clone)]
pub struct DhtHandle {
    cmd_tx: Arc<mpsc::Sender<Command>>,
}

impl DhtHandle {
    pub async fn publish(&self, hint: DhtHint) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Publish {
                hint,
                respond_to: tx,
            })
            .await
            .map_err(|_| anyhow!("dht worker not running"))?;
        rx.await.map_err(|_| anyhow!("dht worker dropped"))?
    }

    pub async fn resolve(&self, did: String) -> Result<Option<DhtHint>> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Resolve {
                did,
                respond_to: tx,
            })
            .await
            .map_err(|_| anyhow!("dht worker not running"))?;
        rx.await.map_err(|_| anyhow!("dht worker dropped"))?
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.cmd_tx
            .send(Command::Shutdown)
            .await
            .map_err(|_| anyhow!("dht worker not running"))
    }
}

enum Command {
    Publish {
        hint: DhtHint,
        respond_to: oneshot::Sender<Result<()>>,
    },
    Resolve {
        did: String,
        respond_to: oneshot::Sender<Result<Option<DhtHint>>>,
    },
    Shutdown,
}

#[derive(NetworkBehaviour)]
struct DiscoveryBehaviour {
    identify: identify::Behaviour,
    kademlia: Kademlia<MemoryStore>,
}

pub fn spawn(
    identity: &IdentityRecord,
    config: DhtConfig,
    home: &Path,
) -> Result<Option<(DhtHandle, JoinHandle<()>)>> {
    if !config.enabled {
        return Ok(None);
    }

    let secret = SecretKey::try_from_bytes(identity.keys.signing_key().to_bytes())
        .map_err(|_| anyhow!("invalid signing key material"))?;
    let ed25519 = libp2p::identity::ed25519::Keypair::from(secret);
    let keypair = Keypair::from(ed25519);

    let mut swarm = SwarmBuilder::with_existing_identity(keypair.clone())
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|local_key| {
            let peer_id = PeerId::from(local_key.public());
            let store = MemoryStore::new(peer_id);
            let mut kad_config = KademliaConfig::new(PROTOCOL_NAME);
            kad_config.set_query_timeout(Duration::from_secs(30));
            let identify_cfg = identify::Config::new(
                format!("hn-dht/{}", env!("CARGO_PKG_VERSION")),
                local_key.public(),
            );
            Ok(DiscoveryBehaviour {
                identify: identify::Behaviour::new(identify_cfg),
                kademlia: Kademlia::with_config(peer_id, store, kad_config),
            })
        })?
        .build();

    let listen_addrs = if config.listen.is_empty() {
        vec![format!(
            "/ip4/0.0.0.0/tcp/{}",
            random_ephemeral_port().unwrap_or(0)
        )]
    } else {
        config.listen
    };
    for addr in listen_addrs {
        let multiaddr: Multiaddr = addr
            .parse()
            .with_context(|| format!("invalid listen multiaddr '{addr}'"))?;
        Swarm::listen_on(&mut swarm, multiaddr)?;
    }

    let mut bootstrap = HashSet::new();
    for addr in config.bootstrap {
        match addr.parse::<Multiaddr>() {
            Ok(multiaddr) => {
                if let Some(peer) = multiaddr
                    .iter()
                    .filter_map(|p| match p {
                        Protocol::P2p(peer) => Some(peer),
                        _ => None,
                    })
                    .last()
                {
                    swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer, multiaddr.clone());
                    bootstrap.insert(peer);
                }
            }
            Err(err) => error!(%err, "invalid bootstrap address '{}'", addr),
        }
    }

    let (cmd_tx_raw, mut cmd_rx) = mpsc::channel::<Command>(32);
    let cmd_tx = Arc::new(cmd_tx_raw);
    let home = home.to_path_buf();
    let mut pending_resolve: HashMap<QueryId, oneshot::Sender<Result<Option<DhtHint>>>> =
        HashMap::new();
    let mut republish = interval(Duration::from_secs(60 * 15));

    let mut swarm_handle = swarm;

    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        Command::Publish { hint, respond_to } => {
                            let res = publish_record(&mut swarm_handle, &home, hint).await;
                            let _ = respond_to.send(res);
                        }
                        Command::Resolve { did, respond_to } => {
                            let key = record_key_for_did(&did);
                            let query_id =
                                swarm_handle.behaviour_mut().kademlia.get_record(key);
                            pending_resolve.insert(query_id, respond_to);
                        }
                        Command::Shutdown => break,
                    }
                }
                event = swarm_handle.select_next_some() => {
                    if let Err(err) = handle_swarm_event(event, &mut pending_resolve) {
                        error!(%err, "dht swarm error");
                    }
                }
                _ = republish.tick() => {
                    if let Err(err) = republish_local_records(&mut swarm_handle, &home).await {
                        error!(%err, "failed to republish local DHT records");
                    }
                    if !bootstrap.is_empty() {
                        if let Err(err) = swarm_handle.behaviour_mut().kademlia.bootstrap() {
                            error!(%err, "kad bootstrap error");
                        }
                    }
                }
            }
        }
    });

    Ok(Some((DhtHandle { cmd_tx }, task)))
}

async fn publish_record(
    swarm: &mut Swarm<DiscoveryBehaviour>,
    home: &Path,
    hint: DhtHint,
) -> Result<()> {
    let json = serde_json::to_vec(&hint)?;
    let key = record_key_for_did(&hint.did);
    let mut record = Record::new(key.clone(), json);
    record.publisher = Some(*swarm.local_peer_id());
    apply_record_ttl(&mut record, &hint)?;
    swarm
        .behaviour_mut()
        .kademlia
        .put_record(record, Quorum::Majority)?;

    swarm
        .behaviour_mut()
        .kademlia
        .start_providing(key)
        .map_err(|err| anyhow!(err))?;

    let dir = ensure_dht_dir(home)?;
    let file = dir.join(format!("{}.json", hint.id.replace(':', "_")));
    fs::write(&file, serde_json::to_vec_pretty(&hint)?)?;
    info!("published DHT hint {}", hint.id);
    Ok(())
}

async fn republish_local_records(swarm: &mut Swarm<DiscoveryBehaviour>, home: &Path) -> Result<()> {
    let dir = ensure_dht_dir(home)?;
    if !dir.exists() {
        return Ok(());
    }
    let now = OffsetDateTime::now_utc();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let data = fs::read(entry.path())?;
        let hint: DhtHint = serde_json::from_slice(&data)?;
        if hint.expires_at <= now {
            let _ = fs::remove_file(entry.path());
            continue;
        }
        publish_record(swarm, home, hint).await?;
    }
    Ok(())
}

fn handle_swarm_event(
    event: SwarmEvent<DiscoveryBehaviourEvent>,
    pending_resolve: &mut HashMap<QueryId, oneshot::Sender<Result<Option<DhtHint>>>>,
) -> Result<()> {
    match event {
        SwarmEvent::Behaviour(DiscoveryBehaviourEvent::Kademlia(
            KademliaEvent::OutboundQueryProgressed { id, result, .. },
        )) => {
            if let Some(channel) = pending_resolve.remove(&id) {
                match result {
                    QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(peer_record))) => {
                        match serde_json::from_slice::<DhtHint>(&peer_record.record.value) {
                            Ok(hint) => {
                                let _ = channel.send(Ok(Some(hint)));
                            }
                            Err(err) => {
                                let _ = channel.send(Err(anyhow!(err)));
                            }
                        }
                    }
                    QueryResult::GetRecord(Ok(GetRecordOk::FinishedWithNoAdditionalRecord {
                        ..
                    })) => {
                        let _ = channel.send(Ok(None));
                    }
                    QueryResult::GetRecord(Err(_)) => {
                        let _ = channel.send(Ok(None));
                    }
                    _ => {
                        pending_resolve.insert(id, channel);
                    }
                }
            }
        }
        SwarmEvent::Behaviour(DiscoveryBehaviourEvent::Identify(event)) => {
            info!(?event, "identify event");
        }
        SwarmEvent::Behaviour(DiscoveryBehaviourEvent::Kademlia(event)) => {
            info!(?event, "kad event");
        }
        SwarmEvent::NewListenAddr { address, .. } => {
            info!(%address, "dht listening");
        }
        _ => {}
    }
    Ok(())
}

fn ensure_dht_dir(home: &Path) -> Result<PathBuf> {
    let dir = home.join("discovery").join("dht");
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }
    Ok(dir)
}

fn random_ephemeral_port() -> Option<u16> {
    let mut rng = rand::thread_rng();
    Some(rng.gen_range(40_000..60_000))
}

fn record_key_for_did(did: &str) -> RecordKey {
    let hash = compute_did_hash(did);
    let bytes = hash.into_bytes();
    RecordKey::new(&bytes)
}

fn apply_record_ttl(record: &mut Record, hint: &DhtHint) -> Result<()> {
    let now = OffsetDateTime::now_utc();
    if hint.expires_at <= now {
        return Err(anyhow!("refusing to publish expired DHT hint {}", hint.id));
    }
    let ttl_time = (hint.expires_at - now)
        .try_into()
        .unwrap_or_else(|_| StdDuration::from_secs(0));
    if ttl_time.is_zero() {
        return Err(anyhow!("DHT hint TTL computed to zero for {}", hint.id));
    }
    record.expires = Some(Instant::now() + ttl_time);
    Ok(())
}
