use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use flume::RecvTimeoutError;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use time::OffsetDateTime;
use tracing::{debug, info, warn};

use crate::peer_table::{PeerRecord, PeerTable};
use crate::types::LocalPeer;

pub struct MdnsHandle {
    stop: Arc<AtomicBool>,
    daemon: Arc<ServiceDaemon>,
    service_fullname: String,
    browse_handle: Option<thread::JoinHandle<()>>,
}

impl MdnsHandle {
    pub fn start(local_peer: LocalPeer, peer_table: PeerTable) -> Result<Self> {
        let daemon = Arc::new(ServiceDaemon::new()?);
        let properties = local_peer.properties();
        let property_refs: Vec<(&str, &str)> = properties
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let mut info = ServiceInfo::new(
            &local_peer.service_type,
            &local_peer.service_instance,
            &local_peer.host_name,
            (),
            local_peer.listen_addr.port(),
            &property_refs[..],
        )
        .context("failed to build service info for mDNS announcement")?;

        info = info.enable_addr_auto();

        daemon
            .register(info.clone())
            .context("failed to register mDNS service")?;
        let service_fullname = info.get_fullname().to_string();
        info!(service = %service_fullname, "registered mDNS announcement");

        let receiver = daemon
            .browse(&local_peer.service_type)
            .context("failed to start mDNS browser")?;

        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();
        let table_clone = peer_table.clone();
        let self_did = local_peer.did.clone();

        let browse_handle = thread::spawn(move || {
            while !stop_clone.load(Ordering::Relaxed) {
                match receiver.recv_timeout(Duration::from_secs(1)) {
                    Ok(event) => match event {
                        ServiceEvent::ServiceFound(_, _) => {
                            // The daemon resolves automatically; nothing to do here.
                        }
                        ServiceEvent::ServiceResolved(info) => {
                            if let Some(record) = build_peer_record(&info, &self_did) {
                                table_clone.update(record);
                            }
                        }
                        ServiceEvent::ServiceRemoved(_, fullname) => {
                            if table_clone.remove_by_service(&fullname) {
                                debug!(service = %fullname, "peer removed");
                            }
                        }
                        ServiceEvent::SearchStopped(_) => {
                            warn!("mDNS search stopped unexpectedly");
                            break;
                        }
                        ServiceEvent::SearchStarted(_) => {}
                    },
                    Err(RecvTimeoutError::Timeout) => continue,
                    Err(err) => {
                        warn!(%err, "mDNS receiver error");
                        break;
                    }
                }
            }
        });

        Ok(Self {
            stop,
            daemon,
            service_fullname,
            browse_handle: Some(browse_handle),
        })
    }

    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        match self.daemon.unregister(&self.service_fullname) {
            Ok(receiver) => {
                let _ = receiver.recv_timeout(Duration::from_secs(1));
            }
            Err(err) => warn!(%err, "failed to unregister mDNS service"),
        }
        if let Some(handle) = self.browse_handle.take() {
            if let Err(err) = handle.join() {
                warn!(?err, "failed to join mDNS browse thread");
            }
        }
        match self.daemon.shutdown() {
            Ok(receiver) => {
                let _ = receiver.recv_timeout(Duration::from_secs(1));
            }
            Err(err) => warn!(%err, "mDNS daemon shutdown error"),
        }
    }
}

fn build_peer_record(info: &ServiceInfo, self_did: &str) -> Option<PeerRecord> {
    let properties = info.get_properties();
    let did = properties.get_property_val_str("did")?;
    if did.is_empty() || did == self_did {
        return None;
    }
    let alias = properties
        .get_property_val_str("alias")
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
        .unwrap_or_else(|| info.get_hostname().to_string());
    let endpoints = properties
        .get_property_val_str("http")
        .filter(|value| !value.is_empty())
        .map(|value| vec![value.to_string()])
        .unwrap_or_default();
    let capabilities = properties
        .get_property_val_str("capabilities")
        .map(|value| {
            value
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();
    let addresses = info
        .get_addresses()
        .iter()
        .map(|addr| addr.to_string())
        .collect::<Vec<String>>();

    Some(PeerRecord {
        did: did.to_string(),
        alias,
        service_id: info.get_fullname().to_string(),
        addresses,
        endpoints,
        capabilities,
        last_seen: OffsetDateTime::now_utc(),
    })
}
