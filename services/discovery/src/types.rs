use std::net::SocketAddr;

use anyhow::Result;
use hn_cli::identity::IdentityRecord;
use hostname::get;
use serde::Serialize;
use time::OffsetDateTime;

use crate::peer_table::PeerRecord;

#[derive(Clone, Debug)]
pub struct LocalPeer {
    pub did: String,
    pub alias: String,
    pub capabilities: Vec<String>,
    pub listen_addr: SocketAddr,
    pub service_type: String,
    pub service_instance: String,
    pub host_name: String,
    pub http_host: String,
}

impl LocalPeer {
    pub fn from_identity(
        identity: IdentityRecord,
        listen_addr: SocketAddr,
        service_type: String,
    ) -> Result<Self> {
        let did = identity.profile.id.clone();
        let alias = identity.profile.alias.clone();
        let alias_slug = slugify(&alias);
        let did_slug = identity.keys.did_slug();
        let service_instance = format!("hn-{}-{}", alias_slug, did_slug);

        let host = get()?.to_string_lossy().to_string();
        let host_label = slugify(&host);
        let host_name = if host_label.ends_with(".local") {
            format!("{host_label}.")
        } else {
            format!("{host_label}.local.")
        };
        let http_host = host_name.trim_end_matches('.').to_string();

        Ok(Self {
            did,
            alias,
            capabilities: identity.profile.capabilities.clone(),
            listen_addr,
            service_type,
            service_instance,
            host_name,
            http_host,
        })
    }

    pub fn http_endpoint(&self) -> String {
        format!("http://{}:{}", self.http_host, self.listen_addr.port())
    }

    pub fn properties(&self) -> Vec<(String, String)> {
        let mut props = Vec::new();
        props.push(("did".to_string(), self.did.clone()));
        props.push(("alias".to_string(), self.alias.clone()));
        props.push(("http".to_string(), self.http_endpoint()));
        if !self.capabilities.is_empty() {
            props.push(("capabilities".to_string(), self.capabilities.join(",")));
        }
        props
    }
}

pub fn slugify(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'a'..='z' | '0'..='9' => c,
            'A'..='Z' => c.to_ascii_lowercase(),
            _ => '-',
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

#[derive(Debug, Clone, Serialize)]
pub struct PeerPayload {
    pub did: String,
    pub alias: String,
    pub addresses: Vec<String>,
    pub endpoints: Vec<String>,
    pub capabilities: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen: OffsetDateTime,
}

impl From<PeerRecord> for PeerPayload {
    fn from(value: PeerRecord) -> Self {
        Self {
            did: value.did,
            alias: value.alias,
            addresses: value.addresses,
            endpoints: value.endpoints,
            capabilities: value.capabilities,
            last_seen: value.last_seen,
        }
    }
}
