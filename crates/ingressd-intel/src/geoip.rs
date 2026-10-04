//! Optional offline GeoIP/ASN enrichment over a local MaxMind `.mmdb` database.
//!
//! Only compiled with `--features geoip`. There are **no** per-packet network
//! lookups — the DB is read from disk once at startup and queried in memory.

use std::net::IpAddr;
use std::path::Path;

use ingressd_core::intel::GeoSource;
use serde::Deserialize;

#[derive(Deserialize)]
struct Country {
    #[serde(default)]
    iso_code: Option<String>,
}

#[derive(Deserialize)]
struct Asn {
    #[serde(default)]
    number: Option<u32>,
}

/// A record tolerant of both the City and ASN schema shapes we may be pointed at.
#[derive(Deserialize)]
struct Record {
    #[serde(default)]
    country: Option<Country>,
    #[serde(default)]
    autonomous_system: Option<Asn>,
}

/// An in-memory MaxMind reader used as a [`GeoSource`].
pub struct GeoDb {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl GeoDb {
    /// Open a MaxMind database from disk into memory.
    pub fn open(path: impl AsRef<Path>) -> Result<GeoDb, Box<dyn std::error::Error + Send + Sync>> {
        // `open_read` loads the whole file into a Vec<u8> (no mmap requirement).
        let reader = maxminddb::Reader::open_read(path)?;
        Ok(GeoDb { reader })
    }
}

impl GeoSource for GeoDb {
    fn lookup(&self, ip: IpAddr) -> (Option<u32>, Option<String>) {
        let rec = match ip {
            IpAddr::V4(v4) => self.reader.lookup::<Record>(v4),
            IpAddr::V6(v6) => self.reader.lookup::<Record>(v6),
        };
        match rec {
            Ok(r) => (
                r.autonomous_system.and_then(|a| a.number),
                r.country.and_then(|c| c.iso_code),
            ),
            Err(_) => (None, None),
        }
    }
}
