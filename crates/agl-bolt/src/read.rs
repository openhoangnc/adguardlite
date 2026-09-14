//! Reading a bbolt database.

use std::collections::BTreeMap;
use std::path::Path;

use crate::page::{
    BUCKET_HEADER, BranchElem, BucketHeader, FLAG_BRANCH, FLAG_LEAF, LEAF_ELEM, LeafElem, Meta,
    PAGE_HEADER, PageHeader,
};
use crate::{Error, Result};

/// The keys one bucket holds, in order.
pub type BucketKeys = BTreeMap<Vec<u8>, Vec<u8>>;

/// Every top-level bucket, keyed by name.
pub type Buckets = BTreeMap<Vec<u8>, BucketKeys>;

/// An open database, held in memory.
///
/// The files this reads are small — AdGuard Home's statistics database is a
/// few hundred kilobytes — so the whole thing is loaded rather than mapped.
pub struct Db {
    data: Vec<u8>,
    page_size: usize,
    root: u64,
}

impl Db {
    /// Opens a database file.
    pub fn open(path: &Path) -> Result<Self> {
        Self::from_bytes(std::fs::read(path)?)
    }

    /// Opens a database from its bytes.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        if data.len() < 64 {
            return Err(Error::NotBolt("file too short".into()));
        }

        // The page size is only known after reading a meta page, and the meta
        // page is at a page-size offset — so read meta 0 from the start, which
        // is at offset 0 whatever the page size is.
        let m0 = Meta::parse(&data[..data.len().min(4096)])?;
        let page_size = m0.page_size as usize;
        if !(512..=1 << 20).contains(&page_size) || !page_size.is_power_of_two() {
            return Err(Error::Corrupt(format!("implausible page size {page_size}")));
        }

        let db = Db {
            data,
            page_size,
            root: 0,
        };

        // Both meta pages are candidates; the newer valid one wins.
        let mut best: Option<Meta> = None;
        for i in 0..2u64 {
            let Ok(page) = db.page_bytes(i) else { continue };
            let Ok(m) = Meta::parse(page) else { continue };
            if !m.checksum_ok(page) {
                continue;
            }
            if best.is_none_or(|b| m.txid > b.txid) {
                best = Some(m);
            }
        }

        let meta = best.ok_or_else(|| Error::Corrupt("no valid meta page".into()))?;

        Ok(Db {
            root: meta.root,
            ..db
        })
    }

    /// The page size this file uses.
    pub fn page_size(&self) -> usize {
        self.page_size
    }

    /// Returns the bytes of one page, including its header.
    fn page_bytes(&self, id: u64) -> Result<&[u8]> {
        let start = (id as usize)
            .checked_mul(self.page_size)
            .ok_or_else(|| Error::Corrupt("page offset overflow".into()))?;
        let end = start
            .checked_add(self.page_size)
            .ok_or_else(|| Error::Corrupt("page offset overflow".into()))?;
        if end > self.data.len() {
            return Err(Error::Corrupt(format!(
                "page {id} is past the end of the file"
            )));
        }

        Ok(&self.data[start..end])
    }

    /// Returns a page and everything it overflows onto.
    fn page_with_overflow(&self, id: u64) -> Result<&[u8]> {
        let h = PageHeader::parse(self.page_bytes(id)?)?;
        let pages = 1 + h.overflow as usize;
        let start = id as usize * self.page_size;
        let end = (start + pages * self.page_size).min(self.data.len());

        Ok(&self.data[start..end])
    }

    /// Reads every top-level bucket and the keys it holds.
    ///
    /// The returned map is keyed by bucket name; each value maps the bucket's
    /// keys to their values.
    pub fn buckets(&self) -> Result<Buckets> {
        let mut out = BTreeMap::new();
        let mut entries = Vec::new();
        self.walk(self.root, &mut entries)?;

        for (name, elem_flags, value) in entries {
            if elem_flags & crate::page::BUCKET_LEAF_FLAG == 0 {
                // A bare key at the top level is not a bucket; stats.db has
                // none, but skipping is kinder than failing.
                continue;
            }

            out.insert(name, self.read_bucket(&value)?);
        }

        Ok(out)
    }

    /// Reads a bucket's keys from its stored header and inline data.
    fn read_bucket(&self, value: &[u8]) -> Result<BucketKeys> {
        let hdr = BucketHeader::parse(value)?;

        let mut entries = Vec::new();
        if hdr.is_inline() {
            // The bucket's page follows its header, inside this value.
            let inline = &value[BUCKET_HEADER..];
            self.walk_page(inline, &mut entries)?;
        } else {
            self.walk(hdr.root, &mut entries)?;
        }

        Ok(entries.into_iter().map(|(k, _, v)| (k, v)).collect())
    }

    /// Walks the subtree rooted at `id`, collecting leaf entries.
    fn walk(&self, id: u64, out: &mut Vec<(Vec<u8>, u32, Vec<u8>)>) -> Result<()> {
        let page = self.page_with_overflow(id)?;

        self.walk_page(page, out)
    }

    /// Walks one page's contents, following branch pages.
    fn walk_page(&self, page: &[u8], out: &mut Vec<(Vec<u8>, u32, Vec<u8>)>) -> Result<()> {
        let h = PageHeader::parse(page)?;
        let count = h.count as usize;

        if h.flags & FLAG_LEAF != 0 {
            for i in 0..count {
                let eo = PAGE_HEADER + i * LEAF_ELEM;
                let e = LeafElem::parse(&page[eo..])?;

                let ks = e.ksize as usize;
                let vs = e.vsize as usize;
                let key_at = eo + e.pos as usize;
                let val_at = key_at + ks;
                if val_at + vs > page.len() {
                    return Err(Error::Corrupt("leaf entry runs past the page".into()));
                }

                out.push((
                    page[key_at..key_at + ks].to_vec(),
                    e.flags,
                    page[val_at..val_at + vs].to_vec(),
                ));
            }

            return Ok(());
        }

        if h.flags & FLAG_BRANCH != 0 {
            for i in 0..count {
                let eo = PAGE_HEADER + i * crate::page::BRANCH_ELEM;
                let e = BranchElem::parse(&page[eo..])?;
                self.walk(e.pgid, out)?;
            }

            return Ok(());
        }

        Err(Error::Corrupt(format!(
            "unexpected page flags {:#x}",
            h.flags
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A statistics database written by a real AdGuard Home v0.107.79.
    fn real_db() -> Db {
        use std::io::Read as _;

        let gz: &[u8] = include_bytes!("../../../tests/fixtures/stats/go-stats.db.gz");
        let mut data = Vec::new();
        flate2::read::GzDecoder::new(gz)
            .read_to_end(&mut data)
            .expect("fixture must decompress");

        Db::from_bytes(data).expect("the fixture must open")
    }

    #[test]
    fn opens_a_database_written_by_go() {
        let db = real_db();
        assert_eq!(db.page_size(), 16384);
    }

    #[test]
    fn reads_the_hourly_buckets_go_wrote() {
        let db = real_db();
        let buckets = db.buckets().expect("buckets must parse");

        assert!(!buckets.is_empty(), "the fixture holds statistics");

        for (name, keys) in &buckets {
            // Bucket names are the absolute hour number, big-endian.
            assert_eq!(name.len(), 8, "bucket names are 8-byte hour numbers");
            let hour = u64::from_be_bytes(name[..].try_into().unwrap());
            assert!(
                (400_000..1_000_000).contains(&hour),
                "hour {hour} should be a plausible absolute hour"
            );

            // Each bucket holds exactly the single key upstream writes.
            assert_eq!(keys.len(), 1, "each unit stores one value");
            assert!(keys.contains_key(&vec![0u8]), "under the key [0]");
            assert!(!keys[&vec![0u8]].is_empty(), "with a gob payload");
        }
    }

    #[test]
    fn rejects_a_file_that_is_not_bolt() {
        assert!(matches!(
            Db::from_bytes(vec![0u8; 8192]),
            Err(Error::NotBolt(_))
        ));
        assert!(matches!(
            Db::from_bytes(vec![1, 2, 3]),
            Err(Error::NotBolt(_))
        ));
    }
}
