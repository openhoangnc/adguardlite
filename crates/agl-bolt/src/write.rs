//! Writing a bbolt database.
//!
//! The whole file is rebuilt from scratch on every write.  That is the right
//! trade here: AdGuard Home's statistics database holds a few dozen small
//! buckets and is flushed periodically, so rewriting it costs little and
//! avoids implementing incremental page allocation, free-list reuse and node
//! splitting — the parts of the format most likely to produce a file that Go
//! then refuses to open.

use std::collections::BTreeMap;
use std::path::Path;

use crate::page::{
    BUCKET_HEADER, BUCKET_LEAF_FLAG, BucketHeader, FLAG_FREELIST, FLAG_LEAF, LEAF_ELEM, LeafElem,
    Meta, PAGE_HEADER, PageHeader,
};
use crate::{Error, Result};

/// The largest a bucket may be and still be stored inline, matching bbolt's
/// `maxInlineBucketSize`.
fn max_inline(page_size: usize) -> usize {
    page_size / 4
}

/// A bucket to write: its keys in order.
pub type BucketData = BTreeMap<Vec<u8>, Vec<u8>>;

/// Writes a database containing the given top-level buckets.
///
/// The file is written to a sibling temporary path and renamed over `path`, so
/// an interrupted write cannot leave a half-built database behind.
pub fn write_file(
    path: &Path,
    buckets: &BTreeMap<Vec<u8>, BucketData>,
    page_size: usize,
) -> Result<()> {
    let bytes = build(buckets, page_size)?;

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }

    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &bytes)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }

    std::fs::rename(&tmp, path)?;

    Ok(())
}

/// Builds a complete database image.
pub fn build(buckets: &BTreeMap<Vec<u8>, BucketData>, page_size: usize) -> Result<Vec<u8>> {
    if page_size < 512 || !page_size.is_power_of_two() {
        return Err(Error::Unsupported(format!("page size {page_size}")));
    }

    // Pages 0 and 1 are the meta pages and 2 is the free list.  The root
    // bucket's leaf page starts at 3 and may overflow, so the pages holding
    // buckets too large to inline can only be placed once the root's size is
    // known.
    const META_A: u64 = 0;
    const META_B: u64 = 1;
    const FREELIST: u64 = 2;
    const ROOT: u64 = 3;

    // Pass one: decide inline or spilled, without assigning any page numbers.
    enum Planned {
        /// Stored inside the root page, with its encoded body.
        Inline(Vec<u8>),
        /// Stored on its own pages, with the page image and its page count.
        Spilled(Vec<u8>, usize),
    }

    let mut planned: Vec<(Vec<u8>, Planned)> = Vec::with_capacity(buckets.len());
    for (name, data) in buckets {
        let body = encode_leaf_body(data)?;
        if BUCKET_HEADER + body.len() <= max_inline(page_size) {
            planned.push((name.clone(), Planned::Inline(body)));

            continue;
        }

        // The page id is patched in below, once the root's extent is known.
        let page = build_leaf_page(0, data, page_size)?;
        let pages = page.len() / page_size;
        planned.push((name.clone(), Planned::Spilled(page, pages)));
    }

    // Pass two: the root page's size depends only on the value *lengths*, and
    // a spilled bucket's value is always a bare 16-byte header, so the root
    // can be sized before any page is assigned.
    let sizing: BucketData = planned
        .iter()
        .map(|(name, p)| {
            let len = match p {
                Planned::Inline(body) => BUCKET_HEADER + body.len(),
                Planned::Spilled(..) => BUCKET_HEADER,
            };

            (name.clone(), vec![0u8; len])
        })
        .collect();
    let root_pages =
        build_leaf_page_flagged(ROOT, &sizing, page_size, BUCKET_LEAF_FLAG)?.len() / page_size;

    // Pass three: assign pages to the spilled buckets and build the real root.
    let mut next_page = ROOT + root_pages as u64;
    let mut spilled: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut root_entries: BucketData = BTreeMap::new();

    for (name, p) in planned {
        match p {
            Planned::Inline(body) => {
                let mut v = vec![0u8; BUCKET_HEADER];
                BucketHeader {
                    root: 0,
                    sequence: 0,
                }
                .write(&mut v);
                v.extend_from_slice(&body);
                root_entries.insert(name, v);
            }
            Planned::Spilled(mut page, pages) => {
                let id = next_page;
                next_page += pages as u64;

                // Patch the page id now that it is known.
                let overflow = u32::try_from(pages - 1)
                    .map_err(|_| Error::Unsupported("bucket spans too many pages".into()))?;
                let count = u16::from_le_bytes(page[10..12].try_into().expect("2 bytes"));
                PageHeader {
                    id,
                    flags: FLAG_LEAF,
                    count,
                    overflow,
                }
                .write(&mut page);

                let mut v = vec![0u8; BUCKET_HEADER];
                BucketHeader {
                    root: id,
                    sequence: 0,
                }
                .write(&mut v);
                root_entries.insert(name, v);
                spilled.push((id, page));
            }
        }
    }

    let root_page = build_leaf_page_flagged(ROOT, &root_entries, page_size, BUCKET_LEAF_FLAG)?;
    debug_assert_eq!(
        root_page.len() / page_size,
        root_pages,
        "the root page must occupy what its sizing pass predicted"
    );

    let total_pages = next_page;
    let mut out = vec![0u8; total_pages as usize * page_size];

    // Free list: empty, since nothing is ever reused in a fresh file.
    {
        let off = FREELIST as usize * page_size;
        PageHeader {
            id: FREELIST,
            flags: FLAG_FREELIST,
            count: 0,
            overflow: 0,
        }
        .write(&mut out[off..]);
    }

    let put = |out: &mut Vec<u8>, id: u64, page: &[u8]| {
        let off = id as usize * page_size;
        out[off..off + page.len()].copy_from_slice(page);
    };

    put(&mut out, ROOT, &root_page);
    for (id, page) in &spilled {
        put(&mut out, *id, page);
    }

    // Both meta pages describe the same state; bbolt picks the higher txid.
    let meta = Meta {
        magic: crate::MAGIC,
        version: crate::VERSION,
        page_size: page_size as u32,
        flags: 0,
        root: ROOT,
        root_sequence: 0,
        freelist: FREELIST,
        pgid: total_pages,
        txid: 2,
        checksum: 0,
    };

    let mut a = vec![0u8; page_size];
    meta.write(&mut a, META_A);
    put(&mut out, META_A, &a);

    let mut b = vec![0u8; page_size];
    Meta { txid: 3, ..meta }.write(&mut b, META_B);
    put(&mut out, META_B, &b);

    Ok(out)
}

/// Encodes a leaf page's body — header, element table and data — with no
/// padding, for embedding as an inline bucket.
fn encode_leaf_body(data: &BucketData) -> Result<Vec<u8>> {
    encode_leaf_body_flagged(data, 0)
}

/// Encodes a leaf page body, tagging every element with `elem_flags`.
fn encode_leaf_body_flagged(data: &BucketData, elem_flags: u32) -> Result<Vec<u8>> {
    let count = u16::try_from(data.len())
        .map_err(|_| Error::Unsupported(format!("{} keys in one bucket", data.len())))?;

    let table = PAGE_HEADER + data.len() * LEAF_ELEM;
    let mut body = vec![0u8; table];

    // The inline page's own id is unused by readers; bbolt writes zero.
    PageHeader {
        id: 0,
        flags: FLAG_LEAF,
        count,
        overflow: 0,
    }
    .write(&mut body);

    for (i, (k, v)) in data.iter().enumerate() {
        let elem_off = PAGE_HEADER + i * LEAF_ELEM;
        // `pos` is measured from the element itself to its key.
        let pos = body.len() - elem_off;

        LeafElem {
            flags: elem_flags,
            pos: u32::try_from(pos).map_err(|_| Error::Unsupported("bucket too large".into()))?,
            ksize: u32::try_from(k.len())
                .map_err(|_| Error::Unsupported("key too large".into()))?,
            vsize: u32::try_from(v.len())
                .map_err(|_| Error::Unsupported("value too large".into()))?,
        }
        .write(&mut body[elem_off..]);

        body.extend_from_slice(k);
        body.extend_from_slice(v);
    }

    Ok(body)
}

/// Builds a standalone leaf page, padded to a whole number of pages.
fn build_leaf_page(id: u64, data: &BucketData, page_size: usize) -> Result<Vec<u8>> {
    build_leaf_page_flagged(id, data, page_size, 0)
}

/// Builds a standalone leaf page whose elements carry `elem_flags`.
fn build_leaf_page_flagged(
    id: u64,
    data: &BucketData,
    page_size: usize,
    elem_flags: u32,
) -> Result<Vec<u8>> {
    let mut body = encode_leaf_body_flagged(data, elem_flags)?;

    let pages = body.len().div_ceil(page_size).max(1);
    body.resize(pages * page_size, 0);

    let overflow = u32::try_from(pages - 1)
        .map_err(|_| Error::Unsupported("bucket spans too many pages".into()))?;
    PageHeader {
        id,
        flags: FLAG_LEAF,
        count: data.len() as u16,
        overflow,
    }
    .write(&mut body);

    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Db;

    fn bucket(pairs: &[(&[u8], &[u8])]) -> BucketData {
        pairs
            .iter()
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect()
    }

    fn hour_name(h: u64) -> Vec<u8> {
        h.to_be_bytes().to_vec()
    }

    #[test]
    fn a_written_database_reads_back() {
        let mut buckets = BTreeMap::new();
        buckets.insert(hour_name(497_049), bucket(&[(&[0], b"first payload")]));
        buckets.insert(hour_name(497_050), bucket(&[(&[0], b"second payload")]));

        let bytes = build(&buckets, 4096).unwrap();
        let db = Db::from_bytes(bytes).unwrap();
        let back = db.buckets().unwrap();

        assert_eq!(back.len(), 2);
        assert_eq!(
            back[&hour_name(497_049)][&vec![0u8]],
            b"first payload".to_vec()
        );
        assert_eq!(
            back[&hour_name(497_050)][&vec![0u8]],
            b"second payload".to_vec()
        );
    }

    #[test]
    fn a_large_bucket_gets_its_own_page() {
        // Well past the inline threshold of page_size/4.
        let big = vec![0xABu8; 8000];
        let mut buckets = BTreeMap::new();
        buckets.insert(hour_name(1), bucket(&[(&[0], &big)]));
        buckets.insert(hour_name(2), bucket(&[(&[0], b"small")]));

        let bytes = build(&buckets, 4096).unwrap();
        let db = Db::from_bytes(bytes).unwrap();
        let back = db.buckets().unwrap();

        assert_eq!(back[&hour_name(1)][&vec![0u8]], big);
        assert_eq!(back[&hour_name(2)][&vec![0u8]], b"small".to_vec());
    }

    #[test]
    fn many_buckets_round_trip() {
        // A month of hourly units, the largest window the UI offers.
        let mut buckets = BTreeMap::new();
        for h in 0..24u64 * 30 {
            buckets.insert(
                hour_name(500_000 + h),
                bucket(&[(&[0], format!("unit {h}").as_bytes())]),
            );
        }

        let bytes = build(&buckets, 16384).unwrap();
        let db = Db::from_bytes(bytes).unwrap();
        let back = db.buckets().unwrap();

        assert_eq!(back.len(), 720);
        assert_eq!(back[&hour_name(500_100)][&vec![0u8]], b"unit 100".to_vec());
    }

    #[test]
    fn an_empty_database_round_trips() {
        let bytes = build(&BTreeMap::new(), 4096).unwrap();
        let db = Db::from_bytes(bytes).unwrap();
        assert!(db.buckets().unwrap().is_empty());
    }

    #[test]
    fn both_meta_pages_verify() {
        let mut buckets = BTreeMap::new();
        buckets.insert(hour_name(1), bucket(&[(&[0], b"x")]));
        let bytes = build(&buckets, 4096).unwrap();

        for i in 0..2usize {
            let page = &bytes[i * 4096..(i + 1) * 4096];
            let m = Meta::parse(page).expect("meta must parse");
            assert!(m.checksum_ok(page), "meta page {i} checksum must verify");
            assert_eq!(m.page_size, 4096);
        }
    }

    #[test]
    fn rejects_an_implausible_page_size() {
        assert!(build(&BTreeMap::new(), 100).is_err());
        assert!(
            build(&BTreeMap::new(), 5000).is_err(),
            "must be a power of two"
        );
    }

    #[test]
    fn writes_and_reopens_a_real_file() {
        let dir = std::env::temp_dir().join(format!("agl-bolt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("stats.db");

        let mut buckets = BTreeMap::new();
        buckets.insert(hour_name(42), bucket(&[(&[0], b"payload")]));
        write_file(&p, &buckets, 4096).unwrap();

        let db = Db::open(&p).unwrap();
        assert_eq!(
            db.buckets().unwrap()[&hour_name(42)][&vec![0u8]],
            b"payload".to_vec()
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
