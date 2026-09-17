//! Page and meta layouts.

use crate::{Error, Result};

/// The size of a page header.
pub const PAGE_HEADER: usize = 16;

/// The size of a leaf page element.
pub const LEAF_ELEM: usize = 16;

/// The size of a branch page element.
pub const BRANCH_ELEM: usize = 16;

/// The size of a bucket header stored as a leaf value.
pub const BUCKET_HEADER: usize = 16;

/// The bytes of a meta struct that the checksum covers.
pub const META_CHECKSUMMED: usize = 56;

/// Page flag: an interior B+tree node.
pub const FLAG_BRANCH: u16 = 0x01;

/// Page flag: a leaf node.
pub const FLAG_LEAF: u16 = 0x02;

/// Page flag: a meta page.
pub const FLAG_META: u16 = 0x04;

/// Page flag: the free list.
pub const FLAG_FREELIST: u16 = 0x10;

/// Leaf element flag: the value is a nested bucket.
pub const BUCKET_LEAF_FLAG: u32 = 0x01;

/// A page header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageHeader {
    /// The page's identifier, which is also its index in the file.
    pub id: u64,
    /// What kind of page this is.
    pub flags: u16,
    /// How many elements the page holds.
    pub count: u16,
    /// How many extra pages this page spills onto.
    pub overflow: u32,
}

impl PageHeader {
    /// Reads a page header from the start of `b`.
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() < PAGE_HEADER {
            return Err(Error::Corrupt("page header truncated".into()));
        }

        Ok(PageHeader {
            id: u64::from_le_bytes(b[0..8].try_into().expect("8 bytes")),
            flags: u16::from_le_bytes(b[8..10].try_into().expect("2 bytes")),
            count: u16::from_le_bytes(b[10..12].try_into().expect("2 bytes")),
            overflow: u32::from_le_bytes(b[12..16].try_into().expect("4 bytes")),
        })
    }

    /// Writes the header into the start of `b`.
    pub fn write(&self, b: &mut [u8]) {
        b[0..8].copy_from_slice(&self.id.to_le_bytes());
        b[8..10].copy_from_slice(&self.flags.to_le_bytes());
        b[10..12].copy_from_slice(&self.count.to_le_bytes());
        b[12..16].copy_from_slice(&self.overflow.to_le_bytes());
    }
}

/// The contents of a meta page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Meta {
    /// Must equal [`crate::MAGIC`].
    pub magic: u32,
    /// The file format version.
    pub version: u32,
    /// The page size this file uses.
    pub page_size: u32,
    /// Reserved.
    pub flags: u32,
    /// The page holding the root bucket.
    pub root: u64,
    /// The root bucket's sequence counter.
    pub root_sequence: u64,
    /// The page holding the free list.
    pub freelist: u64,
    /// One past the highest allocated page.
    pub pgid: u64,
    /// The transaction that wrote this meta page.
    pub txid: u64,
    /// An FNV-1a hash of everything above.
    pub checksum: u64,
}

impl Meta {
    /// Reads a meta page's contents, which follow the page header.
    pub fn parse(page: &[u8]) -> Result<Self> {
        if page.len() < PAGE_HEADER + META_CHECKSUMMED + 8 {
            return Err(Error::Corrupt("meta page truncated".into()));
        }

        let b = &page[PAGE_HEADER..];
        let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().expect("4 bytes"));
        let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().expect("8 bytes"));

        let m = Meta {
            magic: u32_at(0),
            version: u32_at(4),
            page_size: u32_at(8),
            flags: u32_at(12),
            root: u64_at(16),
            root_sequence: u64_at(24),
            freelist: u64_at(32),
            pgid: u64_at(40),
            txid: u64_at(48),
            checksum: u64_at(56),
        };

        if m.magic != crate::MAGIC {
            return Err(Error::NotBolt(format!("bad magic {:#x}", m.magic)));
        }
        if m.version != crate::VERSION {
            return Err(Error::Unsupported(format!("version {}", m.version)));
        }

        Ok(m)
    }

    /// Reports whether the stored checksum matches the contents.
    pub fn checksum_ok(&self, page: &[u8]) -> bool {
        let start = PAGE_HEADER;
        let end = start + META_CHECKSUMMED;
        if page.len() < end {
            return false;
        }

        crate::fnv1a64(&page[start..end]) == self.checksum
    }

    /// Writes the meta page, including its header and checksum.
    pub fn write(&self, page: &mut [u8], page_id: u64) {
        PageHeader {
            id: page_id,
            flags: FLAG_META,
            count: 0,
            overflow: 0,
        }
        .write(page);

        let b = &mut page[PAGE_HEADER..];
        b[0..4].copy_from_slice(&self.magic.to_le_bytes());
        b[4..8].copy_from_slice(&self.version.to_le_bytes());
        b[8..12].copy_from_slice(&self.page_size.to_le_bytes());
        b[12..16].copy_from_slice(&self.flags.to_le_bytes());
        b[16..24].copy_from_slice(&self.root.to_le_bytes());
        b[24..32].copy_from_slice(&self.root_sequence.to_le_bytes());
        b[32..40].copy_from_slice(&self.freelist.to_le_bytes());
        b[40..48].copy_from_slice(&self.pgid.to_le_bytes());
        b[48..56].copy_from_slice(&self.txid.to_le_bytes());

        let sum = crate::fnv1a64(&page[PAGE_HEADER..PAGE_HEADER + META_CHECKSUMMED]);
        page[PAGE_HEADER + 56..PAGE_HEADER + 64].copy_from_slice(&sum.to_le_bytes());
    }
}

/// One entry of a leaf page.
#[derive(Clone, Copy, Debug)]
pub struct LeafElem {
    /// Whether the value is a nested bucket.
    pub flags: u32,
    /// The offset from this element to its key.
    pub pos: u32,
    /// The key's length.
    pub ksize: u32,
    /// The value's length.
    pub vsize: u32,
}

impl LeafElem {
    /// Reads a leaf element from the start of `b`.
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() < LEAF_ELEM {
            return Err(Error::Corrupt("leaf element truncated".into()));
        }

        Ok(LeafElem {
            flags: u32::from_le_bytes(b[0..4].try_into().expect("4 bytes")),
            pos: u32::from_le_bytes(b[4..8].try_into().expect("4 bytes")),
            ksize: u32::from_le_bytes(b[8..12].try_into().expect("4 bytes")),
            vsize: u32::from_le_bytes(b[12..16].try_into().expect("4 bytes")),
        })
    }

    /// Writes the element into the start of `b`.
    pub fn write(&self, b: &mut [u8]) {
        b[0..4].copy_from_slice(&self.flags.to_le_bytes());
        b[4..8].copy_from_slice(&self.pos.to_le_bytes());
        b[8..12].copy_from_slice(&self.ksize.to_le_bytes());
        b[12..16].copy_from_slice(&self.vsize.to_le_bytes());
    }

    /// Reports whether this element holds a nested bucket.
    pub fn is_bucket(&self) -> bool {
        self.flags & BUCKET_LEAF_FLAG != 0
    }
}

/// One entry of a branch page.
#[derive(Clone, Copy, Debug)]
pub struct BranchElem {
    /// The offset from this element to its key.
    pub pos: u32,
    /// The key's length.
    pub ksize: u32,
    /// The child page.
    pub pgid: u64,
}

impl BranchElem {
    /// Reads a branch element from the start of `b`.
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() < BRANCH_ELEM {
            return Err(Error::Corrupt("branch element truncated".into()));
        }

        Ok(BranchElem {
            pos: u32::from_le_bytes(b[0..4].try_into().expect("4 bytes")),
            ksize: u32::from_le_bytes(b[4..8].try_into().expect("4 bytes")),
            pgid: u64::from_le_bytes(b[8..16].try_into().expect("8 bytes")),
        })
    }
}

/// A bucket header, stored as the value of a bucket leaf element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BucketHeader {
    /// The page holding the bucket's root, or 0 when the bucket is inline.
    pub root: u64,
    /// The bucket's sequence counter.
    pub sequence: u64,
}

impl BucketHeader {
    /// Reads a bucket header from the start of `b`.
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() < BUCKET_HEADER {
            return Err(Error::Corrupt("bucket header truncated".into()));
        }

        Ok(BucketHeader {
            root: u64::from_le_bytes(b[0..8].try_into().expect("8 bytes")),
            sequence: u64::from_le_bytes(b[8..16].try_into().expect("8 bytes")),
        })
    }

    /// Writes the header into the start of `b`.
    pub fn write(&self, b: &mut [u8]) {
        b[0..8].copy_from_slice(&self.root.to_le_bytes());
        b[8..16].copy_from_slice(&self.sequence.to_le_bytes());
    }

    /// Reports whether the bucket's contents are stored inline.
    pub fn is_inline(&self) -> bool {
        self.root == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_headers_round_trip() {
        let h = PageHeader {
            id: 42,
            flags: FLAG_LEAF,
            count: 3,
            overflow: 1,
        };
        let mut b = [0u8; PAGE_HEADER];
        h.write(&mut b);
        assert_eq!(PageHeader::parse(&b).unwrap(), h);
    }

    #[test]
    fn leaf_elements_round_trip() {
        let e = LeafElem {
            flags: BUCKET_LEAF_FLAG,
            pos: 32,
            ksize: 8,
            vsize: 309,
        };
        let mut b = [0u8; LEAF_ELEM];
        e.write(&mut b);
        let back = LeafElem::parse(&b).unwrap();
        assert_eq!(back.pos, 32);
        assert_eq!(back.ksize, 8);
        assert_eq!(back.vsize, 309);
        assert!(back.is_bucket());
    }

    #[test]
    fn bucket_headers_round_trip() {
        let h = BucketHeader {
            root: 0,
            sequence: 7,
        };
        let mut b = [0u8; BUCKET_HEADER];
        h.write(&mut b);
        assert_eq!(BucketHeader::parse(&b).unwrap(), h);
        assert!(h.is_inline());
        assert!(
            !BucketHeader {
                root: 5,
                sequence: 0
            }
            .is_inline()
        );
    }

    #[test]
    fn meta_pages_round_trip_with_a_valid_checksum() {
        let m = Meta {
            magic: crate::MAGIC,
            version: crate::VERSION,
            page_size: 4096,
            flags: 0,
            root: 2,
            root_sequence: 0,
            freelist: 3,
            pgid: 8,
            txid: 5,
            checksum: 0,
        };

        let mut page = vec![0u8; 4096];
        m.write(&mut page, 0);

        let back = Meta::parse(&page).unwrap();
        assert_eq!(back.root, 2);
        assert_eq!(back.txid, 5);
        assert_eq!(back.page_size, 4096);
        assert!(back.checksum_ok(&page), "the written checksum must verify");

        // A single flipped byte must invalidate it.
        page[PAGE_HEADER + 20] ^= 0xFF;
        let tampered = Meta::parse(&page).unwrap();
        assert!(!tampered.checksum_ok(&page));
    }

    #[test]
    fn rejects_files_that_are_not_bolt() {
        let page = vec![0u8; 4096];
        assert!(matches!(Meta::parse(&page), Err(Error::NotBolt(_))));
    }
}
