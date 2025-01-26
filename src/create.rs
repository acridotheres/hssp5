use crate::{Compression, FileWithSource};
use acr::{
    encryption::aes256cbc,
    hash::{murmur3, sha256},
};
use dh::{recommended::*, Readable, Rw, Writable};
use std::io::Result;

pub fn create<'a>(
    version: u8,
    sources: Vec<FileWithSource<'a>>,
    encryption: Option<(&str, &[u8; 16])>,
    compression: Option<Compression>,
    main_file: Option<u32>,
    target: &'a mut dyn Rw<'a>,
    buffer_size: u64,
) -> Result<(u64, u32)> {
    todo!();
}
