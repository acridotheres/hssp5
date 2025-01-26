use crate::Metadata;
use dh::{recommended::*, Readable, Writable};
use std::io::Result;

pub fn extract<'a>(
    source: &'a mut dyn Readable<'a>,
    meta: &'a Metadata,
    file: usize,
    target: &'a mut dyn Writable<'a>,
    buffer_size: u64,
    target_pos: u64,
) -> Result<()> {
    let mut reader;
    let mut offset = 128;
    let src = if meta.compression.is_some()
        && meta.compression.as_ref().unwrap().decompressed.is_some()
    {
        offset = 0;
        reader = dh::data::read_ref(
            meta.compression
                .as_ref()
                .unwrap()
                .decompressed
                .as_ref()
                .unwrap(),
        );
        &mut reader
    } else {
        source
    };
    let src = if meta.encryption.is_some() {
        offset = 0;
        reader = dh::data::read_ref(&meta.encryption.as_ref().unwrap().decrypted);
        &mut reader
    } else {
        src
    };
    src.copy_to_at(
        meta.files[file].offset + offset,
        target_pos,
        meta.files[file].length,
        target,
        buffer_size,
    )?;
    Ok(())
}
