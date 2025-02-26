use crate::{Compression, Encryption, File, Metadata, Multivol};
use acr::{
    compression::{decompressor::decompress, Method},
    encryption::aes256cbc,
    hash::{murmur3, sha256},
};
use chrono::{DateTime, Utc};
use dh::{recommended::*, Readable};
use std::io::Result;

pub fn verify_integrity<'a>(reader: &'a mut dyn Readable<'a>, meta: &Metadata) -> Result<bool> {
    let hash = meta.checksum;
    let offset = 128;
    let size = reader.size()?;

    let calculated = murmur3(reader, offset, size - offset, 0x31082007)?;
    Ok(calculated == hash)
}

pub fn metadata<'a>(reader: &'a mut dyn Readable<'a>, password: Option<&str>) -> Result<Metadata> {
    reader.jump(4)?;
    let version = reader.read_u8()?;
    if version != 4 {
        unimplemented!("HSSP 5");
    } else {
        reader.jump(3)?;
    }

    let file_count = reader.read_u32le()?;
    let pwd_hash: [u8; 32] = reader.read_bytes(32)?.try_into().unwrap();
    let iv: [u8; 16] = reader.read_bytes(16)?.try_into().unwrap();

    let encrypted = !(pwd_hash == [0; 32] && iv == [0; 16]);
    let compression = reader.read_bytes(4)?.try_into().unwrap();
    let checksum = reader.read_u32le()?;

    let total_files = reader.read_u64le()?;
    let continue_offset = reader.read_u64le()?;
    let previous_checksum = reader.read_u32le()?;
    let next_checksum = reader.read_u32le()?;
    let id = reader.read_u32le()?;
    let multivol = if next_checksum != 0 || previous_checksum != 0 {
        Some(Multivol {
            total_files,
            continue_offset,
            previous_checksum: if previous_checksum != 0 {
                Some(previous_checksum)
            } else {
                None
            },
            next_checksum: if next_checksum != 0 {
                Some(next_checksum)
            } else {
                None
            },
            id,
        })
    } else {
        None
    };
    let comment = reader.read_utf8(16)?;
    let comment = comment.split('\0').next().unwrap().to_string();
    let generator = reader.read_utf8(16)?;
    let generator = generator.split('\0').next().unwrap().to_string();

    let compression_method = match &compression {
        b"NONE" => Method::None,
        b"LZMA" => Method::Lzma,
        b"DEFL" => Method::Deflate,
        b"DFLT" => Method::DeflateZlib,
        _ => Method::Unsupported,
    };
    let mut size = reader.size()? - 128;
    let mut decompressed = dh::data::write_new(size);
    size = decompress(
        reader,
        128,
        size,
        &compression_method,
        &mut decompressed,
        1024,
    )?;
    let mut decompressed = dh::data::close(decompressed);
    decompressed.truncate(size as usize);
    let mut r = dh::data::rw(decompressed);
    let reader = &mut r;

    let mut decrypted_reader = None;
    let body: &mut dyn Readable = if encrypted {
        if password.is_none() {
            return Ok(Metadata {
                version,
                checksum,
                encryption: Some(Encryption {
                    hash: [0; 32],
                    hash_expected: pwd_hash,
                    iv,
                    decrypted: vec![],
                }),
                files: vec![],
                comment: if !comment.is_empty() {
                    Some(comment)
                } else {
                    None
                },
                generator: if !generator.is_empty() {
                    Some(generator)
                } else {
                    None
                },
                compression: if compression_method != Method::None {
                    Some(Compression {
                        method: compression_method,
                        decompressed: None,
                    })
                } else {
                    None
                },
                multivol,
            });
        }

        let password = password.unwrap();

        let key = sha256(
            &mut dh::data::read_ref(password.as_bytes()),
            0,
            password.len() as u64,
        )?;

        let hash = sha256(&mut dh::data::read_ref(&key), 0, 32)?;

        if hash != pwd_hash {
            return Ok(Metadata {
                version,
                checksum,
                encryption: Some(Encryption {
                    hash,
                    hash_expected: pwd_hash,
                    iv,
                    decrypted: vec![],
                }),
                files: vec![],
                comment: if !comment.is_empty() {
                    Some(comment)
                } else {
                    None
                },
                generator: if !generator.is_empty() {
                    Some(generator)
                } else {
                    None
                },
                compression: if compression_method != Method::None {
                    Some(Compression {
                        method: compression_method,
                        decompressed: None,
                    })
                } else {
                    None
                },
                multivol,
            });
        }

        let pos = reader.pos()?;
        let size = reader.size()? - pos;
        let decrypted = aes256cbc::decrypt(reader, &key, &iv, pos, size)?;
        decrypted_reader = Some(dh::data::read(decrypted));
        decrypted_reader.as_mut().unwrap()
    } else {
        reader
    };

    let mut files = Vec::new();

    for _ in 0..file_count {
        let size = body.read_u64le()?;
        let path_length = body.read_u16le()?;
        let path = body.read_utf8(path_length as u64)?;
        let owner_length = body.read_u16le()?;
        let owner = body.read_utf8(owner_length as u64)?;
        let group_length = body.read_u16le()?;
        let group = body.read_utf8(group_length as u64)?;
        let weblink_length = body.read_u32le()?;
        let weblink = body.read_utf8(weblink_length as u64)?;
        let creation = body.read_uxle(6)? as u64;
        let modification = body.read_uxle(6)? as u64;
        let access = body.read_uxle(6)? as u64;
        let perm_byte_1 = body.read_u8()?;
        let perm_byte_2 = body.read_u8()?;
        let permissions = [
            perm_byte_1 >> 5,
            (perm_byte_1 >> 2) & 0b111,
            ((perm_byte_1 & 0b11) << 1) | (perm_byte_2 >> 7),
        ];
        let directory = (perm_byte_2 & 0b0100_0000) != 0;
        let hidden = (perm_byte_2 & 0b0010_0000) != 0;
        let system = (perm_byte_2 & 0b0001_0000) != 0;
        let enable_backup = (perm_byte_2 & 0b0000_1000) != 0;
        let require_backup = (perm_byte_2 & 0b0000_0100) != 0;
        let readonly = (perm_byte_2 & 0b0000_0010) != 0;
        let main = (perm_byte_2 & 0b0000_0001) != 0;
        files.push(File {
            path,
            directory,
            offset: 0,
            length: size,
            owner: Some(owner),
            group: Some(group),
            weblink: Some(weblink),
            creation: DateTime::<Utc>::from_timestamp_millis(creation as i64)
                .unwrap_or_else(|| DateTime::<Utc>::from_timestamp_millis(0).unwrap()),
            modification: DateTime::<Utc>::from_timestamp_millis(modification as i64)
                .unwrap_or_else(|| DateTime::<Utc>::from_timestamp_millis(0).unwrap()),
            access: DateTime::<Utc>::from_timestamp_millis(access as i64)
                .unwrap_or_else(|| DateTime::<Utc>::from_timestamp_millis(0).unwrap()),
            permissions,
            hidden,
            system,
            enable_backup,
            require_backup,
            readonly,
            main,
        });
    }

    for file in files.iter_mut() {
        file.offset = body.pos()?;
        body.jump(file.length as i64)?;
    }

    Ok(Metadata {
        checksum,
        version,
        encryption: if encrypted {
            Some(Encryption {
                hash: pwd_hash,
                hash_expected: pwd_hash,
                iv,
                decrypted: dh::data::close(decrypted_reader.unwrap()),
            })
        } else {
            None
        },
        files,
        compression: if compression_method != Method::None {
            Some(Compression {
                method: compression_method,
                decompressed: Some(dh::data::close(r)),
            })
        } else {
            None
        },
        comment: if !comment.is_empty() {
            Some(comment)
        } else {
            None
        },
        generator: if !generator.is_empty() {
            Some(generator)
        } else {
            None
        },
        multivol,
    })
}
