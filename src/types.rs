use acr::compression::Method;
use chrono::{DateTime, Utc};
use dh::Readable;

#[derive(Debug)]
pub struct Metadata {
    pub version: u8,
    pub checksum: u32,
    pub encryption: Option<Encryption>,
    pub files: Vec<File>,
    pub compression: Option<Compression>,
    pub multivol: Option<Multivol>,
    pub comment: Option<String>,
    pub generator: Option<String>,
}

#[derive(Debug)]
pub struct Encryption {
    pub hash: [u8; 32],
    pub hash_expected: [u8; 32],
    pub iv: [u8; 16],
    pub decrypted: Vec<u8>,
}

#[derive(Debug)]
pub struct Compression {
    pub method: Method,
    pub decompressed: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct Multivol {
    pub total_files: u64,
    pub continue_offset: u64,
    pub previous_checksum: Option<u32>,
    pub next_checksum: Option<u32>,
    pub id: u32,
}

#[derive(Debug)]
pub struct File {
    pub path: String,
    pub directory: bool,
    pub offset: u64,
    pub length: u64,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub weblink: Option<String>,
    pub creation: DateTime<Utc>,
    pub modification: DateTime<Utc>,
    pub access: DateTime<Utc>,
    pub permissions: [u8; 3],
    pub hidden: bool,
    pub system: bool,
    pub enable_backup: bool,
    pub require_backup: bool,
    pub readonly: bool,
    pub main: bool,
}

pub struct FileWithSource<'a>(pub &'a File, pub &'a mut dyn Readable<'a>);
