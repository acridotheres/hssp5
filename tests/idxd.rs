use acr::compression::Method;
use dh::recommended::*;
use hssp5::{extract, metadata, verify_integrity};

#[test]
fn idxd_normal() {
    let mut reader = dh::file::open_r("tests/samples/idxd-normal.hssp").unwrap();
    let meta = metadata(&mut reader, None).unwrap();

    assert!(verify_integrity(&mut reader, &meta).unwrap());
    assert_eq!(meta.version, 4);
    assert_eq!(meta.checksum, 812753517);
    assert!(meta.encryption.is_none());
    assert_eq!(meta.files.len(), 1);
    assert_eq!(meta.files[0].path, "test.txt");
    assert!(!meta.files[0].directory);
    assert_eq!(meta.files[0].offset, 104);
    assert_eq!(meta.files[0].length, 13);
    assert!(!meta.files[0].main);

    let mut target = dh::data::write_new(meta.files[0].length);
    extract(&mut reader, &meta, 0, &mut target, 1024, 0).unwrap();
    assert_eq!(dh::data::close(target), b"Hello, world!");
}

#[test]
fn idxd_multiple() {
    let mut reader = dh::file::open_r("tests/samples/idxd-multiple.hssp").unwrap();
    let meta = metadata(&mut reader, None).unwrap();

    assert!(verify_integrity(&mut reader, &meta).unwrap());
    assert_eq!(meta.version, 4);
    assert_eq!(meta.checksum, 1676798403);
    assert!(meta.encryption.is_none());
    assert_eq!(meta.files.len(), 2);
    assert_eq!(meta.files[0].path, "test.txt");
    assert!(!meta.files[0].directory);
    assert_eq!(meta.files[0].offset, 210);
    assert_eq!(meta.files[0].length, 13);
    assert!(!meta.files[0].main);
    assert_eq!(meta.files[1].path, "test2.txt");
    assert!(!meta.files[1].directory);
    assert_eq!(meta.files[1].offset, 223);
    assert_eq!(meta.files[1].length, 15);
    assert!(!meta.files[1].main);

    let mut target = dh::data::write_new(meta.files[0].length);
    extract(&mut reader, &meta, 0, &mut target, 1024, 0).unwrap();
    assert_eq!(dh::data::close(target), b"Hello, world!");
    let mut target = dh::data::write_new(meta.files[1].length);
    extract(&mut reader, &meta, 1, &mut target, 1024, 0).unwrap();
    assert_eq!(dh::data::close(target), b"Hello, world! 2");
}

#[test]
fn idxd_encrypted() {
    let mut reader = dh::file::open_r("tests/samples/idxd-encrypted.hssp").unwrap();
    let meta = metadata(&mut reader, Some("Password")).unwrap();

    assert!(verify_integrity(&mut reader, &meta).unwrap());
    assert_eq!(meta.version, 4);
    assert_eq!(meta.checksum, 4083272515);
    assert!(meta.encryption.is_some());
    assert_eq!(meta.files.len(), 1);
    assert_eq!(meta.files[0].path, "test.txt");
    assert!(!meta.files[0].directory);
    assert_eq!(meta.files[0].offset, 104);
    assert_eq!(meta.files[0].length, 13);
    assert!(!meta.files[0].main);

    let mut target = dh::data::write_new(meta.files[0].length);
    extract(&mut reader, &meta, 0, &mut target, 1024, 0).unwrap();
    assert_eq!(dh::data::close(target), b"Hello, world!");
}

#[test]
fn idxd_comp_lzma() {
    let mut reader = dh::file::open_r("tests/samples/idxd-comp-lzma.hssp").unwrap();
    let meta = metadata(&mut reader, None).unwrap();

    assert!(verify_integrity(&mut reader, &meta).unwrap());
    assert_eq!(meta.version, 4);
    assert_eq!(meta.checksum, 2228228509);
    assert!(meta.encryption.is_none());
    let compression = meta.compression.as_ref().unwrap();
    assert!(compression.method == Method::Lzma);
    assert_eq!(meta.files.len(), 1);
    assert_eq!(meta.files[0].path, "test.txt");
    assert!(!meta.files[0].directory);
    assert_eq!(meta.files[0].offset, 104);
    assert_eq!(meta.files[0].length, 13);
    assert!(!meta.files[0].main);

    let mut target = dh::data::write_new(meta.files[0].length);
    extract(&mut reader, &meta, 0, &mut target, 1024, 0).unwrap();
    assert_eq!(dh::data::close(target), b"Hello, world!");
}
