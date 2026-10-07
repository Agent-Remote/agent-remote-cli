// Tests for src/attachments/capture.rs.

use super::*;
#[test]
fn oversized_bitmap_dimensions_are_rejected_before_conversion() {
    let mut encoded = std::io::Cursor::new(Vec::new());
    image::DynamicImage::new_rgb8(1, 1)
        .write_to(&mut encoded, image::ImageFormat::Bmp)
        .unwrap();
    let mut bytes = encoded.into_inner();
    bytes[18..22].copy_from_slice(&100_000i32.to_le_bytes());
    assert!(normalize_image(bytes).is_none());
}
#[test]
fn unsupported_images_are_normalized_and_unknown_data_rejected() {
    for format in [image::ImageFormat::Bmp, image::ImageFormat::Tiff] {
        let source = image::DynamicImage::new_rgb8(3, 2);
        let mut bytes = std::io::Cursor::new(Vec::new());
        source.write_to(&mut bytes, format).unwrap();
        let ClipboardPayload::Image { bytes, extension } =
            normalize_image(bytes.into_inner()).unwrap()
        else {
            panic!()
        };
        assert_eq!(extension, "png");
        let decoded = image::load_from_memory(&bytes).unwrap();
        assert_eq!((decoded.width(), decoded.height()), (3, 2));
    }
    assert!(normalize_image(b"not an image".to_vec()).is_none());
}
#[test]
fn compressed_supported_formats_keep_their_extension_and_bytes() {
    for (bytes, extension) in [
        (b"\xff\xd8\xff".as_slice(), "jpg"),
        (b"GIF89a", "gif"),
        (b"RIFF1234WEBP", "webp"),
        (b"\x89PNG\r\n\x1a\n", "png"),
    ] {
        assert_eq!(
            normalize_image(bytes.to_vec()),
            Some(ClipboardPayload::Image {
                bytes: bytes.to_vec(),
                extension
            })
        );
    }
}
#[tokio::test]
async fn native_file_lists_preserve_unicode_and_reject_partial_results() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("中文 file.txt");
    std::fs::write(&file, "x").unwrap();
    let json = serde_json::json!({"files":[file],"image":null});
    assert_eq!(
        native_payload(&json.to_string()).await,
        Some(ClipboardPayload::Files(vec![file.clone()]))
    );
    assert!(
        native_payload(&serde_json::json!({"files":[file,"/nonexistent-drop"]}).to_string())
            .await
            .is_none()
    );
}
