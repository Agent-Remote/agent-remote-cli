//! Platform clipboard helpers with bounded output and explicit image formats.
use super::{ClipboardPayload, MAX_FILES_PER_PASTE, MAX_IMAGE_BYTES};
use base64::Engine;
use tokio::process::Command;

pub(super) async fn read() -> Option<ClipboardPayload> {
    let raw = read_platform().await?;
    match raw {
        ClipboardPayload::Image { bytes, .. } => {
            tokio::task::spawn_blocking(move || normalize_image(bytes))
                .await
                .ok()?
        }
        files => Some(files),
    }
}

fn normalize_image(bytes: Vec<u8>) -> Option<ClipboardPayload> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_IMAGE_BYTES {
        return None;
    }
    let format = image::guess_format(&bytes).ok()?;
    let extension = match format {
        image::ImageFormat::Png => "png",
        image::ImageFormat::Jpeg => "jpg",
        image::ImageFormat::Gif => "gif",
        image::ImageFormat::WebP => "webp",
        image::ImageFormat::Bmp | image::ImageFormat::Tiff => {
            let mut reader = image::ImageReader::with_format(std::io::Cursor::new(bytes), format);
            let mut limits = image::Limits::default();
            limits.max_image_width = Some(8192);
            limits.max_image_height = Some(8192);
            limits.max_alloc = Some(MAX_IMAGE_BYTES);
            reader.limits(limits);
            let decoded = reader.decode().ok()?;
            let mut output = BoundedImage(Vec::new());
            decoded
                .write_with_encoder(image::codecs::png::PngEncoder::new(&mut output))
                .ok()?;
            return Some(ClipboardPayload::Image {
                bytes: output.0,
                extension: "png",
            });
        }
        _ => return None,
    };
    Some(ClipboardPayload::Image { bytes, extension })
}

struct BoundedImage(Vec<u8>);
impl std::io::Write for BoundedImage {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if (self.0.len() + bytes.len()) as u64 > MAX_IMAGE_BYTES {
            return Err(std::io::Error::other("clipboard image is too large"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(serde::Deserialize)]
struct NativePayload {
    #[serde(default)]
    files: Vec<String>,
    image: Option<String>,
}
async fn native_payload(json: &str) -> Option<ClipboardPayload> {
    let payload: NativePayload = serde_json::from_str(json).ok()?;
    if !payload.files.is_empty() {
        if payload.files.len() > MAX_FILES_PER_PASTE {
            return None;
        }
        let mut files = Vec::new();
        for file in payload.files {
            files.push(super::paths::resolve(&file).await?);
        }
        return Some(ClipboardPayload::Files(files));
    }
    Some(ClipboardPayload::Image {
        bytes: base64::engine::general_purpose::STANDARD
            .decode(payload.image?)
            .ok()?,
        extension: "png",
    })
}

#[cfg(target_os = "macos")]
async fn read_platform() -> Option<ClipboardPayload> {
    // One snapshot/helper avoids image/file races and preserves Unicode/newlines.
    let script = r#"ObjC.import('AppKit'); var p=$.NSPasteboard.generalPasteboard; var a=p.propertyListForType($.NSFilenamesPboardType); var v={}; if(a && !a.isNil() && a.count>0) {v.files=ObjC.deepUnwrap(a);} else {var d=p.dataForType($.NSPasteboardTypePNG); if(!d || d.isNil()) d=p.dataForType($.NSPasteboardTypeTIFF); if(d && !d.isNil()) v.image=ObjC.unwrap(d.base64EncodedStringWithOptions(0));} $.NSFileHandle.fileHandleWithStandardOutput.writeData($(JSON.stringify(v)).dataUsingEncoding($.NSUTF8StringEncoding));"#;
    native_payload(&run_text("/usr/bin/osascript", &["-l", "JavaScript", "-e", script]).await?)
        .await
}

#[cfg(target_os = "windows")]
async fn read_platform() -> Option<ClipboardPayload> {
    read_windows().await
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
async fn read_windows() -> Option<ClipboardPayload> {
    // Base64 UTF-8 JSON is independent of PowerShell's console code page.
    let script = r#"Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; $v=@{}; $f=[Windows.Forms.Clipboard]::GetFileDropList(); if($f.Count -gt 0){$v.files=@($f)} else {$i=[Windows.Forms.Clipboard]::GetImage(); if($null -ne $i){$m=New-Object IO.MemoryStream; try{$i.Save($m,[Drawing.Imaging.ImageFormat]::Png);$v.image=[Convert]::ToBase64String($m.ToArray())}finally{$m.Dispose();$i.Dispose()}}}; [Console]::Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $v -Compress))))"#;
    let encoded = run_text(
        "powershell.exe",
        &[
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-STA",
            "-Command",
            script,
        ],
    )
    .await?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    native_payload(std::str::from_utf8(&bytes).ok()?).await
}

#[cfg(target_os = "linux")]
pub(super) fn is_wsl() -> bool {
    std::env::var_os("WSL_INTEROP").is_some() || std::env::var_os("WSL_DISTRO_NAME").is_some()
}

#[cfg(target_os = "linux")]
async fn read_platform() -> Option<ClipboardPayload> {
    if is_wsl() {
        if let Some(payload) = read_windows().await {
            return Some(payload);
        }
    }
    // Discover offered formats first; don't launch a helper for every possible MIME.
    for (program, list_args, prefix) in [
        (
            "wl-paste",
            vec!["--list-types"],
            vec!["--no-newline", "--type"],
        ),
        (
            "xclip",
            vec!["-selection", "clipboard", "-o", "-t", "TARGETS"],
            vec!["-selection", "clipboard", "-o", "-t"],
        ),
    ] {
        if program == "wl-paste" && std::env::var_os("WAYLAND_DISPLAY").is_none() {
            continue;
        }
        if program == "xclip" && std::env::var_os("DISPLAY").is_none() {
            continue;
        }
        let Some(types) = run_text(program, &list_args).await else {
            continue;
        };
        for mime in [
            "text/uri-list",
            "image/png",
            "image/jpeg",
            "image/webp",
            "image/gif",
            "image/tiff",
            "image/bmp",
        ] {
            if !types.lines().any(|line| line.trim() == mime) {
                continue;
            }
            let mut args = prefix.clone();
            args.push(mime);
            let Some(bytes) = run_bytes(program, &args).await else {
                continue;
            };
            if mime == "text/uri-list" {
                if let Some(files) =
                    super::paths::parse_dropped_paths(std::str::from_utf8(&bytes).ok()?).await
                {
                    return Some(ClipboardPayload::Files(files));
                }
            } else {
                return Some(ClipboardPayload::Image {
                    bytes,
                    extension: "png",
                });
            }
        }
    }
    None
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
async fn read_platform() -> Option<ClipboardPayload> {
    None
}

async fn run_bytes(program: &str, args: &[&str]) -> Option<Vec<u8>> {
    use std::process::Stdio;
    use tokio::io::AsyncReadExt;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?.take(MAX_IMAGE_BYTES * 2 + 1);
    let operation = async {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).await.ok()?;
        if bytes.len() as u64 > MAX_IMAGE_BYTES * 2 {
            return None;
        }
        child.wait().await.ok()?.success().then_some(bytes)
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), operation)
        .await
        .ok()
        .flatten()
}
pub(super) async fn run_text(program: &str, args: &[&str]) -> Option<String> {
    String::from_utf8(run_bytes(program, args).await?).ok()
}

#[cfg(test)]
#[path = "../../tests/unit/src/attachments/capture.rs"]
mod tests;
