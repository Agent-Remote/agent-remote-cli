//! Explicit desktop test: snapshots all pasteboard formats in memory and restores
//! them only while the test still owns the clipboard. Never logs clipboard data.
#![cfg(target_os = "macos")]
use agent_remote_cli::attachments::{read_clipboard_payload, ClipboardPayload};
use base64::Engine;
use serde_json::{json, Value};
use std::{
    io::Write,
    process::{Command, Stdio},
};

const SCRIPT: &str = r#"
ObjC.import('AppKit');
var p=$.NSPasteboard.generalPasteboard;
var raw=$.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
var r=JSON.parse(ObjC.unwrap($.NSString.alloc.initWithDataEncoding(raw,$.NSUTF8StringEncoding)));
function emit(v){$.NSFileHandle.fileHandleWithStandardOutput.writeData($(JSON.stringify(v)).dataUsingEncoding($.NSUTF8StringEncoding));}
if(r.op==='snapshot'){
 var items=[];var a=p.pasteboardItems;
 for(var i=0;i<a.count;i++){var item=a.objectAtIndex(i),v={};var types=ObjC.deepUnwrap(item.types);types.forEach(function(t){var d=item.dataForType($(t));if(d&&!d.isNil())v[t]=ObjC.unwrap(d.base64EncodedStringWithOptions(0));});items.push(v);}
 emit({items:items,count:p.changeCount});
}else{
 if(p.changeCount!==r.count){emit({conflict:true});}
 else{p.clearContents;if(r.op==='files'){p.setPropertyListForType($(r.files),$.NSFilenamesPboardType);}else{var a=$.NSMutableArray.alloc.init;r.items.forEach(function(v){var item=$.NSPasteboardItem.alloc.init;Object.keys(v).forEach(function(t){var d=$.NSData.alloc.initWithBase64EncodedStringOptions($(v[t]),0);item.setDataForType(d,$(t));});a.addObject(item);});if(a.count>0)p.writeObjects(a);}emit({count:p.changeCount});}
}
"#;
fn pasteboard(request: Value) -> Value {
    let mut child = Command::new("/usr/bin/osascript")
        .args(["-l", "JavaScript", "-e", SCRIPT])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "pasteboard fixture failed");
    serde_json::from_slice(&output.stdout).unwrap()
}
struct Restore {
    items: Value,
    count: Value,
}
impl Restore {
    fn replace(&mut self, mut request: Value) {
        request["count"] = self.count.clone();
        let result = pasteboard(request);
        assert_ne!(
            result["conflict"], true,
            "clipboard changed externally; test stopped"
        );
        self.count = result["count"].clone();
    }
}
impl Drop for Restore {
    fn drop(&mut self) {
        let result = pasteboard(json!({"op":"restore","items":self.items,"count":self.count}));
        if result["conflict"] == true {
            eprintln!("Clipboard changed externally; preserved the user's newer clipboard.");
        }
    }
}
#[tokio::test]
#[ignore = "temporarily owns the macOS desktop clipboard; run explicitly"]
async fn macos_real_clipboard_images_files_and_plain_text() {
    let saved = pasteboard(json!({"op":"snapshot"}));
    let mut restore = Restore {
        items: saved["items"].clone(),
        count: saved["count"].clone(),
    };
    for (format, mime) in [
        (image::ImageFormat::Png, "public.png"),
        (image::ImageFormat::Tiff, "public.tiff"),
    ] {
        let mut data = std::io::Cursor::new(Vec::new());
        image::DynamicImage::new_rgb8(4, 3)
            .write_to(&mut data, format)
            .unwrap();
        let mut item = serde_json::Map::new();
        item.insert(
            mime.into(),
            json!(base64::engine::general_purpose::STANDARD.encode(data.into_inner())),
        );
        restore.replace(json!({"op":"set","items":[item]}));
        let ClipboardPayload::Image { bytes, extension } =
            read_clipboard_payload().await.expect("real image capture")
        else {
            panic!("expected image")
        };
        assert_eq!(extension, "png");
        let image = image::load_from_memory(&bytes).unwrap();
        assert_eq!((image.width(), image.height()), (4, 3));
    }
    let temp = tempfile::tempdir().unwrap();
    let first = temp.path().join("中文 first.txt");
    let second = temp.path().join("second file.txt");
    std::fs::write(&first, "one").unwrap();
    std::fs::write(&second, "two").unwrap();
    restore.replace(json!({"op":"files","files":[first,second]}));
    assert_eq!(
        read_clipboard_payload().await,
        Some(ClipboardPayload::Files(vec![first, second]))
    );
    restore.replace(json!({"op":"set","items":[{"public.utf8-plain-text":base64::engine::general_purpose::STANDARD.encode("ordinary text 中文")}]}));
    assert!(read_clipboard_payload().await.is_none());
}
