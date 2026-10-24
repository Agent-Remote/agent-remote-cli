use super::*;

#[test]
fn service_command_accepts_exact_native_arguments_and_preserves_paths() {
    let (binary,config)=command_paths(r#""C:\Program Files\WireGuard\wireguard.exe" /tunnelservice "C:\ProgramData\Agent Remote\wg0.conf""#).unwrap();
    assert_eq!(
        binary,
        PathBuf::from(r"C:\Program Files\WireGuard\wireguard.exe")
    );
    assert_eq!(
        config,
        PathBuf::from(r"C:\ProgramData\Agent Remote\wg0.conf")
    );
    for command in [
        r"C:\Program Files\WireGuard\wireguard.exe /tunnelservice C:\wg0.conf",
        r"C:\WireGuard\wireguard.exe /uninstalltunnelservice wg0",
        r"C:\WireGuard\wireguard.exe /tunnelservice C:\wg0.conf extra",
        r"wireguard.exe /tunnelservice C:\wg0.conf",
        r"C:\WireGuard\wireguard.exe /tunnelservice relative.conf",
        r"C:\WireGuard\wireguard.exe /tunnelservice C:\safe\..\wg0.conf",
    ] {
        assert!(command_paths(command).is_err());
    }
}

#[test]
fn service_string_reads_are_bounded_to_the_returned_native_buffer() {
    let mut buffer = vec![0usize; 8];
    let wide = unsafe {
        std::slice::from_raw_parts_mut(
            buffer.as_mut_ptr().cast::<u16>(),
            std::mem::size_of_val(buffer.as_slice()) / 2,
        )
    };
    wide[..4].copy_from_slice(&[b'a' as u16, b'b' as u16, b'c' as u16, 0]);
    assert_eq!(
        buffer_string(buffer.as_ptr().cast(), &buffer, 3).unwrap(),
        "abc"
    );
    assert!(buffer_string(buffer.as_ptr().cast(), &buffer, 2).is_err());
    assert!(buffer_string(null(), &buffer, 100).is_err());
    let end = unsafe { buffer.as_ptr().add(buffer.len()).cast::<u16>() };
    assert!(buffer_string(end, &buffer, 100).is_err());
}
