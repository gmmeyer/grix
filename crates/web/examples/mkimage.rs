//! Check the page's halves against a native QEMU: `mkimage SPEC_JSON OUT
//! GUEST=HOST...` writes a boot image the way the page builds one, and
//! `mkimage decode` prints what the machine wrote on stdin as the page would.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args[0] == "decode" {
        let mut data = Vec::new();
        std::io::stdin().read_to_end(&mut data).unwrap();
        let out = grix_web::Session::default().output(&data);
        let mut rest = &out[..];
        while let [kind, a, b, c, d, tail @ ..] = rest {
            let len = u32::from_le_bytes([*a, *b, *c, *d]) as usize;
            println!("{kind}: {:?}", String::from_utf8_lossy(&tail[..len]));
            rest = &tail[len..];
        }
        return;
    }
    let spec: grix_web::Spec = serde_json::from_str(&args[0]).expect("spec");
    let mut b = grix_web::Builder::default();
    for imp in &args[2..] {
        let (guest, host) = imp.split_once('=').expect("GUEST=HOST");
        let meta = std::fs::metadata(host).expect(host);
        b.file(guest, std::fs::read(host).unwrap(), meta.permissions().mode()).unwrap();
    }
    std::fs::write(&args[1], b.image(&spec).unwrap()).unwrap();
}
