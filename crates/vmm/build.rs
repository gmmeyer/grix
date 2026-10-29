// Hypervisor.framework is linked weakly: its GIC functions are macOS 15+,
// and on older systems grix-vmm should say so instead of failing to load.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(supported)");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if arch == "aarch64" && (os == "macos" || os == "linux") || arch == "x86_64" && os == "linux" {
        println!("cargo::rustc-cfg=supported");
    }
    if os == "macos" {
        println!("cargo::rustc-link-arg=-Wl,-weak_framework,Hypervisor");
    }
}
