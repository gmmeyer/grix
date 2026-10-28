//! Run Linux programs inside a capability-scoped Rust unikernel.
//!
//! ```no_run
//! use grix::{Capability, Sandbox};
//!
//! let sandbox = Sandbox::builder()
//!     .import("./build/hello", "/bin/hello")?
//!     .env("GREETING", "hi")
//!     .build()?;
//! let out = sandbox.run(&["/bin/hello", "world"])?;
//! println!("{}", String::from_utf8_lossy(&out.stdout));
//! for event in &out.events {
//!     eprintln!("{event}");
//! }
//! # Ok::<(), anyhow::Error>(())
//! ```
//!
//! The program sees only the files you import, and can only use the
//! capabilities you grant ([`Capability`]). Anything it tries beyond that is
//! denied and reported in [`RunOutput::events`].

pub mod auth;
pub mod build;
mod container;
mod control;
mod dns;
mod event;
mod export;
mod hostfs;
mod image;
mod manifest;
pub mod mcp;
mod mount;
mod net;
mod oci;
mod sandbox;
pub mod snapshot;
mod treecache;
mod vmm;

pub use container::{Image, ImageConfig};
pub use control::RunControl;
pub use event::GuestEvent;
pub use export::{Export, ExportContent, ExportEntry, ExportState};
pub use grix_abi::policy::{Capability, DenyAction};
pub use manifest::{ExportTo, Manifest};
pub use mount::{MountChanges, MountState};
pub use oci::pull_to_layout as pull;
pub use sandbox::{ExitStatus, MountMode, RunOutput, Sandbox, SandboxBuilder, Stream};
pub use snapshot::Snapshot;
