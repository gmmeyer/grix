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

mod at;
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
mod metrics;
mod mount;
mod net;
mod oci;
pub mod results;
mod sandbox;
pub mod snapshot;
mod treecache;
mod vmm;

pub use container::{Image, ImageConfig};
pub use control::RunControl;
pub use event::GuestEvent;
pub use export::{Export, ExportContent, ExportEntry, ExportState};
pub use grix_abi::policy::{Capability, DenyAction};
pub use grix_abi::stats::{Limit, Resource, Stats as GuestStats, Usage};
pub use manifest::{ExportTo, Manifest};
pub use metrics::Metrics;
pub use mount::{MountChanges, MountState};
pub use net::Publish;
pub use oci::pull_to_layout as pull;
pub use sandbox::{Arch, ExitStatus, HostUsage, MountMode, RunOutput, Sandbox, SandboxBuilder, Stream};
pub use snapshot::Snapshot;
