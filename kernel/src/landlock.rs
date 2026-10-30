//! Landlock: rules a program sets on itself (landlock_create_ruleset,
//! landlock_add_rule, landlock_restrict_self), as Linux's
//! security/landlock does them, to ABI 5: filesystem rights through
//! REFER (2), TRUNCATE (3) and IOCTL_DEV (5), and TCP bind and connect
//! by port (4). Not ABI 6's scoping of abstract sockets and signals.
//!
//! Like a seccomp filter, it can only take away: the policy's gates come
//! first (`syscall::require` in the handlers, before any check here), and
//! what Landlock refuses is EACCES (EXDEV for some renames and links), the
//! program's own choice, never reported as a denial.
//!
//! A domain is per thread (`Thread::landlock`): the layers it restricted
//! itself with, oldest first, each the rights it handles, and every rule
//! of every layer merged by object (a node, or a TCP port), each holding
//! what each layer grants there. It's immutable, shared by `Arc` with the
//! threads and processes that inherit it (clone, fork, execve), and a
//! restriction makes a new one with a layer more (at most 16). An access
//! is allowed when every layer that handles it has a rule granting it on
//! the node or one of its ancestors (`landlock_unmask_layers`).
//!
//! Rules hold their nodes by identity (`Ino`), pinned so a removed node's
//! slot isn't reused for another; a pinned node is never idle, so a live
//! mount's directories with rules (and those above them) aren't forgotten
//! to make room (`Fs::evict`), and copying a lazy import's node up keeps
//! its slot. A node replaced on the host is another node, as an inode
//! replaced on Linux is.
//!
//! A file with several names is under the directory its path went
//! through, as a dentry is (`Fs::found_in`): `Node::parent` is only its
//! first name's, which may be gone. On a live mount each name is a node
//! of its own, so a rule on a file there holds for that name alone.
//!
//! Every check is a function of the domain and the filesystem it's given
//! (callers hold `fs::lock()` or take it once for the check), and without
//! a domain anywhere in the process it's one test (`Process::landlocked`).

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;

use crate::errno::*;
use crate::fd::{FdEntry, FileKind, O_ACCMODE, O_RDONLY, O_RDWR, O_WRONLY, new_file};
use crate::fs::{self, Fs, Ino, Kind, ROOT};
use crate::kmem::Charge;
use crate::process::Process;
use crate::uaccess::*;

/// The ABI version the version query reports.
pub const ABI: u64 = 5;

// Filesystem access rights (include/uapi/linux/landlock.h).
pub const EXECUTE: u16 = 1 << 0;
pub const WRITE_FILE: u16 = 1 << 1;
pub const READ_FILE: u16 = 1 << 2;
pub const READ_DIR: u16 = 1 << 3;
pub const REMOVE_DIR: u16 = 1 << 4;
pub const REMOVE_FILE: u16 = 1 << 5;
pub const MAKE_CHAR: u16 = 1 << 6;
pub const MAKE_DIR: u16 = 1 << 7;
pub const MAKE_REG: u16 = 1 << 8;
pub const MAKE_SOCK: u16 = 1 << 9;
pub const MAKE_FIFO: u16 = 1 << 10;
#[allow(dead_code)] // the policy denies making devices first
pub const MAKE_BLOCK: u16 = 1 << 11;
pub const MAKE_SYM: u16 = 1 << 12;
pub const REFER: u16 = 1 << 13;
pub const TRUNCATE: u16 = 1 << 14;
pub const IOCTL_DEV: u16 = 1 << 15;
/// Every filesystem right ABI 5 has.
const FS_ALL: u16 = 0xffff;
/// The rights a rule on a file (not a directory) may grant.
const ACCESS_FILE: u16 = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV;

// Network access rights.
pub const BIND_TCP: u16 = 1 << 0;
pub const CONNECT_TCP: u16 = 1 << 1;
const NET_ALL: u16 = BIND_TCP | CONNECT_TCP;

const CREATE_RULESET_VERSION: u64 = 1;
const RULE_PATH_BENEATH: u64 = 1;
const RULE_NET_PORT: u64 = 2;

const ENOMSG: Errno = Errno(42);
const EBADFD: Errno = Errno(77);
const EAFNOSUPPORT: Errno = Errno(97);

/// Linux's LANDLOCK_MAX_NUM_LAYERS.
pub const MAX_LAYERS: usize = 16;
/// Rules in every ruleset and domain together (each also charged to
/// `kmem`): a program can fork and restrict each child, so the bound is
/// global.
const MAX_RULES: usize = 32 * 1024;
static RULES: AtomicUsize = AtomicUsize::new(0);
/// A rule's share of the heap: its B-tree entry, grants and pin, and the
/// node the pin keeps. A /proc/<pid>/task node's thread stops paying for
/// it when it goes, and a rule can outlive that.
const RULE_COST: u64 = 128 + fs::PROC_NODE_COST;
/// Ids for layers (`scope_le`), never reused.
static NEXT_LAYER: AtomicU64 = AtomicU64::new(1);

/// The deepest walk up the tree (a bound, not a limit anything reaches:
/// paths are at most 4096 bytes).
const MAX_DEPTH: usize = 4096;

/// What each layer grants, by layer: one rule's worth.
type Grants = [u16; MAX_LAYERS];
/// For each access right (by bit), the layers that haven't granted it yet
/// (Linux's layer_masks).
type Masks = [u16; 16];

/// Rules counted in `RULES` and charged to `kmem`, given back when dropped.
#[derive(Default)]
struct Held {
    rules: usize,
    charge: Charge,
}

impl Held {
    fn new(fixed: usize) -> Result<Held, Errno> {
        Ok(Held { rules: 0, charge: Charge::new(fixed as u64)? })
    }

    fn take(&mut self, more: usize) -> Result<(), Errno> {
        if RULES.load(Ordering::Relaxed) + more > MAX_RULES {
            crate::stats::hit(grix_abi::stats::Limit::KernelMemory);
            return Err(ENOMEM);
        }
        self.charge.resize(self.charge.bytes() + more as u64 * RULE_COST)?;
        // Under the kernel lock: check-then-add doesn't race.
        RULES.fetch_add(more, Ordering::Relaxed);
        self.rules += more;
        Ok(())
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        RULES.fetch_sub(self.rules, Ordering::Relaxed);
    }
}

/// A ruleset being made (a `landlock-ruleset` descriptor's).
pub struct Ruleset {
    handled_fs: u16,
    handled_net: u16,
    /// Path rules: what each node's rules grant, and the node pinned.
    fs: BTreeMap<Ino, (u16, Arc<()>)>,
    net: BTreeMap<u16, u16>,
    held: Held,
}

pub type RulesetRef = Arc<Mutex<Ruleset>>;

/// One restriction: the rights it handles.
#[derive(Clone, Copy)]
struct Layer {
    /// Whose (`scope_le`).
    id: u64,
    fs: u16,
    net: u16,
}

/// A thread's restrictions: its layers and their rules, merged.
pub struct Domain {
    /// Oldest first.
    layers: Vec<Layer>,
    fs: BTreeMap<Ino, (Grants, Arc<()>)>,
    net: BTreeMap<u16, Grants>,
    _held: Held,
}

/// The calling thread's domain. Without one anywhere in the process, a
/// single test.
#[inline]
pub fn domain(p: &Process) -> Option<Arc<Domain>> {
    if !p.landlocked {
        return None;
    }
    p.threads.get(&p.current).and_then(|t| t.landlock.clone())
}

/// The calling thread's domain, for a change to `ino` or in it: none on
/// a read-only mount, where the call is EROFS before Landlock has a say
/// (Linux's mnt_want_write comes first).
pub fn domain_changing(p: &Process, fs: &Fs, ino: Ino) -> Option<Arc<Domain>> {
    domain(p).filter(|_| !fs.read_only(ino))
}

/// `access` to directory `dir` for the calling thread (takes the
/// filesystem's lock if it has a domain): EACCES unless every layer
/// allows it.
pub fn check(p: &Process, dir: Ino, access: u16) -> Result<(), Errno> {
    match domain(p) {
        Some(d) => d.check(&fs::lock(), dir, access),
        None => Ok(()),
    }
}

/// May `p` look into `q` as a tracer could (/proc/<pid>/environ, its
/// descriptors, pidfd_getfd)? Not from a domain into a process outside it
/// (Linux's hook_ptrace_access_check): `q` must have all of `p`'s layers.
pub fn may_inspect(p: &Process, q: &Process) -> bool {
    let Some(mine) = domain(p) else { return true };
    let theirs = q.threads.get(&q.pid).or(q.threads.values().next()).and_then(|t| t.landlock.as_deref());
    theirs.is_some_and(|d| mine.scope_le(d))
}

/// Linux's get_mode_access: making a node of this kind.
pub fn make_access(kind: &Kind) -> u16 {
    match kind {
        Kind::Dir(_) => MAKE_DIR,
        Kind::Symlink(_) => MAKE_SYM,
        Kind::Fifo(_) => MAKE_FIFO,
        Kind::Socket(_) => MAKE_SOCK,
        Kind::Dev(_) => MAKE_CHAR,
        Kind::File(_) | Kind::Unlinked { .. } | Kind::Proc(_) => MAKE_REG,
    }
}

/// Opening `ino`, found in directory `dir`, with access mode `acc`
/// (Linux's hook_file_open): what the open needs (reading a directory is
/// READ_DIR) must be allowed, and what's refused of the rights kept for
/// later (TRUNCATE, and IOCTL_DEV for a device) is returned for
/// `OpenFile::landlock_denied`.
pub fn open_access(d: &Domain, fs: &Fs, ino: Ino, dir: Ino, acc: u32) -> Result<u16, Errno> {
    let kind = &fs.node(ino).kind;
    let read = if matches!(kind, Kind::Dir(_)) { READ_DIR } else { READ_FILE };
    let need = match acc {
        O_RDONLY => read,
        O_WRONLY => WRITE_FILE,
        O_RDWR => read | WRITE_FILE,
        _ => 0,
    };
    let later = TRUNCATE | if matches!(kind, Kind::Dev(_)) { IOCTL_DEV } else { 0 };
    let allowed = d.allowed_in(fs, ino, dir, need | later);
    if allowed & need != need {
        return Err(EACCES);
    }
    Ok(later & !allowed)
}

/// Removing a node of this kind (Linux's maybe_remove).
fn remove_access(fs: &Fs, ino: Ino) -> u16 {
    if fs.is_dir(ino) { REMOVE_DIR } else { REMOVE_FILE }
}

fn bits(set: u16) -> impl Iterator<Item = usize> {
    (0..16).filter(move |b| set & (1 << b) != 0)
}

/// Linux's landlock_unmask_layers: take the layers `grants` grants out of
/// `masks` for the rights in `request`. True once none is left wanting.
fn unmask(grants: Option<&Grants>, request: u16, masks: &mut Masks) -> bool {
    if request == 0 {
        return true;
    }
    let Some(grants) = grants else { return false };
    for (level, &access) in grants.iter().enumerate() {
        for bit in bits(request & access) {
            masks[bit] &= !(1 << level);
        }
    }
    bits(request).all(|bit| masks[bit] == 0)
}

fn all_granted(masks: &Masks) -> bool {
    masks.iter().all(|&m| m == 0)
}

impl Domain {
    /// Linux's landlock_init_layer_masks: which layers handle each right
    /// in `request`, and those rights. A layer that handles any filesystem
    /// right handles REFER too, asked for or not: reparenting is denied
    /// unless a rule grants it.
    fn init(&self, request: u16, net: bool) -> (Masks, u16) {
        let mut masks = [0u16; 16];
        let mut handled = 0;
        for (level, layer) in self.layers.iter().enumerate() {
            let own = match (net, layer.fs) {
                (true, _) => layer.net,
                (false, 0) => 0,
                (false, fs) => fs | REFER,
            };
            let h = request & own;
            handled |= h;
            for bit in bits(h) {
                masks[bit] |= 1 << level;
            }
        }
        (masks, handled)
    }

    fn rule(&self, ino: Ino) -> Option<&Grants> {
        self.fs.get(&ino).map(|r| &r.0)
    }

    /// Take out of `masks` what the rule on `ino` grants of `request`,
    /// then each from directory `dir` up to the root, until nothing is
    /// wanted.
    fn walk(&self, fs: &Fs, ino: Ino, dir: Ino, request: u16, masks: &mut Masks) -> bool {
        let (mut ino, mut next) = (ino, dir);
        for _ in 0..MAX_DEPTH {
            if unmask(self.rule(ino), request, masks) {
                return true;
            }
            // The root, or a directory no longer in the tree, whose
            // parent may be gone: nothing more grants anything.
            if ino == ROOT || !fs.is_dir(next) || fs.is_dir(ino) && fs.node(ino).nlink == 0 {
                return false;
            }
            (ino, next) = (next, fs.node(next).parent);
        }
        false
    }

    /// Of `access` to `ino`, found in directory `dir`, what every layer
    /// allows (what isn't handled is allowed).
    pub fn allowed_in(&self, fs: &Fs, ino: Ino, dir: Ino, access: u16) -> u16 {
        let (mut masks, request) = self.init(access, false);
        if request == 0 || self.walk(fs, ino, dir, request, &mut masks) {
            return access;
        }
        bits(access).filter(|&b| masks[b] == 0).fold(0, |a, b| a | 1 << b)
    }

    /// `access` to a file found in `dir`, or to a directory (`dir` its
    /// parent): EACCES unless every layer allows it all.
    pub fn check_in(&self, fs: &Fs, ino: Ino, dir: Ino, access: u16) -> Result<(), Errno> {
        if self.allowed_in(fs, ino, dir, access) == access { Ok(()) } else { Err(EACCES) }
    }

    /// `access` to directory `dir`.
    pub fn check(&self, fs: &Fs, dir: Ino, access: u16) -> Result<(), Errno> {
        self.check_in(fs, dir, fs.node(dir).parent, access)
    }

    /// Every handled right, as granted from `dir` up to the root (Linux's
    /// collect_domain_accesses, the tree being one mount).
    fn collect(&self, fs: &Fs, dir: Ino) -> (Masks, bool) {
        let (mut masks, request) = self.init(FS_ALL, false);
        let ok = self.walk(fs, dir, fs.node(dir).parent, request, &mut masks);
        (masks, ok)
    }

    /// Every handled right, as the rule on `ino` alone grants it.
    fn child(&self, ino: Ino) -> Masks {
        let (mut masks, request) = self.init(FS_ALL, false);
        unmask(self.rule(ino), request, &mut masks);
        masks
    }

    /// Moving `src` (the node a link or rename takes) from directory
    /// `odir` to `ndir`, over `dst` (what's there now: replaced, or
    /// exchanged with `exchange`); `removable` for a rename. Linux's
    /// current_check_refer_path: the right to make the node in the
    /// destination (and to remove what it replaces), and when it changes
    /// directory, REFER on both sides and no right gained by the move:
    /// EXDEV when only that's missing.
    #[allow(clippy::too_many_arguments)]
    pub fn check_refer(
        &self,
        fs: &Fs,
        src: Ino,
        odir: Ino,
        ndir: Ino,
        dst: Option<Ino>,
        removable: bool,
        exchange: bool,
    ) -> Result<(), Errno> {
        let mut request1 = match dst {
            Some(d) if exchange => make_access(&fs.node(d).kind),
            _ => 0,
        };
        let mut request2 = make_access(&fs.node(src).kind);
        if removable {
            request1 |= remove_access(fs, src);
            request2 |= dst.map_or(0, |d| remove_access(fs, d));
        }
        if odir == ndir {
            // No reparenting: REFER isn't needed.
            return self.check(fs, ndir, request1 | request2);
        }
        request1 |= REFER;
        request2 |= REFER;
        let (mut masks1, ok1) = self.collect(fs, odir);
        let (mut masks2, ok2) = self.collect(fs, ndir);
        if ok1 && ok2 {
            return Ok(());
        }
        let child1 = (self.child(src), fs.is_dir(src));
        let child2 = dst.filter(|_| exchange).map(|d| (self.child(d), fs.is_dir(d)));
        if no_more_access(&masks1, &child1, &masks2, child2.as_ref()) {
            // Only what was asked for matters now.
            let ok1 = scope_to_request(request1, &mut masks1);
            let ok2 = scope_to_request(request2, &mut masks2);
            if ok1 && ok2 {
                return Ok(());
            }
        }
        if is_eacces(&masks1, request1) || is_eacces(&masks2, request2) { Err(EACCES) } else { Err(EXDEV) }
    }

    /// Is this domain the same as `other`, or one `other` was made from?
    /// (Linux's domain_scope_le.)
    fn scope_le(&self, other: &Domain) -> bool {
        self.layers.len() <= other.layers.len() && self.layers.iter().zip(&other.layers).all(|(a, b)| a.id == b.id)
    }

    /// TCP `access` (BIND_TCP, CONNECT_TCP) to `port`.
    pub fn net_allowed(&self, port: u16, access: u16) -> bool {
        let (mut masks, request) = self.init(access, true);
        unmask(self.net.get(&port), request, &mut masks)
    }
}

/// Linux's no_more_access: does the destination restrict at least what
/// the source did, for the node moved (and, exchanging, the other way)?
fn no_more_access(parent1: &Masks, child1: &(Masks, bool), parent2: &Masks, child2: Option<&(Masks, bool)>) -> bool {
    for bit in 0..16 {
        let file_access = (1u16 << bit) & ACCESS_FILE != 0;
        if (child1.1 || file_access) && (parent1[bit] & child1.0[bit]) | parent2[bit] != parent2[bit] {
            return false;
        }
        if let Some(child2) = child2
            && (child2.1 || file_access)
            && (parent2[bit] & child2.0[bit]) | parent1[bit] != parent1[bit]
        {
            return false;
        }
    }
    true
}

/// Forget the rights not in `request`; true if what's left is granted.
fn scope_to_request(request: u16, masks: &mut Masks) -> bool {
    for (bit, m) in masks.iter_mut().enumerate() {
        if request & (1 << bit) == 0 {
            *m = 0;
        }
    }
    all_granted(masks)
}

/// A right other than REFER refused (Linux's is_eacces).
fn is_eacces(masks: &Masks, request: u16) -> bool {
    bits(request & !REFER).any(|bit| masks[bit] != 0)
}

// ---------------------------------------------------------------- system calls

/// The ruleset at descriptor `fd`, opened for `write` (add_rule) or
/// reading (restrict_self).
fn ruleset_of(p: &Process, fd: u64, write: bool) -> Result<RulesetRef, Errno> {
    let file = p.fds.get(fd)?;
    let f = file.lock();
    let FileKind::Landlock(rs) = &f.kind else { return Err(EBADFD) };
    let acc = f.flags & O_ACCMODE;
    let can = if write { acc == O_WRONLY || acc == O_RDWR } else { acc == O_RDONLY || acc == O_RDWR };
    if !can {
        return Err(EPERM);
    }
    Ok(rs.clone())
}

/// landlock_create_ruleset(attr, size, flags).
pub fn create_ruleset(p: &mut Process, attr: u64, size: u64, flags: u64) -> SysResult {
    if flags == CREATE_RULESET_VERSION {
        return if attr == 0 && size == 0 { Ok(ABI) } else { Err(EINVAL) };
    }
    if flags != 0 {
        return Err(EINVAL);
    }
    // struct landlock_ruleset_attr { u64 handled_access_fs, handled_access_net; }
    // (ABI 6's `scoped` after them, which must then be zero), read as
    // copy_min_struct_from_user does.
    if attr == 0 {
        return Err(EFAULT);
    }
    if size < 8 {
        return Err(EINVAL);
    }
    if size > 4096 {
        return Err(E2BIG);
    }
    let mut raw = [0u8; 16];
    let known = (size as usize).min(16);
    copy_in(&mut p.aspace, attr, &mut raw[..known])?;
    if size > 16 {
        let mut rest = alloc::vec![0u8; size as usize - 16];
        copy_in(&mut p.aspace, attr.checked_add(16).ok_or(EFAULT)?, &mut rest)?;
        if rest.iter().any(|&b| b != 0) {
            return Err(E2BIG);
        }
    }
    let fs = u64::from_le_bytes(raw[..8].try_into().unwrap());
    let net = u64::from_le_bytes(raw[8..].try_into().unwrap());
    if fs & !(FS_ALL as u64) != 0 || net & !(NET_ALL as u64) != 0 {
        return Err(EINVAL);
    }
    if fs == 0 && net == 0 {
        return Err(ENOMSG);
    }
    let rs = Ruleset {
        handled_fs: fs as u16,
        handled_net: net as u16,
        fs: BTreeMap::new(),
        net: BTreeMap::new(),
        held: Held::new(core::mem::size_of::<Ruleset>() + 64)?,
    };
    let file = new_file(FileKind::Landlock(Arc::new(Mutex::new(rs))), O_RDWR);
    p.fds.alloc(FdEntry { file, cloexec: true }, 0)
}

/// landlock_add_rule(ruleset_fd, rule_type, rule_attr, flags).
pub fn add_rule(p: &mut Process, fd: u64, ty: u64, attr: u64, flags: u64) -> SysResult {
    if flags != 0 {
        return Err(EINVAL);
    }
    let rs = ruleset_of(p, fd, true)?;
    match ty {
        RULE_PATH_BENEATH => {
            // struct landlock_path_beneath_attr { u64 allowed_access; s32 parent_fd; } (packed)
            let mut raw = [0u8; 12];
            copy_in(&mut p.aspace, attr, &mut raw)?;
            let allowed = u64::from_le_bytes(raw[..8].try_into().unwrap());
            let parent_fd = i32::from_le_bytes(raw[8..].try_into().unwrap());
            if allowed == 0 {
                return Err(ENOMSG);
            }
            let mask = rs.lock().handled_fs as u64;
            if allowed | mask != mask {
                return Err(EINVAL);
            }
            let allowed = allowed as u16;
            // Any descriptor of a node, O_PATH ones too; not pipes, sockets
            // or anonymous files (EBADFD, as Linux's get_path_from_fd).
            let file = p.fds.get(parent_fd as i64 as u64)?;
            let ino = match &file.lock().kind {
                FileKind::Node(ino) | FileKind::Dev(_, ino) | FileKind::Fifo(crate::fd::FifoFile { ino, .. }) => *ino,
                FileKind::Pty(end) => end.ino,
                _ => return Err(EBADFD),
            };
            let fs = fs::lock();
            if !fs.is_dir(ino) && allowed & !ACCESS_FILE != 0 {
                return Err(EINVAL);
            }
            let mut rs = rs.lock();
            let rs = &mut *rs;
            if !rs.fs.contains_key(&ino) {
                rs.held.take(1)?;
                rs.fs.insert(ino, (0, fs.pin(ino)));
            }
            rs.fs.get_mut(&ino).unwrap().0 |= allowed;
            Ok(0)
        }
        RULE_NET_PORT => {
            // struct landlock_net_port_attr { u64 allowed_access; u64 port; }
            let mut raw = [0u8; 16];
            copy_in(&mut p.aspace, attr, &mut raw)?;
            let allowed = u64::from_le_bytes(raw[..8].try_into().unwrap());
            let port = u64::from_le_bytes(raw[8..].try_into().unwrap());
            if allowed == 0 {
                return Err(ENOMSG);
            }
            let mut rs = rs.lock();
            let mask = rs.handled_net as u64;
            if allowed | mask != mask || port > u16::MAX as u64 {
                return Err(EINVAL);
            }
            let rs = &mut *rs;
            if !rs.net.contains_key(&(port as u16)) {
                rs.held.take(1)?;
            }
            *rs.net.entry(port as u16).or_default() |= allowed as u16;
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}

/// landlock_restrict_self(ruleset_fd, flags): a new layer on the calling
/// thread's domain.
pub fn restrict_self(p: &mut Process, fd: u64, flags: u64) -> SysResult {
    if flags != 0 {
        return Err(EINVAL);
    }
    // As seccomp: no_new_privs, or CAP_SYS_ADMIN, which here is root's
    // (nothing honours setuid bits; a layer only ever takes away).
    if !p.cur().seccomp.no_new_privs && p.uid != 0 {
        return Err(EPERM);
    }
    let rs = ruleset_of(p, fd, false)?;
    let rs = rs.lock();
    let parent = p.cur().landlock.clone();
    let parent = parent.as_deref();
    let level = parent.map_or(0, |d| d.layers.len());
    if level >= MAX_LAYERS {
        return Err(E2BIG);
    }
    // The budget before the copies (a rule on the same object in both is
    // counted twice: at most by this much, for as long as it's held).
    let mut held = Held::new(core::mem::size_of::<Domain>() + core::mem::size_of::<Layer>() * (level + 1) + 64)?;
    held.take(parent.map_or(0, |d| d.fs.len() + d.net.len()) + rs.fs.len() + rs.net.len())?;
    let mut layers = parent.map_or_else(Vec::new, |d| d.layers.clone());
    let id = NEXT_LAYER.fetch_add(1, Ordering::Relaxed);
    layers.push(Layer { id, fs: rs.handled_fs, net: rs.handled_net });
    let mut fs = parent.map_or_else(BTreeMap::new, |d| d.fs.clone());
    for (&ino, (access, pin)) in &rs.fs {
        fs.entry(ino).or_insert_with(|| ([0; MAX_LAYERS], pin.clone())).0[level] = *access;
    }
    let mut net = parent.map_or_else(BTreeMap::new, |d| d.net.clone());
    for (&port, &access) in &rs.net {
        net.entry(port).or_insert([0; MAX_LAYERS])[level] = access;
    }
    let domain = Domain { layers, fs, net, _held: held };
    p.cur().landlock = Some(Arc::new(domain));
    p.landlocked = true;
    Ok(0)
}

/// The TCP port a bind or connect names, checked as Linux's
/// current_check_access_socket checks it before the network stack sees
/// it: Ok(None) when Landlock has nothing to say (another family, or a
/// disconnect).
fn socket_port(p: &mut Process, v6: bool, addr: u64, len: u64, bind: bool) -> Result<Option<u16>, Errno> {
    const AF_UNSPEC: u16 = 0;
    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 10;
    if len < 2 {
        return Err(EINVAL);
    }
    let mut raw = [0u8; 24];
    let n = (len as usize).min(24);
    copy_in(&mut p.aspace, addr, &mut raw[..n])?;
    let family = u16::from_le_bytes([raw[0], raw[1]]);
    let port = u16::from_be_bytes([raw[2], raw[3]]);
    match family {
        AF_UNSPEC | AF_INET if len < 16 => return Err(EINVAL),
        // SIN6_LEN_RFC2133
        AF_INET6 if len < 24 => return Err(EINVAL),
        AF_UNSPEC | AF_INET | AF_INET6 => {}
        _ => return Ok(None),
    }
    let own = if v6 { AF_INET6 } else { AF_INET };
    if family == AF_UNSPEC {
        // Disconnecting is always allowed; binding to AF_UNSPEC is
        // INADDR_ANY on an AF_INET socket only.
        if !bind {
            return Ok(None);
        }
        if own != AF_INET {
            return Err(EINVAL);
        }
        if raw[4..8] != [0; 4] {
            return Err(EAFNOSUPPORT);
        }
    } else if family != own {
        return Err(EINVAL);
    }
    Ok(Some(port))
}

/// A TCP socket's bind (`bind`) or connect to the address at `addr`.
pub fn check_socket(p: &mut Process, v6: bool, addr: u64, len: u64, bind: bool) -> Result<(), Errno> {
    let Some(d) = domain(p) else { return Ok(()) };
    let access = if bind { BIND_TCP } else { CONNECT_TCP };
    if d.init(access, true).1 == 0 {
        return Ok(());
    }
    match socket_port(p, v6, addr, len, bind)? {
        Some(port) if !d.net_allowed(port, access) => Err(EACCES),
        _ => Ok(()),
    }
}

/// Device ioctls a file opened without IOCTL_DEV may still make (Linux's
/// is_masked_device_ioctl): the descriptor's own (FIOCLEX, FIONBIO, ...)
/// and the filesystem's.
pub fn ioctl_exempt(cmd: u32) -> bool {
    matches!(
        cmd,
        0x5451 // FIOCLEX
            | 0x5450 // FIONCLEX
            | 0x5421 // FIONBIO
            | 0x5452 // FIOASYNC
            | 0x5460 // FIOQSIZE
            | 0xc004_5877 // FIFREEZE
            | 0xc004_5878 // FITHAW
            | 0xc020_660b // FS_IOC_FIEMAP
            | 0x2 // FIGETBSZ
            | 0x4004_9409 // FICLONE
            | 0x4020_940d // FICLONERANGE
            | 0xc018_9436 // FIDEDUPERANGE
            | 0x8011_1500 // FS_IOC_GETFSUUID
            | 0x8081_1501 // FS_IOC_GETFSSYSFSPATH
    )
}
