# grix in a web page

Runnable grix examples for a web page. The real grix kernel boots in QEMU
compiled to WebAssembly ([qemu-wasm](https://github.com/ktock/qemu-wasm),
QEMU 8.2 with a TCG backend that emits wasm). grix's host side for a page,
`crates/web` (`grix-web`), is grix's own Rust compiled to
`wasm32-unknown-unknown`. It builds the boot image with `grix_abi::image`,
decodes the console's frames with `grix_abi::wire`, and gives stdin the
same credit-based flow control as the CLI. Nothing about the guest is
re-implemented in JavaScript.

```sh
make kernel fixtures
web/build.sh                   # assembles web/dist (QEMU-wasm: ~15 min the first time, in Docker)
node web/serve.mjs web/dist    # http://localhost:8080/
```

- `grix.js`: `Grix.load(...)`, then `grix.run({ argv, files, allow, stdin | tty, ... })`.
- `grix-example.js`: `<grix-example>`, an example a reader can edit, grant
  capabilities to and run again (see the top of the file for its attributes).
- `index.html`: every example below, on one page. `smoke.html?bin=...&argv=[...]` runs one program.

## Hosting

QEMU's threads are Web Workers sharing memory, so the page that shows the
examples must be **cross-origin isolated**:

- **Headers**, where the host can set them:
  `Cross-Origin-Opener-Policy: same-origin` and
  `Cross-Origin-Embedder-Policy: require-corp`. `serve.mjs` sends them, and
  so does Cloudflare Pages (or Netlify) from the `_headers` file `build.sh`
  writes into `web/dist`.
- **GitHub Pages** can't set headers. There, the page loads
  [coi-serviceworker](https://github.com/gzuidhof/coi-serviceworker)
  (`build.sh` puts it in `web/dist`) before anything else. On the first
  visit it installs a service worker and reloads the page once, after which
  the worker adds the headers. The script has to be served from the page's
  own site.

The files can live somewhere other than the page, for instance a blog on
GitHub Pages with the files on Cloudflare: load `grix-example.js` by its
full URL, and the rest comes from beside it. They need
`Access-Control-Allow-Origin` and `Cross-Origin-Resource-Policy:
cross-origin` (the `_headers` file has both). A browser won't start a Worker
from another site's script, so `grix.js` starts each of QEMU's workers as a
small module of the page's own that imports the real one. Cloudflare Pages
takes files up to 25 MiB, which the Node root filesystem (28 MB) is over.

**grixos.dev** is `web/dist`, deployed by `web/deploy.sh`. The page, the
runner, QEMU and the kernel are on Cloudflare Pages (project `grixos`).
The examples' programs and root filesystems are in R2 (bucket
`grixos-files`, at `files.grixos.dev`, with CORS open to every origin
for GET), and the page finds them through
`<meta name="grix-files" content="https://files.grixos.dev/">`. Another
page, such as a blog post, can use them the same way:

```html
<meta name="grix-files" content="https://files.grixos.dev/">
<script src="/coi-serviceworker.js"></script>   <!-- if the host can't set COOP/COEP -->
<script type="module" src="https://grixos.dev/grix-example.js"></script>
<grix-example command="/bin/net" caps="net"
  files='[{"src": "bin/net", "path": "/bin/net", "mode": 493}]'></grix-example>
```

Each run reserves 1.5 GiB of wasm memory (guest RAM, QEMU and its
translation cache) and only one machine runs at a time: starting an
example stops the one running. Phones may not have that much memory.

Everything is static. What a reader downloads once (and then caches):

| | size | gzipped |
|---|---|---|
| QEMU (`qemu-system-aarch64.wasm`) | 17.9 MB | 4.5 MB |
| grix kernel (stripped) | 0.96 MB | 0.43 MB |
| grix-web | 0.19 MB | |

## Which examples are worth embedding

Measured in Chromium on an x86_64 Linux host (16 cores), with assets
already cached. "Time" runs from Run to the exit status and includes
booting the machine.

| example | payload (gzipped) | time | verdict |
|---|---|---|---|
| `hello`: argv, env, stdout/stderr, exit status | 16 KB | 0.7 s | **yes** |
| `net` without and then with `net`: the denial and what it needed | 15 KB | 0.7 s | **yes**, the core story |
| busybox `wc` of an imported file and a missing one | 660 KB | 0.7 s | **yes** |
| busybox `sort` with editable stdin | 660 KB | 0.8 s | **yes** |
| busybox `sh -c` pipeline, without and then with `process` | 660 KB | 1.1 s | **yes** |
| bash REPL in TTY mode (job control, Ctrl-C, `fs_write` denials) | 1.8 MB | prompt in 1.2 s | **yes**, the best hands-on demo |
| pthreads (`threads`) | 23 KB | 1.5 s | yes |
| Go `os/exec` (fork, pipes, kill) | 790 KB | 2.5 s | yes |
| Python 3.12 REPL | 15 MB | prompt in 9 s | yes, once the reader opts in (readline and site make it slower than `-c`) |
| Python `-c` | 15 MB | 4.8 s | yes, opt-in |
| Node 22 `-e` | 28 MB | 9.3 s | maybe: it's the size more than the time |
| 4 CPUs (`smp`) | | 195 s, against 3 s on 1 CPU | no |

What a page can't show:

- **Networking beyond the guest.** The page has no host proxy, so `net`
  only lets sockets exist (and loopback inside the guest). A WebSocket
  proxy could stand in for `crates/grix/src/net.rs`, but that's a server.
- **Several CPUs.** It works but is about 60× slower here (QEMU-wasm's
  multi-vCPU path).
- **Exports, mounts, snapshots, x86_64 programs.** Exports could be wired
  up (`grix_abi::wire::ExportMsg`). Live mounts need a host filesystem.
  Snapshots need grix-vmm. x86_64 programs would run under qemu-x86_64
  inside the emulated machine: 38 MB and very slow.

## How the console gets through

QEMU-wasm's stdio is a TTY whose operations go to `Module.pty`
(xterm-pty's emscripten library). `grix.js` gives it a pty with no line
discipline that hands what QEMU writes to grix-web and feeds frames back.
The browser's `poll()` there waits only for that pty, never for QEMU's
other descriptors, which has two consequences:

- `virtio-mmio.ioeventfd=off`: a queue kick is otherwise an eventfd for
  the main loop, which never sees it, so the device never takes the
  guest's output.
- The page wakes QEMU's main loop every 2 ms. Without that, bottom halves
  and newly armed timers wait for the next console input.

QEMU also never gets from the guest's PSCI `SYSTEM_OFF` to `exit()`, so a
run ends at the guest's exit frame, and the page terminates QEMU's
workers.
