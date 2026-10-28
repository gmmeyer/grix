// grix in a web page: the grix kernel in QEMU compiled to wasm, with the
// host's side (boot image, console frames, stdin credit) from grix-web,
// grix's own Rust, also compiled to wasm.
//
//   const grix = await Grix.load({ qemu: './qemu-system-aarch64.js',
//                                  kernel: './grix-kernel', web: './grix_web.wasm' });
//   const run = grix.run({ argv: ['/bin/hello'], files: [{ path: '/bin/hello', data, mode: 0o755 }],
//                          onStdout, onStderr, onEvent, onMissing, onLog });
//   await run.done;   // { status: 'exited with status 0', ... }
//
// QEMU needs threads, so the page must be cross-origin isolated (COOP and
// COEP headers) for SharedArrayBuffer.

const textEncoder = new TextEncoder();

// grix-web's exports, over its memory.
class Web {
  constructor(instance) {
    this.x = instance.exports;
  }

  static async load(url) {
    const { instance } = await WebAssembly.instantiateStreaming(fetch(url), {});
    return new Web(instance);
  }

  // Copy bytes into grix-web's memory; returns [ptr, len] to free after.
  put(bytes) {
    const len = bytes.length;
    const ptr = this.x.grix_alloc(len);
    new Uint8Array(this.x.memory.buffer, ptr, len).set(bytes);
    return [ptr, len];
  }

  out() {
    return new Uint8Array(this.x.memory.buffer, this.x.grix_out_ptr(), this.x.grix_out_len()).slice();
  }

  // Call `f(ptr, len, ...)` with `bytes` in grix-web's memory.
  with(bytes, f) {
    const [ptr, len] = this.put(bytes);
    try {
      return f(ptr, len);
    } finally {
      this.x.grix_free(ptr, len);
    }
  }

  check(status) {
    if (status !== 0) throw new Error(new TextDecoder().decode(this.out()));
  }

  reset() {
    this.x.grix_reset();
  }

  import(kind, path, mode, data) {
    this.with(textEncoder.encode(path), (pp, pl) =>
      this.with(data, (dp, dl) => this.check(this.x.grix_import(kind, mode, pp, pl, dp, dl))));
  }

  image(spec) {
    this.with(textEncoder.encode(JSON.stringify(spec)), (p, l) => this.check(this.x.grix_image(p, l)));
    return this.out();
  }

  qemuArgs(spec) {
    this.with(textEncoder.encode(JSON.stringify(spec)), (p, l) => this.check(this.x.grix_qemu_args(p, l)));
    return JSON.parse(new TextDecoder().decode(this.out()));
  }

  // Bytes from the machine, as [kind, bytes] records.
  output(bytes) {
    this.with(bytes, (p, l) => this.x.grix_output(p, l));
    const out = this.out();
    const records = [];
    const view = new DataView(out.buffer);
    for (let i = 0; i + 5 <= out.length;) {
      const len = view.getUint32(i + 1, true);
      records.push([out[i], out.subarray(i + 5, i + 5 + len)]);
      i += 5 + len;
    }
    return records;
  }

  stdin(bytes, end) {
    this.with(bytes, (p, l) => this.x.grix_stdin(p, l, end));
  }

  input() {
    this.x.grix_input();
    return this.out();
  }

  signal(n) {
    this.x.grix_signal(n);
    return this.out();
  }

  resize(rows, cols) {
    this.x.grix_resize(rows, cols);
    return this.out();
  }
}

// What QEMU's stdio is: xterm-pty's interface (QEMU-wasm's TTY goes
// through `Module.pty`), carrying the console's frames, with no line
// discipline in the way.
class Console {
  constructor(web, onRecord) {
    this.web = web;
    this.onRecord = onRecord;
    this.pending = [];
    this.readers = new Set();
  }

  get readable() {
    return this.pending.length > 0;
  }

  get writable() {
    return true;
  }

  // QEMU reads the console's input.
  read(n) {
    return this.pending.splice(0, n);
  }

  // QEMU writes what the guest sent.
  write(bytes) {
    for (const [kind, data] of this.web.output(Uint8Array.from(bytes))) this.onRecord(kind, data);
    // Credit may have come back for more stdin.
    this.send(this.web.input());
  }

  send(frames) {
    if (!frames.length) return;
    for (const b of frames) this.pending.push(b);
    this.wake();
  }

  wake() {
    for (const f of [...this.readers]) f();
  }

  // QEMU's main loop waits in poll(), which in the browser waits only for
  // this console (xterm-pty's emscripten-pty.js), not for the other fds
  // that should wake it: its bottom halves, a vCPU arming an earlier
  // timer. So it never sees the console open, and timers fire late. Wake
  // it often; it polls again and finds no input.
  tick(ms) {
    this.ticker = setInterval(() => this.wake(), ms);
  }

  stop() {
    clearInterval(this.ticker);
  }

  onReadable(f) {
    this.readers.add(f);
    return { dispose: () => this.readers.delete(f) };
  }

  onSignal() {
    return { dispose() {} };
  }

  ioctl(req) {
    switch (req) {
      case 'TCGETS':
        return { iflag: 0, oflag: 0, cflag: 0, lflag: 0, cc: new Array(32).fill(0) };
      case 'TIOCGWINSZ':
        return [24, 80];
      default:
        return undefined;
    }
  }
}

const RECORD = { 1: 'stdout', 2: 'stderr', 3: 'log', 4: 'event', 5: 'exit', 6: 'event' };

export class Grix {
  constructor(web, qemuFactory, qemuUrl, kernel) {
    this.web = web;
    this.qemuFactory = qemuFactory;
    this.qemuUrl = qemuUrl;
    this.kernel = kernel;
    this.busy = false;
  }

  static async load({ qemu, kernel, web }) {
    // QEMU's threads are Web Workers, which emscripten keeps no handle on
    // that a run could end: note each one for the run it's made for.
    if (!Grix.workers) {
      Grix.workers = [];
      const Real = globalThis.Worker;
      globalThis.Worker = class extends Real {
        constructor(...a) {
          super(...a);
          Grix.workers.push(this);
        }
      };
    }
    const qemuUrl = new URL(qemu, location.href).href;
    const [w, factory, k] = await Promise.all([
      Web.load(web),
      import(qemuUrl).then(m => m.default),
      fetch(kernel).then(r => r.arrayBuffer()).then(b => new Uint8Array(b)),
    ]);
    return new Grix(w, factory, qemuUrl, k);
  }

  // One program in a fresh machine. `files`: [{ path, data, mode }] or
  // { path, dir: true } or { path, symlink }; `stdin`: bytes, given all
  // at once (or use the run's `write`, then `end`).
  run(opts) {
    if (this.busy) throw new Error('one run at a time');
    this.busy = true;
    const web = this.web;
    web.reset();
    for (const f of opts.files ?? []) {
      if (f.dir) web.import(1, f.path, f.mode ?? 0o755, new Uint8Array());
      else if (f.symlink !== undefined) web.import(2, f.path, 0o777, textEncoder.encode(f.symlink));
      else web.import(0, f.path, f.mode ?? 0o644, f.data);
    }
    const spec = {
      argv: opts.argv,
      env: opts.env ?? [],
      allow: opts.allow ?? [],
      kill_on_deny: !!opts.killOnDeny,
      cwd: opts.cwd ?? '/',
      memory_mb: opts.memoryMb ?? 256,
      uid: opts.uid ?? 1000,
      gid: opts.gid ?? 1000,
      cpus: opts.cpus ?? 1,
      stdin: opts.stdin !== undefined || !!opts.interactive,
      tty: opts.tty ?? null,
      now_ms: Date.now(),
      seed: Array.from(crypto.getRandomValues(new Uint8Array(32))),
    };
    const image = web.image(spec);
    const args = [...web.qemuArgs(spec), ...(opts.qemuArgs ?? [])];
    const result = { status: null, events: [], stdout: '', stderr: '', started: performance.now() };
    const decoders = { 1: new TextDecoder(), 2: new TextDecoder(), 3: new TextDecoder() };
    const console_ = new Console(web, (kind, data) => {
      const name = RECORD[kind];
      if (kind === 4 || kind === 5 || kind === 6) {
        const text = new TextDecoder().decode(data);
        if (kind === 4 || kind === 6) {
          result.events.push(text);
          (kind === 4 ? opts.onEvent : opts.onMissing ?? opts.onEvent)?.(text);
        } else {
          result.status = text;
          result.ended = performance.now();
          // The guest's last word. QEMU-wasm doesn't get from the shutdown
          // to exit(), so the run ends here.
          setTimeout(() => finish('stopped'), 50);
        }
        return;
      }
      if (name === 'log') opts.onLog?.(decoders[kind].decode(data, { stream: true }));
      else {
        result[name] += decoders[kind].decode(data, { stream: true });
        (name === 'stdout' ? opts.onStdout : opts.onStderr)?.(data);
      }
    });
    if (opts.stdin !== undefined) web.stdin(opts.stdin, true);
    console_.send(web.input());
    console_.tick(opts.tickMs ?? 2);

    let resolve;
    const done = new Promise(r => (resolve = r));
    let module;
    // QEMU's threads are Web Workers: kept to end them with the run.
    const workers = [];
    const finish = (how) => {
      if (result.finished) return;
      result.finished = true;
      console_.stop();
      for (const w of workers) w.terminate();
      result.qemu = how;
      if (result.status === null) {
        try {
          const uart = module?.FS?.readFile('/uart');
          if (uart) for (const [kind, data] of web.output(uart)) {
            const text = new TextDecoder().decode(data);
            if (kind === 5) result.status = text;
            else if (kind === 4 || kind === 6) result.events.push(text);
            else result[RECORD[kind]] = (result[RECORD[kind]] ?? '') + text;
          }
        } catch {}
      }
      this.busy = false;
      resolve(result);
    };
    const qemuLog = [];
    Grix.workers = workers;
    this.qemuFactory({
      arguments: args,
      pty: console_,
      mainScriptUrlOrBlob: this.qemuUrl,
      print: (s) => { qemuLog.push(s); opts.onQemu?.(s); },
      printErr: (s) => { qemuLog.push(s); opts.onQemu?.(s); },
      preRun: [(m) => {
        m.FS.writeFile('/grix-kernel', this.kernel);
        m.FS.writeFile('/grix-image', image);
      }],
      onExit: (code) => finish(`QEMU exited (${code})`),
      onAbort: (what) => finish(`QEMU aborted: ${what}`),
    }).then(m => (module = result.module = m), e => finish(`QEMU failed: ${e}`));
    result.qemuLog = qemuLog;
    if (opts.timeoutMs) {
      // As the CLI does: SIGTERM, then a grace period.
      setTimeout(() => {
        if (result.finished) return;
        result.timedOut = true;
        console_.send(web.signal(15));
        setTimeout(() => finish('timed out'), 2000);
      }, opts.timeoutMs);
    }
    return {
      done,
      result,
      stop: () => finish('stopped'),
      write: (bytes) => { web.stdin(bytes, false); console_.send(web.input()); },
      end: () => { web.stdin(new Uint8Array(), true); console_.send(web.input()); },
      signal: (n) => console_.send(web.signal(n)),
      resize: (rows, cols) => console_.send(web.resize(rows, cols)),
    };
  }
}
