// <grix-example>: a grix run a reader can start, change and run again,
// in the page, on the grix kernel in QEMU compiled to wasm.
//
//   <script type="module" src="grix-example.js"></script>
//   <grix-example
//     command="/bin/net"                      the program and its arguments, shell-quoted
//     files='[{"src": "bin/net", "path": "/bin/net", "mode": 493}]'
//                                             or {"tar": "rootfs/python.tar.gz", "path": "/"},
//                                             or {"text": "...", "path": "/data/x"},
//                                             or {"symlink": "busybox", "path": "/bin/sh"}; `src`
//                                             and `tar` are relative to this script, or to
//                                             <meta name="grix-files" content="URL/"> if the page has one
//     caps="net"                              capabilities the reader may grant
//     allow=""                                ...and those granted to begin with
//     env="GREETING=hi"                       space-separated, or a JSON array
//     stdin="pear&#10;apple"                  the program's stdin (editable)
//     tty                                     an interactive terminal instead
//     show-missing                            list each path looked up but not imported
//                                             (otherwise they're counted, as by the CLI)
//     memory="256" download="14 MB" timeout="60">
//   </grix-example>
//
// The page must be cross-origin isolated (COOP: same-origin, COEP:
// require-corp): QEMU's threads need SharedArrayBuffer.

import { Grix } from './grix.js';
import { fetchTar } from './tar.js';

const BASE = new URL('.', import.meta.url);
const asset = (p) => new URL(p, BASE).href;
// The examples' programs and root filesystems: beside this script, or
// where the page's <meta name="grix-files" content="URL/"> says.
const FILES = document.querySelector('meta[name="grix-files"]')?.content;
const exampleFile = (p) => new URL(p, FILES ? new URL(FILES, location.href) : BASE).href;

let grixPromise = null;
function loadGrix() {
  grixPromise ??= Grix.load({
    qemu: asset('qemu-system-aarch64.js'),
    kernel: asset('grix-kernel'),
    web: asset('grix_web.wasm'),
  }).catch((e) => {
    grixPromise = null;
    throw e;
  });
  return grixPromise;
}

// One machine at a time (each is most of a gigabyte): starting an example
// stops the one running, and its machine goes before the next comes.
let active = null;
let queue = Promise.resolve();
function exclusive(f) {
  const next = queue.then(f, f);
  queue = next.catch(() => {});
  return next;
}

const fileCache = new Map();
function loadFiles(specs) {
  return Promise.all(specs.map((f) => {
    if (f.symlink !== undefined) return [{ path: f.path, symlink: f.symlink }];
    if (f.text !== undefined) return [{ path: f.path, data: new TextEncoder().encode(f.text), mode: f.mode ?? 0o644 }];
    const key = f.tar ?? f.src;
    if (!fileCache.has(key)) {
      const p = f.tar ? fetchTar(exampleFile(f.tar), f.path ?? '/')
        : fetch(exampleFile(f.src)).then((r) => {
          if (!r.ok) throw new Error(`${f.src}: ${r.status}`);
          return r.arrayBuffer();
        }).then((b) => [{ path: f.path, data: new Uint8Array(b), mode: f.mode ?? 0o755 }]);
      fileCache.set(key, p.catch((e) => {
        fileCache.delete(key);
        throw e;
      }));
    }
    return fileCache.get(key);
  })).then((lists) => lists.flat());
}

// A command line as argv: words, '...', "..." and backslashes, as sh.
export function splitCommand(s) {
  const words = [];
  let word = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (/\s/.test(c)) {
      if (word !== null) words.push(word);
      word = null;
    } else if (c === "'") {
      const end = s.indexOf("'", i + 1);
      if (end < 0) throw new Error('unterminated quote');
      word = (word ?? '') + s.slice(i + 1, end);
      i = end;
    } else if (c === '"') {
      word ??= '';
      for (i++; i < s.length && s[i] !== '"'; i++) {
        if (s[i] === '\\' && i + 1 < s.length && '"\\$`'.includes(s[i + 1])) i++;
        word += s[i];
      }
      if (i >= s.length) throw new Error('unterminated quote');
    } else if (c === '\\' && i + 1 < s.length) {
      word = (word ?? '') + s[++i];
    } else {
      word = (word ?? '') + c;
    }
  }
  if (word !== null) words.push(word);
  return words;
}

const STYLE = `
:host {
  --gx-bg: #ffffff; --gx-fg: #1d1f23; --gx-muted: #6a6f78; --gx-border: #d9dce1;
  --gx-panel: #f6f7f9; --gx-term: #15171b; --gx-term-fg: #e6e8eb; --gx-err: #f0a38b;
  --gx-event: #8fc1ff; --gx-ok: #7bd389; --gx-bad: #f28b82; --gx-accent: #2f6fde;
  display: block; margin: 1.25rem 0; font: 14px/1.45 system-ui, sans-serif; color: var(--gx-fg);
}
@media (prefers-color-scheme: dark) {
  :host { --gx-bg: #1b1d21; --gx-fg: #e6e8eb; --gx-muted: #9aa0a9; --gx-border: #33373e;
          --gx-panel: #22252a; --gx-accent: #78a6ff; }
}
.box { border: 1px solid var(--gx-border); border-radius: 8px; overflow: hidden; background: var(--gx-bg); }
.bar { display: flex; flex-wrap: wrap; gap: 8px 12px; align-items: center; padding: 8px 10px;
       background: var(--gx-panel); border-bottom: 1px solid var(--gx-border); }
.cmd { flex: 1 1 260px; display: flex; align-items: center; gap: 6px; min-width: 0; }
.cmd span { color: var(--gx-muted); font-family: ui-monospace, monospace; }
input.command { flex: 1; min-width: 0; font: 13px ui-monospace, SFMono-Regular, Menlo, monospace;
       padding: 5px 7px; border: 1px solid var(--gx-border); border-radius: 5px;
       background: var(--gx-bg); color: var(--gx-fg); }
/* The capabilities and Run move as one: when the bar wraps, they share a row. */
.actions { display: flex; align-items: center; gap: 12px; margin-left: auto; }
.caps { display: flex; gap: 10px; flex-wrap: wrap; font: 12px ui-monospace, monospace; }
.caps label { display: inline-flex; gap: 4px; align-items: center; cursor: pointer; white-space: nowrap; }
button { font: 600 13px system-ui, sans-serif; padding: 5px 14px; border-radius: 5px; cursor: pointer;
         border: 1px solid var(--gx-accent); background: var(--gx-accent); color: #fff; }
button.secondary { background: transparent; color: var(--gx-accent); }
button:disabled { opacity: .5; cursor: default; }
textarea { display: block; width: 100%; box-sizing: border-box; border: 0;
           border-bottom: 1px solid var(--gx-border); padding: 6px 10px; resize: vertical;
           font: 12px ui-monospace, monospace; background: var(--gx-bg); color: var(--gx-fg); }
.stdin-label { font-size: 11px; color: var(--gx-muted); padding: 4px 10px 0; text-transform: uppercase; letter-spacing: .04em; }
pre.out { margin: 0; padding: 10px 12px; min-height: 3.2em; max-height: 360px; overflow: auto;
          background: var(--gx-term); color: var(--gx-term-fg);
          font: 12.5px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace; white-space: pre-wrap; word-break: break-word; }
.term { background: var(--gx-term); padding: 6px; }
.term .idle { color: var(--gx-muted); padding: 4px 6px; }
.err { color: var(--gx-err); }
.event { color: var(--gx-event); }
.status { color: var(--gx-muted); }
.status.ok { color: var(--gx-ok); }
.status.bad { color: var(--gx-bad); }
.events { margin: 0; padding: 6px 10px; max-height: 7.5em; overflow: auto; border-top: 1px solid var(--gx-border);
          font: 12px/1.45 ui-monospace, monospace; color: var(--gx-accent); white-space: pre-wrap; background: var(--gx-panel); }
.missing { padding: 4px 10px; border-top: 1px solid var(--gx-border); font: 12px ui-monospace, monospace; color: var(--gx-muted); }
.missing summary { cursor: pointer; }
.missing pre { margin: 4px 0; max-height: 10em; overflow: auto; white-space: pre-wrap; }
.note { padding: 6px 10px; font-size: 12px; color: var(--gx-muted); border-top: 1px solid var(--gx-border); }
`;

class GrixExample extends HTMLElement {
  connectedCallback() {
    if (this.shadowRoot) return;
    const root = this.attachShadow({ mode: 'open' });
    const tty = this.hasAttribute('tty');
    const caps = (this.getAttribute('caps') ?? '').split(/\s+/).filter(Boolean);
    const allow = new Set((this.getAttribute('allow') ?? '').split(/\s+/).filter(Boolean));
    root.innerHTML = `<style>${STYLE}</style>
      <div class="box">
        <div class="bar">
          <div class="cmd"><span>$</span><input class="command" spellcheck="false" aria-label="Command"></div>
          <div class="actions"><div class="caps"></div><button class="run">Run</button></div>
        </div>
        <div class="stdin" hidden><div class="stdin-label">stdin</div><textarea rows="3" spellcheck="false" aria-label="stdin"></textarea></div>
        ${tty ? '<div class="term"><pre class="out idle">Press Run to start a terminal.</pre></div><pre class="events" hidden></pre>' : '<pre class="out" aria-live="polite"></pre>'}
        <details class="missing" hidden><summary></summary><pre></pre></details>
        <div class="note" hidden></div>
      </div>`;
    this.$ = (s) => root.querySelector(s);
    this.$('.command').value = this.getAttribute('command') ?? '';
    for (const cap of caps) {
      const label = document.createElement('label');
      label.innerHTML = `<input type="checkbox"> ${cap}`;
      label.title = `Grant the ${cap} capability`;
      const box = label.querySelector('input');
      box.value = cap;
      box.checked = allow.has(cap);
      this.$('.caps').append(label);
    }
    if (this.hasAttribute('stdin')) {
      this.$('.stdin').hidden = false;
      this.$('textarea').value = this.getAttribute('stdin');
    }
    const download = this.getAttribute('download');
    if (download) this.note(`Downloads ${download} the first time it runs.`);
    if (!tty) this.$('pre.out').innerHTML = '<span class="status">Press Run.</span>';
    this.$('.run').addEventListener('click', () => (this.running ? this.running.stop('stopped') : this.start()));
    this.$('.command').addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !this.running) this.start();
    });
  }

  note(text) {
    const n = this.$('.note');
    n.hidden = !text;
    n.textContent = text ?? '';
  }

  print(text, cls) {
    const pre = this.$('pre.out');
    const atEnd = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 4;
    if (cls) {
      const span = document.createElement('span');
      span.className = cls;
      span.textContent = text;
      pre.append(span);
    } else {
      pre.append(text);
    }
    if (atEnd) pre.scrollTop = pre.scrollHeight;
  }

  async terminal() {
    if (this.term) return this.term;
    // Each example's shadow root needs the stylesheet; the script, once.
    const css = document.createElement('link');
    css.rel = 'stylesheet';
    css.href = asset('vendor/xterm.css');
    this.shadowRoot.append(css);
    await new Promise((ok) => (css.onload = css.onerror = ok));
    if (!globalThis.Terminal) {
      await new Promise((ok, fail) => {
        const s = document.createElement('script');
        s.src = asset('vendor/xterm.js');
        s.onload = ok;
        s.onerror = () => fail(new Error('loading xterm.js'));
        document.head.append(s);
      });
    }
    this.term = new globalThis.Terminal({ rows: 20, cols: 80, convertEol: false, fontSize: 13,
      theme: { background: '#15171b' } });
    this.$('.term .idle')?.remove();
    this.term.open(this.$('.term'));
    this.term.onData((d) => this.running?.write?.(new TextEncoder().encode(d)));
    return this.term;
  }

  async start() {
    const tty = this.hasAttribute('tty');
    const button = this.$('.run');
    let argv;
    try {
      argv = splitCommand(this.$('.command').value.trim());
      if (!argv.length) throw new Error('no command');
    } catch (e) {
      if (!tty) this.$('pre.out').innerHTML = '';
      return this.print(`${e.message}\n`, 'status bad');
    }
    const allow = [...this.shadowRoot.querySelectorAll('.caps input:checked')].map((b) => b.value);
    const out = tty ? null : this.$('pre.out');
    if (out) out.innerHTML = '';
    button.textContent = 'Stop';
    if (active && active !== this) active.running?.stop('stopped: another example started');
    active = this;
    const pending = {};
    this.running = {
      stop: (why) => {
        pending.stop = why;
        this.handle?.stop();
      },
      write: (b) => this.handle?.write(b),
    };
    const say = (t, cls) => (tty ? this.term?.write(t.replace(/\n/g, '\r\n')) : this.print(t, cls));
    // In a terminal, events would land in the middle of the program's screen.
    const events = this.$('pre.events');
    if (events) {
      events.textContent = '';
      events.hidden = true;
    }
    const event = (e) => {
      if (!events) return this.print(`grix: ${e}\n`, 'event');
      events.hidden = false;
      events.append(`grix: ${e}\n`);
      events.scrollTop = events.scrollHeight;
    };
    // Programs probe many paths that don't exist: as the CLI does without
    // -v, count them (here, with the list a click away).
    const missing = this.$('.missing');
    let missed = 0;
    missing.hidden = true;
    missing.querySelector('pre').textContent = '';
    const onMissing = this.hasAttribute('show-missing') ? event : (e) => {
      missed++;
      missing.hidden = false;
      missing.querySelector('summary').textContent = `grix: ${missed} path(s) were looked up but not imported`;
      missing.querySelector('pre').append(`${e}\n`);
    };
    const env = this.getAttribute('env') ?? '';
    try {
      let term;
      if (tty) {
        term = await this.terminal();
        term.reset();
        // As wide as the box, less xterm's scrollbar (the program learns its
        // size at start).
        const cell = term._core?._renderService?.dimensions?.css?.cell?.width || 7.8;
        const cols = Math.max(40, Math.min(120, Math.floor((this.$('.term').clientWidth - 30) / cell)));
        if (cols !== term.cols) term.resize(cols, term.rows);
        term.focus();
      }
      const t0 = performance.now();
      const loading = setTimeout(() => say('Loading the machine…\n', 'status'), 150);
      const [grix, files] = await Promise.all([loadGrix(), loadFiles(JSON.parse(this.getAttribute('files') ?? '[]'))]);
      clearTimeout(loading);
      if (!crossOriginIsolated) throw new Error('This page is not cross-origin isolated (COOP/COEP), which QEMU in wasm needs.');
      const loaded = performance.now() - t0;
      if (out) out.innerHTML = '';
      // Through the write queue, behind what's in it (reset() would jump it).
      term?.write('\x1bc');
      if (pending.stop) throw new Error(pending.stop);
      const result = await exclusive(async () => {
        const run = grix.run({
          argv,
          files,
          allow,
          env: env.startsWith('[') ? JSON.parse(env) : env.split(/\s+/).filter(Boolean),
          memoryMb: Number(this.getAttribute('memory') ?? 256),
          stdin: tty || !this.hasAttribute('stdin') ? undefined : new TextEncoder().encode(this.$('textarea').value),
          interactive: tty,
          tty: tty ? [term.rows, term.cols] : null,
          timeoutMs: Number(this.getAttribute('timeout') ?? (tty ? 0 : 120)) * 1000,
          onStdout: (b) => (tty ? term.write(b) : this.print(new TextDecoder().decode(b))),
          onStderr: (b) => (tty ? term.write(b) : this.print(new TextDecoder().decode(b), 'err')),
          onEvent: event,
          onMissing,
        });
        this.handle = run;
        if (pending.stop) run.stop();
        return run.done;
      });
      const secs = ((result.ended ?? performance.now()) - result.started) / 1000;
      const ok = result.status === 'exited with status 0';
      const status = result.status ?? pending.stop ?? `no exit status: ${result.qemu}`;
      say(`\n[${status}${result.timedOut ? ' (timed out)' : ''} · ${secs.toFixed(1)} s` +
        `${loaded > 500 ? ` · ${(loaded / 1000).toFixed(1)} s loading` : ''}]\n`, ok ? 'status ok' : 'status');
    } catch (e) {
      say(`\n${e.message ?? e}\n`, 'status bad');
    } finally {
      this.running = null;
      this.handle = null;
      if (active === this) active = null;
      button.textContent = 'Run';
    }
  }
}

customElements.define('grix-example', GrixExample);
