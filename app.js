// Viewer for the encrypted session archive (built by tools/build.mjs).
//
// Security model: every data file is AES-256-GCM encrypted; the key is derived on this
// device from the password (PBKDF2-SHA-256 → HKDF, parameters in data/key.json) and never
// leaves it. By default the key lives only in this page's memory. "Remember on this device"
// stores it in IndexedDB as a non-extractable CryptoKey: scripts can use it to decrypt but
// cannot read its bytes. Decrypted text is inserted as text, except assistant Markdown,
// which the build rendered with raw HTML disabled; the page's CSP forbids inline scripts.
"use strict";
(() => {
  const AAD = "remote-page/v1:";
  const INFO = "remote-page/enc/v1";
  const enc = new TextEncoder();
  const $ = (s, el = document) => el.querySelector(s);
  const zh = /^zh/i.test(navigator.language || "");
  const T = zh ? {
    brand: "会话存档", gateTitle: "私人存档", gateSub: "内容已加密，输入密码解锁。", unlock: "解锁", remember: "在此设备上记住",
    gateNote: "密码只在本机用于解密，不会发送到任何地方。", busy: "正在解锁…", bad: "密码不对。", firstOffline: "第一次打开需要联网。",
    search: "搜索会话", searchAll: "全文", lock: "锁定", menu: "会话列表", top: "回到顶部", bottom: "跳到最新",
    pinned: "已置顶", sessions: "会话", archived: "已归档", noSessions: "没有会话", pick: "从左侧选择一个会话",
    synced: "同步于", offlineReady: "离线可用", offlineProgress: "正在缓存", offlineMissing: "离线缓存不完整", fill: "缓存全部", theme: { auto: "主题：跟随系统", light: "主题：浅色", dark: "主题：深色" },
    steps: (n) => `${n} 个步骤`, thinking: "思考过程", pasted: (n) => `粘贴的内容（${n} 行）`, queued: "排队消息", compacted: "对话已压缩", showSummary: "查看摘要", hideSummary: "收起摘要",
    tasks: "任务", next: "下一步", question: "提问", answer: "回答", input: "输入", output: "输出", loading: "正在解密…", failed: "无法打开：",
    updated: "存档已更新。", reload: "载入", results: (n, q) => `“${q}” 的全文结果：${n} 处`, scanning: (a, b) => `正在搜索… ${a}/${b}`, noResults: "没有找到。", items: "条", copy: "复制", copied: "已复制",
  } : {
    brand: "Sessions", gateTitle: "Private archive", gateSub: "The content is encrypted. Enter the password to unlock.", unlock: "Unlock", remember: "Remember on this device",
    gateNote: "The password is used only on this device to decrypt; it is never sent anywhere.", busy: "Unlocking…", bad: "Wrong password.", firstOffline: "The first launch needs a network connection.",
    search: "Search sessions", searchAll: "Full text", lock: "Lock", menu: "Sessions", top: "Top", bottom: "Latest",
    pinned: "Pinned", sessions: "Sessions", archived: "Archived", noSessions: "No sessions", pick: "Pick a session on the left",
    synced: "Synced", offlineReady: "Available offline", offlineProgress: "Caching", offlineMissing: "Offline cache incomplete", fill: "Cache all", theme: { auto: "Theme: system", light: "Theme: light", dark: "Theme: dark" },
    steps: (n) => `${n} steps`, thinking: "Thinking", pasted: (n) => `Pasted text (${n} lines)`, queued: "Queued message", compacted: "Conversation compacted", showSummary: "Show summary", hideSummary: "Hide summary",
    tasks: "Tasks", next: "Next step", question: "Question", answer: "Answer", input: "Input", output: "Output", loading: "Decrypting…", failed: "Could not open: ",
    updated: "The archive was updated.", reload: "Load", results: (n, q) => `Full-text results for “${q}”: ${n}`, scanning: (a, b) => `Searching… ${a}/${b}`, noResults: "Nothing found.", items: "items", copy: "Copy", copied: "Copied",
  };

  // ---------- small DOM helper ----------
  function el(tag, props, ...kids) {
    const e = document.createElement(tag);
    if (props) for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false) continue;
      if (k === "class") e.className = v;
      else if (k === "text") e.textContent = v;
      else if (k === "html") e.innerHTML = v; // only build-rendered Markdown
      else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v === true ? "" : v);
    }
    for (const k of kids.flat()) if (k != null && k !== false) e.append(k instanceof Node ? k : String(k));
    return e;
  }

  // ---------- crypto ----------
  const hex = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
  let META = null, KEY = null, INDEX = null;
  const DOCS = new Map();

  async function deriveKey(pw, meta) {
    const base = await crypto.subtle.importKey("raw", enc.encode(pw.normalize("NFC")), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: hex(meta.salt), iterations: meta.iter }, base, 256);
    const hk = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode(INFO) }, hk, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  }

  async function openFile(path, key = KEY) {
    const r = await fetch(path, { credentials: "omit" });
    if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
    const buf = new Uint8Array(await r.arrayBuffer());
    if (buf[0] !== 1) throw new Error("unknown file format");
    const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: buf.subarray(1, 13), additionalData: enc.encode(AAD + path) }, key, buf.subarray(13)));
    const len = new DataView(plain.buffer, plain.byteOffset, plain.byteLength).getUint32(0);
    const stream = new Blob([plain.subarray(4, 4 + len)]).stream().pipeThrough(new DecompressionStream("gzip"));
    return JSON.parse(await new Response(stream).text());
  }

  // ---------- remembered key (IndexedDB, non-extractable CryptoKey) ----------
  const KID = location.pathname.replace(/[^/]*$/, "");
  function idb() {
    return new Promise((res, rej) => {
      const r = indexedDB.open("rp-keys", 1);
      r.onupgradeneeded = () => r.result.createObjectStore("keys");
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
  }
  async function kv(mode, fn) {
    const db = await idb();
    return new Promise((res, rej) => {
      const tx = db.transaction("keys", mode);
      const req = fn(tx.objectStore("keys"));
      tx.oncomplete = () => res(req && req.result);
      tx.onerror = () => rej(tx.error);
    });
  }
  const keyGet = () => kv("readonly", (s) => s.get(KID)).catch(() => null);
  const keyPut = (v) => kv("readwrite", (s) => s.put(v, KID));
  const keyDel = () => kv("readwrite", (s) => s.delete(KID)).catch(() => {});

  // ---------- local preferences (no content, only ids and UI state) ----------
  const PREF = "rp-ui:" + KID;
  let prefs = {};
  try { prefs = JSON.parse(localStorage.getItem(PREF) || "{}"); } catch {}
  const savePrefs = () => { try { localStorage.setItem(PREF, JSON.stringify(prefs)); } catch {} };
  prefs.collapsed ||= {};
  prefs.pos ||= {};

  // ---------- theme ----------
  function applyTheme() {
    const t = prefs.theme || "auto";
    if (t === "auto") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", t);
    $("#theme").textContent = T.theme[t];
  }

  // ---------- service worker / offline status ----------
  let swStatus = null, swProgress = null;
  function registerSW() {
    if (!("serviceWorker" in navigator)) return;
    navigator.serviceWorker.register("sw.js").then((reg) => {
      const ask = () => navigator.serviceWorker.controller?.postMessage({ rp: "status" });
      ask();
      document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") { reg.update().catch(() => {}); ask(); } });
    }).catch(() => {});
    let hadController = !!navigator.serviceWorker.controller;
    navigator.serviceWorker.addEventListener("controllerchange", () => {
      if (hadController) showUpdate();
      hadController = true;
      navigator.serviceWorker.controller?.postMessage({ rp: "status" });
    });
    navigator.serviceWorker.addEventListener("message", (e) => {
      const m = e.data || {};
      if (m.rp === "status") { swStatus = m; swProgress = null; }
      if (m.rp === "progress") swProgress = m;
      if (m.rp === "error") swProgress = { error: m.message };
      renderFoot();
    });
  }

  function renderFoot() {
    if (!INDEX) return;
    const desktop = $("#desktop-link");
    if (desktop && INDEX.desktopUrl) {
      const address = new URL(INDEX.desktopUrl);
      if (address.protocol === "https:" && address.hostname.endsWith(".ts.net")) {
        desktop.href = address.href;
        desktop.textContent = zh ? "打开我的桌面" : "Open my desktop";
        desktop.hidden = false;
      }
    }
    const d = new Date(INDEX.built);
    $("#sync").textContent = `${T.synced} ${d.toLocaleString(zh ? "zh-CN" : undefined, { dateStyle: "medium", timeStyle: "short" })}`;
    const off = $("#offline");
    const fill = $("#fill");
    fill.hidden = true;
    if (swProgress && swProgress.total) {
      off.textContent = `${T.offlineProgress} ${swProgress.done}/${swProgress.total}`;
      off.className = "";
    } else if (swStatus) {
      const ok = swStatus.cached >= swStatus.total;
      off.textContent = ok ? `✓ ${T.offlineReady} · ${(swStatus.totalBytes / 1e6).toFixed(0)} MB` : `${T.offlineMissing} (${swStatus.cached}/${swStatus.total})`;
      off.className = ok ? "ok" : "";
      fill.hidden = ok;
    } else {
      off.textContent = "";
    }
  }

  function showUpdate() {
    if (!INDEX) return;
    const b = $("#banner");
    b.replaceChildren(T.updated, el("button", { type: "button", text: T.reload, onclick: async () => { b.hidden = true; await reloadData(); } }));
    b.hidden = false;
  }

  async function reloadData() {
    try {
      INDEX = await openFile("data/index.bin");
      DOCS.clear();
      renderSidebar();
      renderFoot();
      if (current) openSession(current, { keepScroll: true });
    } catch (err) { console.error(err); }
  }

  // ---------- gate ----------
  function showGate(msg) {
    $("#app").hidden = true;
    $("#gate").hidden = false;
    $("#gate-msg").textContent = msg || "";
    setTimeout(() => $("#pw").focus(), 50);
  }

  async function unlock(key) {
    const index = await openFile("data/index.bin", key); // throws OperationError on a wrong key
    KEY = key;
    INDEX = index;
    $("#gate").hidden = true;
    $("#pw").value = "";
    $("#app").hidden = false;
    renderSidebar();
    renderFoot();
    const last = prefs.last && INDEX.sessions.find((s) => s.id === prefs.last);
    if (last) openSession(last.id);
    else showPlaceholder();
  }

  async function lock() {
    await keyDel();
    KEY = null; INDEX = null; DOCS.clear();
    location.reload();
  }

  // ---------- sidebar ----------
  const SORT = {
    recency: (a, b) => b.u - a.u,
    created: (a, b) => b.c - a.c,
    alpha: (a, b) => a.t.localeCompare(b.t, undefined, { numeric: true, sensitivity: "base" }),
  };
  function sorted(list, sec) {
    if (sec.sortBy === "manual" && INDEX.order[sec.id]) {
      const pos = new Map(INDEX.order[sec.id].map((id, i) => [id, i]));
      return list.slice().sort((a, b) => (pos.get(a.id) ?? 1e9) - (pos.get(b.id) ?? 1e9) || b.u - a.u);
    }
    const f = SORT[sec.sortBy] || SORT.recency;
    const out = list.slice().sort(f);
    // Built-in order: recency is newest first, alpha is A→Z; "ascending" flips recency/created.
    if ((sec.sortBy === "recency" || sec.sortBy === "created" || !SORT[sec.sortBy]) && sec.ascending) out.reverse();
    if (sec.sortBy === "alpha" && !sec.ascending) out.reverse();
    return out;
  }

  let filter = "";
  function renderSidebar() {
    const nav = $("#sections");
    nav.replaceChildren();
    const q = filter.trim().toLowerCase();
    const match = (s) => !q || s.t.toLowerCase().includes(q) || (s.cwd || "").toLowerCase().includes(q);
    const all = INDEX.sessions.filter(match);
    const live = all.filter((s) => !s.arc);
    const groups = new Set(INDEX.sections.filter((s) => s.kind === "manual").map((s) => s.id));
    let any = false;
    const addSection = (sec, label, list, flat) => {
      if (!list.length && !(sec.showEmpty && !q)) return;
      any = any || list.length > 0;
      const key = sec.id;
      const collapsed = q ? false : prefs.collapsed[key] ?? sec.collapsed;
      const box = el("div", { class: `sec${collapsed ? " collapsed" : ""}${flat ? " flat" : ""}` });
      const head = el("button", { type: "button", class: "sec-head", onclick: () => {
        const now = !box.classList.contains("collapsed");
        box.classList.toggle("collapsed", now);
        prefs.collapsed[key] = now;
        savePrefs();
      } },
      el("span", { class: "chev", text: "▾" }), el("span", { class: "name", text: label }), el("span", { class: "count", text: String(list.length) }));
      const rows = el("div", { class: "rows" });
      for (const s of sorted(list, sec)) {
        rows.append(el("button", {
          type: "button", class: `row${current === s.id ? " on" : ""}`, "data-id": s.id,
          title: `${s.t}\n${s.cwd || ""}\n${new Date(s.u).toLocaleString()}`,
          onclick: () => { openSession(s.id); closeDrawer(); },
        }, s.t));
      }
      box.append(head, rows);
      nav.append(box);
    };
    for (const sec of INDEX.sections) {
      if (!sec.shown) continue;
      if (sec.kind === "pinned") addSection(sec, T.pinned, live.filter((s) => s.pin));
      else if (sec.kind === "manual") addSection(sec, sec.name, live.filter((s) => !s.pin && s.g === sec.id));
      else if (sec.kind === "sessions") addSection(sec, T.sessions, live.filter((s) => !s.pin && (!s.g || !groups.has(s.g))), true);
    }
    const arc = all.filter((s) => s.arc);
    if (arc.length) addSection({ id: "__archived", sortBy: "recency", collapsed: true }, T.archived, arc, true);
    if (!any) nav.append(el("div", { class: "empty-side", text: T.noSessions }));
  }

  function markActive() {
    for (const r of document.querySelectorAll("#sections .row")) r.classList.toggle("on", r.dataset.id === current);
  }

  // ---------- conversation ----------
  let current = null;
  let openSeq = 0;
  const conv = () => $("#conv");
  const scroller = () => $("#scroll");

  function showPlaceholder() {
    current = null;
    $("#title").textContent = "";
    $("#subtitle").textContent = "";
    conv().replaceChildren(el("div", { class: "placeholder", text: T.pick }));
    markActive();
  }

  async function getDoc(entry) {
    if (DOCS.has(entry.f)) return DOCS.get(entry.f);
    const doc = await openFile("data/s/" + entry.f);
    DOCS.set(entry.f, doc);
    if (DOCS.size > 40) DOCS.delete(DOCS.keys().next().value);
    return doc;
  }

  function savePos() {
    if (!current) return;
    const s = scroller();
    prefs.pos[current] = s.scrollHeight - s.clientHeight - s.scrollTop < 40 ? -1 : s.scrollTop;
    savePrefs();
  }

  async function openSession(id, opts = {}) {
    const entry = INDEX.sessions.find((s) => s.id === id);
    if (!entry) return showPlaceholder();
    if (current && current !== id) savePos();
    const seq = ++openSeq;
    current = id;
    prefs.last = id;
    savePrefs();
    markActive();
    $("#title").textContent = entry.t;
    const d = new Date(entry.u);
    $("#subtitle").textContent = [entry.cwd, entry.br, d.toLocaleString(zh ? "zh-CN" : undefined, { dateStyle: "medium", timeStyle: "short" }), `${entry.n || 0} ${T.items}`].filter(Boolean).join(" · ");
    const keep = opts.keepScroll ? scroller().scrollTop : null;
    if (!DOCS.has(entry.f)) conv().replaceChildren(el("div", { class: "loading", text: T.loading }));
    let doc;
    try { doc = await getDoc(entry); } catch (err) {
      if (seq === openSeq) conv().replaceChildren(el("div", { class: "loading", text: T.failed + (err.message || err) }));
      return;
    }
    if (seq !== openSeq) return;
    conv().replaceChildren(renderItems(doc.items));
    const s = scroller();
    if (opts.item != null) {
      const target = conv().querySelector(`[data-i="${opts.item}"]`) || nearestItem(opts.item);
      if (target) { openParents(target); target.scrollIntoView({ block: "center" }); target.classList.add("hl"); }
    } else if (keep != null) s.scrollTop = keep;
    else {
      const p = prefs.pos[id];
      s.scrollTop = p == null || p === -1 ? s.scrollHeight : p;
    }
  }

  function nearestItem(i) {
    let best = null;
    for (const n of conv().querySelectorAll("[data-i]")) { if (+n.dataset.i <= i) best = n; else break; }
    return best;
  }
  function openParents(node) {
    for (let p = node.parentElement; p && p !== conv(); p = p.parentElement) if (p.tagName === "DETAILS" && !p.open) { p.open = true; p.dispatchEvent(new Event("toggle")); }
  }

  const fmtDay = (ts) => new Date(ts).toLocaleDateString(zh ? "zh-CN" : undefined, { year: "numeric", month: "long", day: "numeric", weekday: "short" });
  const fmtTime = (ts) => new Date(ts).toLocaleTimeString(zh ? "zh-CN" : undefined, { hour: "2-digit", minute: "2-digit" });

  // A details element whose body is built only when first opened (keeps big sessions light).
  function lazyDetails(cls, summaryKids, build) {
    const body = el("div", { class: "body" });
    const d = el("details", { class: cls }, el("summary", null, el("span", { class: "chev", text: "▶" }), summaryKids), body);
    let built = false;
    d.addEventListener("toggle", () => { if (d.open && !built) { built = true; body.append(build()); } });
    return d;
  }

  function toolNode(it) {
    return lazyDetails(`tool${it.e ? " err" : ""}`, [el("span", { class: "tn", text: it.n }), el("span", { class: "tl", text: it.l || "" })], () => {
      const f = document.createDocumentFragment();
      if (it.i) f.append(el("pre", { class: "io in", text: it.i }));
      if (it.o) f.append(el("pre", { class: `io out${it.e ? " e" : ""}`, text: it.o }));
      return f;
    });
  }
  const thinkNode = (it) => lazyDetails("think", [el("span", { text: T.thinking })], () => el("div", { class: "md", html: it.h }));

  function stepsNode(list) {
    if (list.length === 1) { const it = list[0].it; const n = it.k === "t" ? toolNode(it) : thinkNode(it); n.dataset.i = list[0].i; return n; }
    const counts = new Map();
    for (const { it } of list) { const name = it.k === "t" ? it.n : T.thinking; counts.set(name, (counts.get(name) || 0) + 1); }
    const parts = [...counts].sort((a, b) => b[1] - a[1]).map(([n, c]) => (c > 1 ? `${n} ×${c}` : n)).join(" · ");
    const errs = list.some(({ it }) => it.e);
    const last = list[list.length - 1].it;
    const node = lazyDetails("steps", [el("span", { class: "summary-line" }, T.steps(list.length), el("span", { class: "faint", text: `  ${parts}` }), errs ? el("span", { class: "faint", text: " · ⚠" }) : null)], () => {
      const f = document.createDocumentFragment();
      for (const { it, i } of list) { const n = it.k === "t" ? toolNode(it) : thinkNode(it); n.dataset.i = i; f.append(n); }
      return f;
    });
    node.dataset.i = list[0].i;
    node.title = last.k === "t" ? `${last.n} ${last.l || ""}` : "";
    return node;
  }

  function addCopyButtons(root) {
    for (const pre of root.querySelectorAll("pre")) {
      const b = el("button", { type: "button", class: "copy", text: T.copy });
      b.addEventListener("click", () => {
        navigator.clipboard?.writeText(pre.querySelector("code")?.textContent ?? pre.textContent).then(() => { b.textContent = T.copied; setTimeout(() => (b.textContent = T.copy), 1200); }).catch(() => {});
      });
      pre.append(b);
    }
  }

  function renderItems(items) {
    const f = document.createDocumentFragment();
    let steps = null;
    let lastDay = "";
    const flush = () => { if (steps) { f.append(stepsNode(steps)); steps = null; } };
    items.forEach((it, i) => {
      if (it.k === "t" || it.k === "th") { (steps ||= []).push({ it, i }); return; }
      flush();
      if ((it.k === "u" || it.k === "cmd") && it.ts) {
        const day = fmtDay(it.ts);
        if (day !== lastDay) { f.append(el("div", { class: "date", text: day })); lastDay = day; }
      }
      const node = renderItem(it);
      if (node) { if (node.nodeType === 1) node.dataset.i = i; f.append(node); }
    });
    flush();
    return f;
  }

  function renderItem(it) {
    switch (it.k) {
      case "u": {
        const b = el("div", { class: "bubble" }, it.x || "");
        if (it.im?.length) b.append(el("div", { class: "imgs" }, it.im.map((src) => el("img", { src, alt: "", loading: "lazy", onclick: () => lightbox(src) }))));
        for (const p of it.p || []) {
          const d = lazyDetails("pasted", [el("span", { text: T.pasted(p.split("\n").length) })], () => el("pre", { class: "io", text: p }));
          b.append(d);
        }
        return el("div", { class: "u" }, b, el("div", { class: "meta", text: [it.q ? T.queued : "", it.ts ? fmtTime(it.ts) : ""].filter(Boolean).join(" · ") }));
      }
      case "cmd":
        return el("div", { class: "u" }, el("div", { class: "bubble cmd", text: it.x }), el("div", { class: "meta", text: it.ts ? fmtTime(it.ts) : "" }));
      case "a": {
        const n = el("div", { class: "a md", html: it.h });
        addCopyButtons(n);
        return n;
      }
      case "plan": {
        const mark = { completed: "✓", in_progress: "◐", pending: "○" };
        return el("div", { class: "card plan" }, el("h4", { text: T.tasks }), el("ul", null, it.s.map(([st, x]) => el("li", { class: st }, el("span", { class: "m", text: mark[st] || "○" }), el("span", { text: x })))));
      }
      case "wrap": {
        const c = el("div", { class: "card wrap" }, el("h4", { text: T.next }), el("p", { text: it.x }));
        if (it.q) c.append(el("p", { class: "ask", text: it.q }));
        if (it.b?.length) c.append(el("div", { class: "chips" }, it.b.map((x) => el("span", { text: x }))));
        return c;
      }
      case "ask": {
        const c = el("div", { class: "card ask-card" }, el("h4", { text: T.question }));
        for (const q of it.qs || []) { c.append(el("div", { class: "q", text: q.q })); if (q.o?.length) c.append(el("div", { class: "chips" }, q.o.map((x) => el("span", { text: x })))); }
        if (it.ans) c.append(el("div", { class: "ans", text: it.ans }));
        return c;
      }
      case "n": {
        const icon = { task: "⚙ ", peer: "↩ ", loop: "↻ ", event: "• ", info: "ℹ ", err: "⚠ ", out: "", intr: "" }[it.c] ?? "";
        const label = icon + (it.x || "") + (it.ts && it.c === "loop" ? `  ${fmtTime(it.ts)}` : "");
        if (it.d) return lazyDetails(`note-d note ${it.c || ""}`, [el("span", { text: label || T.output })], () => el("pre", { class: "io", text: it.d }));
        return el("div", { class: `note ${it.c || ""}`, text: label });
      }
      case "cmp": {
        const wrap = el("div");
        const sum = it.h ? el("div", { class: "compact-summary md", html: it.h, hidden: true }) : null;
        const btn = sum ? el("button", { type: "button", text: T.showSummary, onclick: () => { sum.hidden = !sum.hidden; btn.textContent = sum.hidden ? T.showSummary : T.hideSummary; } }) : null;
        wrap.append(el("div", { class: "divider" }, el("span", { text: T.compacted }), btn));
        if (sum) wrap.append(sum);
        return wrap;
      }
      case "ch":
        return el("div", { class: "chapter", text: it.x });
      default:
        return null;
    }
  }

  function lightbox(src) {
    const lb = el("div", { id: "lightbox", onclick: () => lb.remove() }, el("img", { src, alt: "" }));
    document.body.append(lb);
  }

  // ---------- full-text search ----------
  const strip = (h) => (h || "").replace(/<[^>]+>/g, " ").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, "&");
  function itemText(it) {
    switch (it.k) {
      case "u": return [it.x, ...(it.p || [])].join("\n");
      case "cmd": case "ch": return it.x || "";
      case "a": case "th": case "cmp": return strip(it.h);
      case "t": return [it.l, it.i, it.o].join("\n");
      case "n": return [it.x, it.d].join("\n");
      case "wrap": return [it.x, it.q].join("\n");
      case "plan": return it.s.map((x) => x[1]).join("\n");
      case "ask": return (it.qs || []).map((q) => q.q).join("\n") + "\n" + (it.ans || "");
      default: return "";
    }
  }

  let searchSeq = 0;
  async function searchAll(query) {
    const q = query.trim().toLowerCase();
    if (!q) return;
    const seq = ++searchSeq;
    savePos();
    current = null;
    markActive();
    closeDrawer();
    $("#title").textContent = query.trim();
    $("#subtitle").textContent = "";
    const box = el("div", { class: "results" });
    const head = el("h2", { text: T.scanning(0, INDEX.sessions.length) });
    box.append(head);
    conv().replaceChildren(box);
    scroller().scrollTop = 0;
    let hits = 0;
    const list = INDEX.sessions.slice().sort((a, b) => b.u - a.u);
    for (let k = 0; k < list.length; k++) {
      if (seq !== searchSeq) return;
      const s = list[k];
      let doc;
      try { doc = await getDoc(s); } catch { continue; }
      const found = [];
      if (s.t.toLowerCase().includes(q)) found.push({ i: null, snip: s.t });
      doc.items.forEach((it, i) => {
        if (found.length >= 4) return;
        const text = itemText(it);
        const at = text.toLowerCase().indexOf(q);
        if (at >= 0) found.push({ i, snip: text.slice(Math.max(0, at - 70), at + q.length + 110).replace(/\s+/g, " "), at: Math.min(at, 70) });
      });
      if (found.length) {
        hits += found.length;
        for (const f of found) {
          const snip = el("div", { class: "rs" });
          const lower = f.snip.toLowerCase();
          const p = lower.indexOf(q);
          if (p >= 0) snip.append(f.snip.slice(0, p), el("mark", { text: f.snip.slice(p, p + q.length) }), f.snip.slice(p + q.length));
          else snip.append(f.snip);
          box.append(el("button", { type: "button", class: "result", onclick: () => openSession(s.id, f.i == null ? {} : { item: f.i }) }, el("div", { class: "rt", text: s.t }), snip));
        }
      }
      if (k % 8 === 0) { head.textContent = T.scanning(k + 1, list.length); await new Promise((r) => setTimeout(r, 0)); }
    }
    head.textContent = hits ? T.results(hits, query.trim()) : T.noResults;
  }

  // ---------- layout helpers ----------
  const closeDrawer = () => $("#app").classList.remove("drawer");

  // Locks itself after 30 minutes in the background unless the key is remembered.
  let hiddenAt = 0, remembered = false;
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") { hiddenAt = Date.now(); savePos(); }
    else if (KEY && !remembered && hiddenAt && Date.now() - hiddenAt > 30 * 60 * 1000) location.reload();
  });
  window.addEventListener("pagehide", savePos);

  // ---------- boot ----------
  async function boot() {
    for (const n of document.querySelectorAll("[data-t]")) n.textContent = T[n.dataset.t];
    for (const n of document.querySelectorAll("[data-title]")) { n.title = T[n.dataset.title]; n.setAttribute("aria-label", T[n.dataset.title]); }
    $("#q").placeholder = T.search;
    $("#qall").textContent = T.searchAll;
    $("#pw").placeholder = zh ? "密码" : "Password";
    document.documentElement.lang = zh ? "zh-CN" : "en";
    applyTheme();
    registerSW();

    $("#theme").addEventListener("click", () => { const order = ["auto", "light", "dark"]; prefs.theme = order[(order.indexOf(prefs.theme || "auto") + 1) % 3]; savePrefs(); applyTheme(); });
    $("#fill").addEventListener("click", () => navigator.serviceWorker?.controller?.postMessage({ rp: "fill" }));
    $("#lock").addEventListener("click", lock);
    $("#menu").addEventListener("click", () => $("#app").classList.toggle("drawer"));
    $("#scrim").addEventListener("click", closeDrawer);
    $("#totop").addEventListener("click", () => scroller().scrollTo({ top: 0 }));
    $("#tobottom").addEventListener("click", () => scroller().scrollTo({ top: scroller().scrollHeight }));
    $("#q").addEventListener("input", (e) => { filter = e.target.value; $("#qall").hidden = !filter.trim(); renderSidebar(); });
    $("#q").addEventListener("keydown", (e) => { if (e.key === "Enter") searchAll(e.target.value); });
    $("#qall").addEventListener("click", () => searchAll($("#q").value));
    let t = 0;
    scroller().addEventListener("scroll", () => { clearTimeout(t); t = setTimeout(savePos, 400); }, { passive: true });

    $("#gate-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const btn = $("#unlock"), msg = $("#gate-msg");
      btn.disabled = true;
      msg.textContent = T.busy;
      try {
        META ||= await (await fetch("data/key.json", { credentials: "omit" })).json();
        const key = await deriveKey($("#pw").value, META);
        await unlock(key);
        if ($("#remember").checked) { try { await keyPut({ key, salt: META.salt }); remembered = true; } catch {} }
        else await keyDel();
      } catch (err) {
        msg.textContent = err && err.name === "OperationError" ? T.bad : navigator.onLine === false ? T.firstOffline : String((err && err.message) || err);
      } finally {
        btn.disabled = false;
      }
    });

    try { META = await (await fetch("data/key.json", { credentials: "omit" })).json(); } catch { return showGate(T.firstOffline); }
    const saved = await keyGet();
    if (saved && saved.key && saved.salt === META.salt) {
      try { await unlock(saved.key); remembered = true; return; } catch { await keyDel(); }
    }
    showGate();
  }

  if (!window.crypto?.subtle || typeof DecompressionStream === "undefined") {
    document.body.textContent = "This browser is too old to decrypt the archive (needs WebCrypto and DecompressionStream).";
  } else boot();
})();
