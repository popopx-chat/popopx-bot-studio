#!/usr/bin/env node
/*
 * 窄屏 / RTL 浏览器实测：320px 下逐语种切换控制台与官网，检查横向溢出、
 * 根节点 dir/lang、语言持久化，以及技术字段与代码块的 LTR 隔离。
 *
 * 独立、可跳过：找不到 Chrome 或 Python venv 时打印 SKIP 并以 0 退出。
 * 用法：node studio/tests/narrow_layout_check.mjs
 */
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";

const HERE = import.meta.dirname;
const STUDIO = path.resolve(HERE, "..");
const ROOT = path.resolve(STUDIO, "..");
const PYTHON = process.env.PYTHON || path.join(ROOT, ".venv", "bin", "python");
const CHROME = process.env.CHROME
  || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const TOKEN = "narrow-layout-token-0123456789";
const WIDTH = 320;
const HEIGHT = 900;

const failures = [];
let checks = 0;
function expect(label, ok, detail = "") {
  checks += 1;
  if (!ok) failures.push(`${label}${detail ? `: ${detail}` : ""}`);
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(fn, timeoutMs, what) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const value = await fn();
      if (value) return value;
    } catch { /* keep polling */ }
    if (Date.now() > deadline) throw new Error(`超时等待 ${what}`);
    await sleep(100);
  }
}

class CDP {
  constructor(url) {
    this.seq = 0;
    this.pending = new Map();
    this.ws = new WebSocket(url);
    this.ready = new Promise((resolve, reject) => {
      this.ws.addEventListener("open", resolve);
      this.ws.addEventListener("error", reject);
    });
    this.ws.addEventListener("message", (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      if (!msg.id) return;
      const slot = this.pending.get(msg.id);
      if (!slot) return;
      this.pending.delete(msg.id);
      if (msg.error) slot.reject(new Error(`${slot.method}: ${msg.error.message}`));
      else slot.resolve(msg.result);
    });
  }
  send(method, params = {}) {
    const id = ++this.seq;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject, method });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }
  close() { try { this.ws.close(); } catch { /* already gone */ } }
}

async function evaluate(cdp, expression) {
  const out = await cdp.send("Runtime.evaluate", {
    expression, awaitPromise: true, returnByValue: true,
  });
  if (out.exceptionDetails) {
    throw new Error(out.exceptionDetails.text || "Runtime.evaluate 抛异常");
  }
  return out.result.value;
}

async function main() {
  if (!existsSync(CHROME) || !existsSync(PYTHON)) {
    console.log(`SKIP 窄屏实测：${existsSync(CHROME) ? "Python venv" : "Chrome"} 不存在`);
    return;
  }

  const dataDir = await mkdtemp(path.join(os.tmpdir(), "narrow-layout-data-"));
  const chromeDir = await mkdtemp(path.join(os.tmpdir(), "narrow-layout-chrome-"));
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  let server = null;
  let chrome = null;
  let cdp = null;

  try {
    server = spawn(PYTHON, ["-m", "app.main", "--host", "127.0.0.1", "--port", String(port),
      "--data-dir", dataDir, "--token", TOKEN], { cwd: STUDIO, stdio: "ignore" });
    let serverExit = null;
    server.on("exit", (code) => { serverExit = code; });
    await waitFor(async () => {
      if (serverExit !== null) throw new Error(`服务进程退出（code=${serverExit}）`);
      return (await fetch(`${base}/healthz`)).ok;
    }, 30000, "控制台服务");

    // 建一个 Bot，让表格和卡片在窄屏下有真实内容。
    const made = await fetch(`${base}/api/admin/bots`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${TOKEN}` },
      body: JSON.stringify({ name: "narrow", start: false }),
    });
    expect("预置 Bot 创建成功", made.ok, String(made.status));

    chrome = spawn(CHROME, [
      "--headless=new", "--no-first-run", "--no-default-browser-check",
      "--disable-gpu", "--hide-scrollbars", "--remote-debugging-port=0",
      `--user-data-dir=${chromeDir}`, "about:blank",
    ], { stdio: "ignore" });
    const devtools = await waitFor(async () => {
      const file = path.join(chromeDir, "DevToolsActivePort");
      if (!existsSync(file)) return null;
      const [debugPort] = (await readFile(file, "utf8")).split("\n");
      return debugPort ? Number(debugPort) : null;
    }, 20000, "Chrome DevTools 端口");
    const target = await (await fetch(`http://127.0.0.1:${devtools}/json/new?about:blank`, {
      method: "PUT",
    })).json();
    cdp = new CDP(target.webSocketDebuggerUrl);
    await cdp.ready;
    await cdp.send("Page.enable");
    await cdp.send("Runtime.enable");
    await cdp.send("Emulation.setDeviceMetricsOverride", {
      width: WIDTH, height: HEIGHT, deviceScaleFactor: 1, mobile: false,
    });
    await cdp.send("Page.addScriptToEvaluateOnNewDocument", {
      source: `try { localStorage.setItem("popopx.adminToken", ${JSON.stringify(TOKEN)}); } catch (e) {}`,
    });

    let locales = null;

    const pages = [
      { name: "控制台", url: `${base}/`, probe: `(() => {
          const root = document.documentElement;
          const bad = [];
          for (const el of document.querySelectorAll("pre, input.mono, textarea.mono, .kv dd, .node")) {
            const cs = getComputedStyle(el);
            if (cs.direction !== "ltr" || cs.unicodeBidi !== "isolate") {
              bad.push((el.id || el.className || el.tagName).toString().slice(0, 40));
            }
          }
          return {
            dir: root.getAttribute("dir"), lang: root.lang,
            scrollWidth: Math.max(root.scrollWidth, document.body.scrollWidth),
            innerWidth: window.innerWidth,
            stored: localStorage.getItem("popopx.locale"),
            bidiViolations: bad,
            offenders: [...document.querySelectorAll("body *")].filter((el) => {
              const r = el.getBoundingClientRect();
              return r.width > 0 && (r.right > window.innerWidth + 1 || r.left < -1);
            }).slice(0, 6).map((el) => (el.id || el.tagName.toLowerCase() + "." + String(el.className)).slice(0, 60)),
          };
        })()` },
      { name: "官网", url: `${base}/site`, probe: `(() => {
          const root = document.documentElement;
          const bad = [];
          for (const el of document.querySelectorAll("pre, .spec .v, .ftag span, .step-id, .api .p")) {
            const cs = getComputedStyle(el);
            if (cs.direction !== "ltr" || cs.unicodeBidi !== "isolate") {
              bad.push((el.id || el.className || el.tagName).toString().slice(0, 40));
            }
          }
          return {
            dir: root.getAttribute("dir"), lang: root.lang,
            scrollWidth: Math.max(root.scrollWidth, document.body.scrollWidth),
            innerWidth: window.innerWidth,
            stored: localStorage.getItem("popopx.locale"),
            bidiViolations: bad,
            offenders: [...document.querySelectorAll("body *")].filter((el) => {
              const r = el.getBoundingClientRect();
              return r.width > 0 && (r.right > window.innerWidth + 1 || r.left < -1);
            }).slice(0, 6).map((el) => (el.id || el.tagName.toLowerCase() + "." + String(el.className)).slice(0, 60)),
          };
        })()` },
    ];

    for (const page of pages) {
      await cdp.send("Page.navigate", { url: page.url });
      await waitFor(() => evaluate(cdp, "!!(window.I18N && window.I18N.catalog().locales.length)"),
        20000, `${page.name} i18n 引擎`);
      if (!locales) {
        locales = await evaluate(cdp, "I18N.catalog().locales");
        expect("页面内嵌 21 个语种", locales.length === 21, String(locales.length));
      }
      for (const locale of locales) {
        await evaluate(cdp, `I18N.set(${JSON.stringify(locale)})`);
        await sleep(60);
        const got = await evaluate(cdp, page.probe);
        const rtl = locale === "ar";
        expect(`${page.name} ${locale} 根节点 dir`, got.dir === (rtl ? "rtl" : "ltr"), String(got.dir));
        expect(`${page.name} ${locale} 根节点 lang`, got.lang === locale, String(got.lang));
        expect(`${page.name} ${locale} 写入本地存储`, got.stored === locale, String(got.stored));
        expect(`${page.name} ${locale} 320px 无横向溢出`,
          got.scrollWidth <= got.innerWidth + 1,
          `${got.scrollWidth} > ${got.innerWidth} [${got.offenders.join(" | ")}]`);
        expect(`${page.name} ${locale} 技术字段 LTR 隔离`,
          got.bidiViolations.length === 0, got.bidiViolations.join(","));
      }

      // 刷新后仍记住阿拉伯语，且 boot 阶段就恢复 RTL。
      await evaluate(cdp, `I18N.set("ar")`);
      await cdp.send("Page.reload");
      await waitFor(() => evaluate(cdp, "!!(window.I18N && window.I18N.catalog().locales.length)"),
        20000, `${page.name} 刷新后 i18n 引擎`);
      await sleep(150);
      const restored = await evaluate(cdp, page.probe);
      expect(`${page.name} 刷新后仍是 ar`, restored.lang === "ar" && restored.stored === "ar",
        `${restored.lang}/${restored.stored}`);
      expect(`${page.name} 刷新后仍是 RTL`, restored.dir === "rtl", String(restored.dir));

      if (process.env.SHOTS_DIR) {
        await mkdir(process.env.SHOTS_DIR, { recursive: true });
        for (const shot of [{ width: 320, height: 900, tag: "320" },
          { width: 1440, height: 900, tag: "1440" }]) {
          await cdp.send("Emulation.setDeviceMetricsOverride", {
            width: shot.width, height: shot.height, deviceScaleFactor: 1, mobile: false,
          });
          for (const locale of ["en", "ar"]) {
            await evaluate(cdp, `I18N.set(${JSON.stringify(locale)})`);
            await sleep(120);
            const png = await cdp.send("Page.captureScreenshot", { format: "png" });
            const name = `${page.name}-${shot.tag}-${locale}.png`;
            await writeFile(path.join(process.env.SHOTS_DIR, name), Buffer.from(png.data, "base64"));
            const headClip = shot.tag === "320"
              ? { x: 0, y: 0, width: 320, height: 240, scale: 2 }
              : { x: 0, y: 0, width: 460, height: 90, scale: 2 };
            const head = await cdp.send("Page.captureScreenshot", { format: "png", clip: headClip });
            await writeFile(path.join(process.env.SHOTS_DIR, `${page.name}-${shot.tag}-${locale}-head.png`),
              Buffer.from(head.data, "base64"));
          }
        }
        await cdp.send("Emulation.setDeviceMetricsOverride", {
          width: WIDTH, height: HEIGHT, deviceScaleFactor: 1, mobile: false,
        });
      }
    }

    if (failures.length) {
      console.error(`窄屏/RTL 实测失败 ${failures.length}/${checks} 条：`);
      for (const line of failures) console.error(`  - ${line}`);
      process.exitCode = 1;
    } else {
      console.log(`窄屏/RTL 实测通过：${checks} 条断言（${locales.length} 语种 × 2 页）`);
    }
  } finally {
    cdp?.close();
    chrome?.kill("SIGKILL");
    server?.kill("SIGTERM");
    await sleep(200);
    await rm(dataDir, { recursive: true, force: true });
    await rm(chromeDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(`窄屏/RTL 实测出错：${err.message}`);
  process.exitCode = 1;
});