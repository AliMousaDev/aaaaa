import express from "express";
import { Impit } from "impit";
import * as pako from "pako";

const app = express();
const impit = new Impit({ browser: "chrome", ignoreTlsErrors: true });

const BASE_URL = "https://www.miruro.to";
const PIPE_URL = "https://www.miruro.to/api/secure/pipe";
const MIRURO_PIPE_OBF_KEY = "71951034f8fbcf53d89db52ceb3dc22c";
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

let CF_CLEARANCE = process.env.MIRURO_CF_CLEARANCE || "";

const OBF_KEY_BYTES = [];
for (let i = 0; i < MIRURO_PIPE_OBF_KEY.length; i += 2) {
    OBF_KEY_BYTES.push(parseInt(MIRURO_PIPE_OBF_KEY.substr(i, 2), 16));
}

app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    if (req.method === "OPTIONS") return res.sendStatus(204);
    next();
});
app.use(express.json());
app.disable("etag");

// ==========================================
// 🛠️ DECRYPTION HELPERS
// ==========================================

function base64UrlEncode(obj) {
    const jsonStr = JSON.stringify(obj);
    const utf8Str = unescape(encodeURIComponent(jsonStr));
    const b64 = Buffer.from(utf8Str, "binary").toString("base64");
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function pureAtobBuffer(b64) {
    // نفس فكرة pureAtob الأصلية لكن بترجع Buffer مباشرة
    return Buffer.from(b64, "base64");
}

function decodeMiruroPayload(b64Text) {
    if (
        b64Text.trim().startsWith("<") ||
        b64Text.toLowerCase().includes("cloudflare") ||
        b64Text.toLowerCase().includes("just a moment") ||
        b64Text.toLowerCase().includes("upstream unreachable")
    ) {
        return { _blocked_by_cloudflare: true, _raw_html: b64Text.substring(0, 200) };
    }

    if (b64Text.length < 200 && b64Text.includes("error")) {
        return null;
    }

    // نفس الترتيب بالظبط: استبدال url-safe chars الأول، بعدين padding
    let b64 = b64Text.replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64.length % 4;
    if (pad) b64 += "=".repeat(4 - pad);

    let bytes;
    try {
        bytes = pureAtobBuffer(b64);
    } catch {
        return null;
    }

    // XOR مرة واحدة (زي الأصلي بالظبط)
    const xored = Buffer.alloc(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
        xored[i] = bytes[i] ^ OBF_KEY_BYTES[i % OBF_KEY_BYTES.length];
    }

    let jsonStr = "";
    let isDecompressed = false;

    try {
        const decompressed = pako.ungzip(xored); // من غير to:'string'
        jsonStr = Buffer.from(decompressed).toString("utf-8");
        isDecompressed = true;
    } catch {
        try {
            const decompressed = pako.inflate(xored);
            jsonStr = Buffer.from(decompressed).toString("utf-8");
            isDecompressed = true;
        } catch { /* fallthrough */ }
    }

    if (!isDecompressed) {
        const xored2 = Buffer.alloc(xored.length);
        for (let i = 0; i < xored.length; i++) {
            xored2[i] = xored[i] ^ OBF_KEY_BYTES[i % OBF_KEY_BYTES.length];
        }
        try {
            const decompressed = pako.ungzip(xored2);
            jsonStr = Buffer.from(decompressed).toString("utf-8");
            isDecompressed = true;
        } catch {
            try {
                const decompressed = pako.inflate(xored2);
                jsonStr = Buffer.from(decompressed).toString("utf-8");
                isDecompressed = true;
            } catch { /* fallthrough */ }
        }
    }

    if (!isDecompressed) {
        jsonStr = xored.toString("latin1");
    }

    try {
        return JSON.parse(jsonStr);
    } catch {
        console.error("[Miruro:Decode] ❌ Final text not valid JSON. First 100 chars:", jsonStr.substring(0, 100));
        return null;
    }
}
// ==========================================
// 🌐 RAW PROXY (زي القديم - لسه شغال لأي حاجة تانية)
// ==========================================

app.get("/", async (req, res) => {
    const targetUrl = req.query.url;
    if (!targetUrl) return res.status(400).json({ error: "Missing 'url' query param" });

    let target;
    try {
        target = new URL(targetUrl);
    } catch {
        return res.status(400).json({ error: "Invalid 'url' param" });
    }

    try {
        const response = await impit.fetch(target.toString(), {
            method: "GET",
            headers: {
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.6",
                "Origin": BASE_URL,
                "Referer": req.query.referer || `${BASE_URL}/`,
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "Sec-GPC": "1",
                "Priority": "u=1, i",
                ...(CF_CLEARANCE ? { "Cookie": `cf_clearance=${CF_CLEARANCE}` } : {}),
            },
            redirect: "follow",
        });
        const body = await response.arrayBuffer();
        res.status(response.status);
        response.headers.forEach((value, key) => {
            if (key.toLowerCase() !== "content-encoding") res.setHeader(key, value);
        });
        res.send(Buffer.from(body));
    } catch (e) {
        res.status(502).json({ error: "Fetch failed", detail: String(e) });
    }
});

// ==========================================
// 🔓 MIRURO PIPE ENDPOINT - بيرجع JSON جاهز
// ==========================================
// GET /miruro/pipe?path=search&query={"q":"naruto"}&referer=...

app.get("/miruro/pipe", async (req, res) => {
    const { path, query, referer } = req.query;
    if (!path) return res.status(400).json({ error: "Missing 'path' param" });

    let parsedQuery = {};
    try {
        parsedQuery = query ? JSON.parse(query) : {};
    } catch {
        return res.status(400).json({ error: "Invalid 'query' JSON" });
    }

    const payload = { path, method: "GET", query: parsedQuery, body: null, version: "0.2.0" };
    const encodedPayload = base64UrlEncode(payload);
    const fullUrl = `${PIPE_URL}?e=${encodedPayload}`;

    console.log(`[Miruro:Pipe] 🚀 '${path}' -> ${fullUrl}`);

    try {
        const response = await impit.fetch(fullUrl, {
            method: "GET",
            headers: {
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.6",
                "Origin": BASE_URL,
                "Referer": referer || `${BASE_URL}/`,
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "Sec-GPC": "1",
                "Priority": "u=1, i",
                ...(CF_CLEARANCE ? { "Cookie": `cf_clearance=${CF_CLEARANCE}` } : {}),
            },
            redirect: "follow",
        });

        const b64Text = await response.text();
        console.log(`[Miruro:Pipe] HTTP ${response.status} | size ${b64Text.length}`);

        if (!b64Text) {
            return res.status(502).json({ error: "Empty response from Miruro" });
        }

        const decoded = decodeMiruroPayload(b64Text);

        if (decoded === null) {
            return res.status(502).json({ error: "Failed to decode Miruro payload" });
        }

        return res.status(200).json(decoded);
    } catch (e) {
        console.error(`[Miruro:Pipe] ❌ ${e.message}`);
        return res.status(502).json({ error: "Fetch/decode failed", detail: String(e) });
    }
});

// ==========================================
// 🔑 SET / REFRESH cf_clearance
// ==========================================

app.get("/miruro/set", (req, res) => {
    const { cf } = req.query;
    if (!cf) return res.status(400).json({ error: "Missing 'cf' param" });
    CF_CLEARANCE = cf;
    res.json({ ok: true, message: "cf_clearance updated" });
});

app.get("/miruro/test", async (req, res) => {
    try {
        const response = await impit.fetch(`${BASE_URL}/`, {
            method: "GET",
            headers: {
                ...(CF_CLEARANCE ? { "Cookie": `cf_clearance=${CF_CLEARANCE}` } : {}),
            },
        });
        const text = await response.text();
        const blocked = text.toLowerCase().includes("just a moment") || text.toLowerCase().includes("cloudflare");
        res.json({ status: response.status, blocked, cf_set: !!CF_CLEARANCE });
    } catch (e) {
        res.status(502).json({ error: String(e) });
    }
});

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
    console.log(`Listening on ${PORT}`);
});