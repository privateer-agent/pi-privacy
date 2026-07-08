import { randomBytes, createHash, X509Certificate } from "node:crypto";
import { request as httpsRequest } from "node:https";
import type { TLSSocket } from "node:tls";
import { gunzipSync } from "node:zlib";

// Ported from privateer 0.2 (tree-cli/src/providers/attestation.ts). The pure
// attestation logic is verbatim; what changed for the public package:
//   - DROPPED the privateer-server-proxy path (fetchAttestationViaServer + the
//     auth/privateer import) — that's the private account channel, not public.
//   - config type + base-URL constants inlined (no config/schema / registry deps).
// The SEV-SNP report_data parse, SPKI match, posture mappings are untouched.

const TIMEOUT_MS = 12_000;

export const NEARAI_BASE_URL = "https://cloud-api.near.ai/v1";
export const TINFOIL_BASE_URL = "https://inference.tinfoil.sh/v1";

// Minimal provider config the attestation calls need (replaces ProviderConfig).
export interface AttestConfig {
  apiKey?: string;
  baseURL?: string;
}

export type TeePosture = "green" | "yellow" | "red";

// ── NEAR AI TEE attestation ──────────────────────────────────────────────────
// Every NEAR AI Cloud model runs inside a Trusted Execution Environment (Intel TDX
// confidential VM + NVIDIA confidential-computing GPU). On request, the gateway
// returns a cryptographic attestation report proving the model is running on
// genuine TEE hardware, with a signing key that never leaves the enclave bound to
// a caller-supplied nonce (report_data = signing_address || nonce).
//
// Pragmatic check suited to a TUI: fetch a fresh report bound to our nonce and
// confirm it carries a TEE signing key plus hardware evidence. We do NOT re-validate
// the raw NVIDIA/Intel quote chains here — that's the full verifier's job
// (github.com/nearai/cloud-verifier); expose `raw` so a user can take it there.

export interface Attestation {
  model: string;
  nonce: string; // the 32-byte hex nonce we sent (freshness / anti-replay)
  signingAddress?: string; // TEE-bound key that signs inference responses
  nonceEchoed: boolean; // our nonce appears in the report → it's fresh, not replayed
  hardware: string[]; // detected evidence, e.g. ["NVIDIA", "Intel TDX"]
  raw: unknown; // full report, for display + external verification
}

function baseFor(cfg: AttestConfig): string {
  return (cfg.baseURL ?? NEARAI_BASE_URL).replace(/\/+$/, "");
}

// A 32-byte (64 hex char) random nonce, per NEAR's attestation API guidance.
export function randomNonce(): string {
  return randomBytes(32).toString("hex");
}

// Recursively find the first string value under any of `keys` (case-insensitive).
function deepFindString(obj: unknown, keys: string[]): string | undefined {
  const want = new Set(keys.map((k) => k.toLowerCase()));
  const stack: unknown[] = [obj];
  while (stack.length) {
    const cur = stack.pop();
    if (Array.isArray(cur)) {
      stack.push(...cur);
    } else if (cur && typeof cur === "object") {
      for (const [k, v] of Object.entries(cur)) {
        if (typeof v === "string" && want.has(k.toLowerCase()) && v.trim()) return v.trim();
        if (v && typeof v === "object") stack.push(v);
      }
    }
  }
  return undefined;
}

// Fetch and interpret the attestation report for a model. Throws a readable error
// on missing key / network / HTTP failure so a caller can show "unverified".
export async function fetchAttestation(cfg: AttestConfig, modelId: string): Promise<Attestation> {
  if (!cfg.apiKey) throw new Error("no API key");
  const nonce = randomNonce();
  const url =
    `${baseFor(cfg)}/attestation/report` +
    `?model=${encodeURIComponent(modelId)}&signing_algo=ecdsa&nonce=${nonce}`;

  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), TIMEOUT_MS);
  let raw: unknown;
  try {
    const res = await fetch(url, {
      headers: { authorization: `Bearer ${cfg.apiKey}` },
      signal: ac.signal,
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      const hint = body.slice(0, 200).trim();
      throw new Error(`HTTP ${res.status} ${res.statusText}${hint ? ` — ${hint}` : ""}`);
    }
    raw = await res.json();
  } catch (err) {
    if (err instanceof Error && err.name === "AbortError") {
      throw new Error(`timed out after ${TIMEOUT_MS / 1000}s`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }

  return interpretReport(modelId, nonce, raw);
}

// Turn a raw NEAR attestation report into our Attestation posture. Pure.
export function interpretReport(modelId: string, nonce: string, raw: unknown): Attestation {
  const signingAddress = deepFindString(raw, ["signing_address", "signingAddress", "address"]);
  // Hardware evidence is detected by scanning the serialized report for the quote
  // markers each vendor uses — robust to the exact response shape.
  const blob = JSON.stringify(raw).toLowerCase();
  const hardware: string[] = [];
  if (/nvidia|gpu/.test(blob)) hardware.push("NVIDIA");
  if (/intel|tdx/.test(blob)) hardware.push("Intel TDX");
  // Freshness/anti-replay: our nonce must appear in the report. Require a non-trivial
  // nonce — a real attestation nonce is 32 bytes (64 hex, see randomNonce). Guard
  // against an empty/short nonce, since blob.includes("") is vacuously true and would
  // score a missing nonce as "echoed" (matters when the nonce is externally supplied,
  // e.g. a server-proxied report rather than one bound to our own randomNonce).
  const nonceEchoed = nonce.length >= 16 && blob.includes(nonce.toLowerCase());

  return { model: modelId, nonce, signingAddress, nonceEchoed, hardware, raw };
}

// Map an attestation to a status color. GREEN: fresh report bound to our nonce with
// a TEE signing key and hardware evidence. YELLOW: a report came back but it's
// missing the signing key, hardware evidence, or nonce echo. RED: no material.
export function teePosture(att: Attestation): TeePosture {
  if (!att.signingAddress && att.hardware.length === 0) return "red";
  if (att.signingAddress && att.hardware.length > 0 && att.nonceEchoed) return "green";
  return "yellow";
}

// ── Tinfoil TEE attestation ──────────────────────────────────────────────────
// Tinfoil enclaves publish an attestation document at /.well-known/tinfoil-attestation:
// { format: <predicate URL>, body: <base64 (gzipped) hardware report> }. The
// document attests the *host* — the gateway itself runs in the enclave. For the
// SEV-SNP predicate, report_data[0:32] is the SHA-256 of the enclave's TLS public
// key (SPKI DER): TLS terminates inside the enclave, so matching that hash against
// the key on the connection that served the document proves the channel ends in
// attested hardware. Pragmatic check — we do NOT re-validate the AMD signature
// chain or Sigstore measurements (that's github.com/tinfoilsh/tinfoil-cli's job).

export interface TinfoilAttestation {
  host: string; // host the document came from (attestation is per-host, not per-model)
  format: string; // predicate URL declaring the report type
  hardware: string[]; // TEE platform(s) the predicate names, e.g. ["AMD SEV-SNP"]
  attestedTlsKeyFp?: string; // report_data[0:32]: hash of the enclave's TLS key
  liveTlsKeyFp?: string; // hash of the TLS key that actually served the document
  tlsKeyMatched: boolean; // live key is the attested key → channel ends in the enclave
  raw: unknown; // full document, for display + external verification
}

// What the transport hands back: the parsed well-known document plus the SPKI
// SHA-256 of the leaf cert on the connection that served it. Injectable so tests
// can exercise interpretation without a TLS handshake, and so the connection can be
// the real inference socket (see dispatcherTransport in ./dispatcher.ts).
export type TinfoilTransport = (host: string) => Promise<{ doc: unknown; liveTlsKeyFp?: string }>;

// Node's fetch never exposes the peer certificate, so the default transport drops
// to https.request and reads the leaf cert off the socket that delivered the body —
// the binding is only meaningful against that exact connection.
export const httpsTransport: TinfoilTransport = (host) =>
  new Promise((resolve, reject) => {
    const url = new URL(`https://${host}/.well-known/tinfoil-attestation`);
    const req = httpsRequest(
      {
        hostname: url.hostname,
        port: url.port ? Number(url.port) : 443,
        path: url.pathname,
        method: "GET",
        timeout: TIMEOUT_MS,
        // Force a fresh connection + full TLS handshake every time. A pooled/
        // resumed TLS session skips re-sending the server cert, so
        // getPeerCertificate() returns {} on the abbreviated handshake and the
        // key binding silently fails (posture flips green→yellow on re-verify).
        // Attestation must observe a real handshake anyway, so no session reuse.
        agent: false,
      },
      (res) => {
        let liveTlsKeyFp: string | undefined;
        try {
          // getPeerCertificate(true) → include the full chain / raw DER even when
          // the default view would omit it.
          const peer = (res.socket as TLSSocket).getPeerCertificate(true);
          if (peer?.raw) {
            const spki = new X509Certificate(peer.raw).publicKey.export({ type: "spki", format: "der" });
            liveTlsKeyFp = createHash("sha256").update(spki).digest("hex");
          }
        } catch {
          // cert unavailable → binding stays unconfirmed (yellow), not an error
        }
        let body = "";
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => {
          if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
            const hint = body.slice(0, 200).trim();
            reject(new Error(`HTTP ${res.statusCode} ${res.statusMessage ?? ""}${hint ? ` — ${hint}` : ""}`));
            return;
          }
          try {
            resolve({ doc: JSON.parse(body), liveTlsKeyFp });
          } catch {
            reject(new Error("attestation endpoint returned non-JSON"));
          }
        });
        res.on("error", reject);
      },
    );
    req.on("timeout", () => req.destroy(new Error(`timed out after ${TIMEOUT_MS / 1000}s`)));
    req.on("error", reject);
    req.end();
  });

// Fetch and interpret the attestation document for the configured Tinfoil endpoint.
// Needs no API key — the well-known endpoint is public.
export async function fetchTinfoilAttestation(
  cfg: AttestConfig,
  transport: TinfoilTransport = httpsTransport,
): Promise<TinfoilAttestation> {
  const host = new URL(cfg.baseURL ?? TINFOIL_BASE_URL).host;
  const { doc, liveTlsKeyFp } = await transport(host);
  return interpretTinfoilDoc(host, doc, liveTlsKeyFp);
}

// Turn a raw attestation document into our posture inputs. Pure and lenient: a
// malformed document degrades to "no material" (red) rather than throwing.
export function interpretTinfoilDoc(
  host: string,
  doc: unknown,
  liveTlsKeyFp?: string,
): TinfoilAttestation {
  const d = (doc ?? {}) as { format?: unknown; body?: unknown };
  const format = typeof d.format === "string" ? d.format : "";
  // Hardware evidence comes from the predicate URL itself (e.g.
  // ".../predicate/sev-snp-guest/v2", ".../snp-tdx-multiplatform/v1").
  const fmt = format.toLowerCase();
  const hardware: string[] = [];
  if (/sev|snp/.test(fmt)) hardware.push("AMD SEV-SNP");
  if (/tdx/.test(fmt)) hardware.push("Intel TDX");
  if (/nitro/.test(fmt)) hardware.push("AWS Nitro");

  // Decode the report: base64, gunzipped when the gzip magic leads.
  let report: Buffer | undefined;
  if (typeof d.body === "string" && d.body) {
    try {
      let bytes = Buffer.from(d.body, "base64");
      if (bytes[0] === 0x1f && bytes[1] === 0x8b) bytes = gunzipSync(bytes);
      report = bytes;
    } catch {
      // undecodable body → treated as absent
    }
  }

  // The SEV-SNP report layout puts report_data (64 bytes) at 0x50; Tinfoil packs
  // the TLS-key hash into its first half. Only that predicate's layout is known, so
  // other formats fall back to scanning the report for the live key's bytes.
  const attestedTlsKeyFp =
    /sev-snp-guest/.test(fmt) && report && report.length >= 0x90
      ? report.subarray(0x50, 0x70).toString("hex")
      : undefined;
  const tlsKeyMatched =
    !!liveTlsKeyFp &&
    !!report &&
    (attestedTlsKeyFp === liveTlsKeyFp || report.includes(Buffer.from(liveTlsKeyFp, "hex")));

  return { host, format, hardware, attestedTlsKeyFp, liveTlsKeyFp, tlsKeyMatched, raw: doc };
}

// Posture mapping for Tinfoil, mirroring teePosture. GREEN: a TEE predicate plus the
// live TLS key found inside the attested report (channel demonstrably ends in the
// enclave). YELLOW: a report came back but the binding couldn't be confirmed here.
// RED: no attestation material at all.
export function tinfoilTeePosture(att: TinfoilAttestation): TeePosture {
  if (att.hardware.length === 0 && !att.attestedTlsKeyFp) return "red";
  if (att.hardware.length > 0 && att.tlsKeyMatched) return "green";
  return "yellow";
}
