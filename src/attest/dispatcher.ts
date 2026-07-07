// The out-of-band attestation interposer — the moat, as a reusable module.
//
// Pi's extension hooks can't reach the TLS peer certificate (pi-ai strips the
// provider response to { status, headers }), so a process-wide undici global
// dispatcher captures the enclave's TLS SPKI hash on the `connect` hook — exactly
// what a Tinfoil attestation report pins. Spike-proven to work even when installed
// at extension-init (Pi resolves the global dispatcher at call time), so a Pi
// extension can install this without a pre-import boot shim.

import crypto from "node:crypto";
import { Agent, buildConnector, setGlobalDispatcher } from "undici";

export interface CapturedCert {
  subject: string;
  issuer: string;
  // SHA-256 of the peer cert's SubjectPublicKeyInfo (SPKI DER) — the value a
  // Tinfoil attestation report pins (the enclave TLS key fingerprint).
  spkiSha256: string;
  fingerprint256?: string;
  error?: string;
}

// host -> captured cert. Keyed per-host because undici pools keep-alive sockets:
// the connect hook fires ONLY on a NEW connection, so a reused socket skips it.
// Do NOT pre-pool a connection to an attested host before the first read.
const captured = new Map<string, CapturedCert>();
let installed = false;

// Install the global dispatcher (idempotent). Call from an extension factory or a
// pre-Pi boot module — both work (see spike-ext-dispatcher).
export function installAttestationDispatcher(): void {
  if (installed) return;
  installed = true;

  const baseConnect = buildConnector({});
  const attestingConnector: typeof baseConnect = (opts, cb) =>
    baseConnect(opts, (err, socket) => {
      const host = opts.hostname;
      if (
        !err &&
        socket &&
        host &&
        !captured.has(host) &&
        typeof (socket as any).getPeerCertificate === "function"
      ) {
        try {
          const cert = (socket as any).getPeerCertificate(true);
          if (cert && cert.raw) {
            const spkiDer = new crypto.X509Certificate(cert.raw).publicKey.export({
              type: "spki",
              format: "der",
            });
            captured.set(host, {
              subject: cert.subject?.CN ?? JSON.stringify(cert.subject),
              issuer: cert.issuer?.O ?? cert.issuer?.CN ?? JSON.stringify(cert.issuer),
              spkiSha256: crypto.createHash("sha256").update(spkiDer).digest("hex"),
              fingerprint256: cert.fingerprint256,
            });
          }
        } catch (e) {
          captured.set(host, { error: String(e) } as CapturedCert);
        }
      }
      cb(err, socket as any);
    });

  setGlobalDispatcher(new Agent({ connect: attestingConnector, connectTimeout: 8000 }));
}

export function getCapturedCert(host: string): CapturedCert | undefined {
  return captured.get(host);
}

export function capturedHosts(): ReadonlyMap<string, CapturedCert> {
  return captured;
}

// A TinfoilTransport that binds attestation to the SPKI captured on the real
// provider connection (rather than a separate https.request). Fetches the
// well-known document via global fetch — which flows through the dispatcher, so the
// connect hook records the enclave's SPKI — then reads it back per host. Stronger
// than httpsTransport: it proves the CONNECTION Pi actually uses ends in the enclave.
import type { TinfoilTransport } from "./attestation.ts";

export const dispatcherTransport: TinfoilTransport = async (host) => {
  const res = await fetch(`https://${host}/.well-known/tinfoil-attestation`);
  if (!res.ok) {
    const hint = (await res.text().catch(() => "")).slice(0, 200).trim();
    throw new Error(`HTTP ${res.status} ${res.statusText}${hint ? ` — ${hint}` : ""}`);
  }
  const doc = await res.json();
  const cert = getCapturedCert(host);
  return { doc, liveTlsKeyFp: cert && !cert.error ? cert.spkiSha256 : undefined };
};
