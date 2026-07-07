// Pi package extension entry. Pi discovers extensions from this `extensions/`
// directory (or the `pi.extensions` manifest paths) and loads each file's default
// export as the extension factory `(pi) => void`.
//
// The default export is makePiPrivacyExtension() with default options: install the
// attestation dispatcher, register the config-only privacy providers, verify TEE
// posture, and add /verify. Consumers who want to configure it (e.g. enforce
// OpenRouter ZDR, or hook onPosture) import { makePiPrivacyExtension } from the
// package root instead.
export { default } from "../src/extension.ts";
