// Pi package extension entry. Pi discovers extensions from this `extensions/`
// directory (or the `pi.extensions` manifest paths) and loads each file's default
// export as the extension factory `(pi) => void`.
//
// The default export is makePiPrivacyExtension() configured from the environment +
// an optional pi-privacy.config.json — so a plain `pi install npm:pi-privacy` can
// set every non-function option (piiPolicy, toolExfilPolicy, downgradePolicy,
// enforceOpenRouterZdr, badge sinks, …) WITHOUT writing any TypeScript. See
// src/config.ts for the variable names and precedence (env overrides file).
//
// Consumers who need the code-only options (onPosture, resolveTier, renderBadge), or
// who want to ignore ambient config entirely, import { makePiPrivacyExtension } from
// the package root and pass options directly.
import { makePiPrivacyExtension } from "../src/extension.ts";
import { loadConfig } from "../src/config.ts";

export default makePiPrivacyExtension(loadConfig());
