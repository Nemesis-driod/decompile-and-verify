# Findings to fixes

Order by effect, not by effort. Re-test every change with the same engagement sheet.

| Finding | Fix | Effect | Re-test |
|---|---|---|---|
| Secret-like strings (keys, tokens) in the build | Rotate now. Move the secret server-side, or issue short-lived tokens at runtime | Removes the exposure; stripping and obfuscation do not | `triage.py` reports none |
| Internal hostnames or endpoints | Put them behind authentication; do not ship internal names. Public endpoints stay visible | Limits what a recovered URL gives away | `triage.py` URL list |
| Symbols, debug info, readable names | Strip native builds; enable R8/ProGuard on Android and an obfuscator for .NET; keep mapping files private | Raises the cost of reading. Logic survives (see the toy example) | S component, then the R pass |
| Licence, pricing or scoring logic recovered in few attempts | Move the decision to a server, or split it so the client cannot decide alone. If it must stay client-side, add obfuscation or virtualisation to raise the cost per function and measure the difference | Only a measured change in cost to recover counts | R component and attempts per function |
| Build paths or usernames leak | Build in clean CI with path remapping (`-ffile-prefix-map`, `/pathmap`, Go `-trimpath`) | Removes the leak | `triage.py` build paths |
| Go binary stripped, names still present | Expect names to remain in `.gopclntab`; consider an obfuscator such as garble and re-measure | Raises cost modestly | S component |
| Packer or protector detected | Note that the static surface is inconclusive; run the recovery pass on the unpacked or in-memory image | Avoids a false sense of security | R pass on the unpacked image |
| Short, meaningless class names already present (JAR or APK) | Nothing to fix; record it as an existing control and still run the recovery pass | | R pass |

State plainly that none of these makes recovery impossible. The report's job is to show how much each change raised the cost.
