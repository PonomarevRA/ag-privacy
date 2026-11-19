# Verified library and installer contract

Core is a .NET10 library; NativeAOT exports a versioned C ABI in `include/ag_privacy.h`, usable from C/C++, Python and other FFI hosts. Node uses a separate native CLI process. The old stateless ABI remains compatible for trusted hosts; it does not attest policy provenance. New integrations should use `VerifiedPrivacyModule.Load` / `ag_privacy_create_verified` / Python `VerifiedAgPrivacy` and the verified Node factory.

## Separate signed configuration

A flat local bundle contains `ag-privacy.runtime.json`, detached64-byte P1363 ECDSA P-256 `ag-privacy.runtime.sig`, `policy.json`, optional `person.bin`. The config binds exact SHA256 hashes of policy/model and the compiled regex pack; runtime cannot load regex code/plugins/remote URLs. Fields, scope and lower input/output ceilings are configurable. The schema and strict example are in `config/`; `$schema` is descriptive, runtime never downloads it.

Host must pin BOTH the public SPKI and current approved config SHA256 outside this mutable directory, in readonly installed configuration or an authenticated host store. Never recompute the expected digest from the currently supplied bundle or trust an adjacent public-key file merely because it exists. This prevents replay of an older valid signed `off`/minimal/profile after a human has enabled full protection or changed scope/policy. A signature authenticates the issuer, not freshness or proof of a physical click.

Load verifies bounded exact bytes before parsing/using them, holds a frozen snapshot, rejects duplicate/unknown settings, mode flags, unsafe basenames, missing artifacts and bad hashes. Unix artifact opens use nonblocking/no-follow flags and require seekable regular-file behaviour; FIFO cannot stall a registry lock. Filesystem corruption/mounted remote FS/kernel stalls still require host process isolation and request deadlines; this is not an OS security boundary. Windows UNC roots are rejected. Install roots and parent directories must be trusted local storage.

A loaded context does not live-reload on disk changes. On human re-enable/change, serialize requests, close obsolete contexts, replace trusted pins atomically and open the new signed configuration. Never keep an old authorized-off context reachable by agents. No silent fallback to old/unverified settings on failure. Keys, binaries, pins, signing/control APIs and raw storage must be isolated from arbitrary agent code. Signed configs do not protect a modified process/library or compromised OS.

## Three persistent installation choices

`config/install-options.json` describes options for product installers. Recommended default is full protection. User may explicitly choose a persisted default:

- `strict`: default conservative full-value redaction.
- `credentials-only`: recognized tokens/secrets, password fields and supported form logins; names/other personal data can remain original. No NER/model needed.
- `off`: original data, still subject to parser/resource limits.

Reduced/off require a signed `humanSetupChoice` equal to mode and the approved current config digest. Host invokes `InstallationSettings.SignAfterHumanChoice` ONLY after authenticating the actual user's installer/settings action and displaying the supplied warning. This is host-only control plane, not an agent tool or a language classifier. The normal admin CLI signer refuses non-strict modes; there is no agent-facing `--disable` or input flag. Product installers must wire a real UI/event boundary; this SDK does not authenticate a human by itself and does not deploy that UI into existing products.

User-selected install defaults persist across tasks/chats/restarts until the user changes them. Temporary task/chat disclosure grants retain their own separate TTL/revoke rules. A direct real user instruction to preserve originals already counts in its explicit scope; do not ask twice. It does not authorize permanent logs or third-party transfers.

Every result identifies `ProtectionMode`. Minimal/off have `SafeForAgent=false` and `AuthorizedByHumanChoice=true`, with a clear notice; these are authorized originals, not a no-PII claim. Generic strict adapters reject unsafe results. Only the verified-installation adapter may release them under the already pinned human choice. Masking still sets `MustDiscloseMasking`, never returning original-to-mask mappings or detected samples.

### Minimal coverage

Structured secret fields (`password`, tokens/authorization/API keys/cookies/CSRF/session credentials and custom policy fields typed SECRET) are fully masked, including objects/arrays. Default credential protection cannot be weakened by changing a field's policy type. Login aliases and custom KLOGIN fields are protected inside `form`, `forms`, `formfields`, `inputs`; descriptor objects `name`/`id` + `value` and `type=password` are supported. Literal HTML input attributes are handled with quote-aware parsing. Structured captured DOM controls are preferred over arbitrary HTML strings.

Recognized JWT/provider-token/private-key patterns, secret labels and Bearer/Basic headers are masked in strings. Arbitrary unlabeled opaque strings, unusual encodings, browser runtime properties absent from a capture and arbitrary HTML grammar are not guaranteed credential detection. Minimal is deliberately labelled limited, not strict/no-PII. Source/shape-specific capture adapters must be qualified. No image/OCR guarantees.

## API ownership and resource bounds

`ag_privacy_create_verified`: rootUTF8 + pinnedSPKI + privateHMACkey + approvedSHA256, all pointer/length pairs. Returns positive process-local int64 ID or0. At most64 pending/live modules, no reuse of IDs. Creation reserves capacity without holding registry lock during IO. `ag_privacy_process_json` returns an owned UTF8 buffer; free once with `ag_privacy_free`. `ag_privacy_destroy` is idempotent; stale/bad IDs fail closed. Mode query returns0/1/2 or-1 invalid. Inputs and outputs never alias; caller supplies valid memory. IDs are not authentication tokens.

Configured ceilings only reduce fixed hard limits. maxOutputBytes limits permitted responses; fixed failure metadata may exceed a smaller configured value but stays under the hard response ceiling. Disabling masking does not disable JSON depth/token/input limits. Module methods serialize work/disposal; use multiple independent contexts for parallel throughput. Caller owns key/input copies and must use appropriate secure memory controls; no promise to erase immutable managed strings or model/provider history.

## Admin preparation

```sh
dotnet run --project tools/AgPrivacy.Configure -c Release -- keygen /private/installer.secret /private/installer.spki
dotnet run --project tools/AgPrivacy.Configure -c Release -- prepare /private/profile policies/default.json models/person-default.bin
# Edit scope/field policy/limits in trusted setup. Sign only after selecting intended configuration.
dotnet run --project tools/AgPrivacy.Configure -c Release -- sign /private/profile /private/installer.secret
# Copy printed approved-config-sha256 into host readonly trust configuration, alongside pinned public SPKI.
```

For minimal/off use the trusted installer API, not a CLI/agent flag. Never distribute private signing/HMAC keys, synthetic fixture tools or test bypass with runtime bundles. Runtime uses only BCL/system libraries and offline artifacts. NativeAOT RID must match OS/architecture; building a RID is not proof it was executed on another OS. Actual current platform results live in reports and package manifests.
