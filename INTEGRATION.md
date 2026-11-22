# Adopt Encryptoglyph

Encryptoglyph 0.2.0 exposes two surfaces that share one envelope: the in-process library, and the versioned HTTP sidecar (`/v1`, header `X-Encryptoglyph-Api: 1`). Keys created through the sidecar stay in process memory. Responses carry fingerprints, never key bytes. The assistant endpoint refuses plaintext and key fields.

## In process

```python
from eg_crypto import Keyring, RecordContext, encrypt, decrypt

kr = Keyring({kid: key}, kid)
ctx = RecordContext("acme", "field", "customers", "42", "email")
blob = encrypt(kr, ctx, b"ada@example.com")
assert decrypt(kr, ctx, blob) == b"ada@example.com"
```

`api/eg_crypto` is the Python package. `crates/encryptoglyph` is the Rust source of truth. `@godesk/encryptoglyph` (`sdk/js`) is the Node.js 24 package. All three check `testvectors/envelope.json`.

```js
import { Keyring, encrypt, decrypt } from "@godesk/encryptoglyph";

const kr = new Keyring(kid, key);
const ctx = { tenant: "acme", purpose: "field", table: "customers", recordId: "42", field: "email" };
const blob = encrypt(kr, ctx, "ada@example.com");
if (Buffer.from(decrypt(kr, ctx, blob)).toString() !== "ada@example.com") throw new Error("round trip");
```

Install with `npm install ./sdk/js`, `npm install ./sdk/js/godesk-encryptoglyph-0.2.0.tgz`, or `npm install github:GoDeskio/Encryptoglyph#<ref>`. No `wasm-pack` step.

## Sidecar

Run the API (it also serves the console):

```bash
cd api
python -m pip install -r requirements.txt
BUILD_SHA="$(git rev-parse --short=12 HEAD)" python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

```python
import os
from encryptoglyph_client import Encryptoglyph

eg = Encryptoglyph(os.environ["EG_URL"])
eg.session()
sealed = eg.seal(
    {"tenant": "acme", "purpose": "field", "table": "customers", "record_id": "42", "field": "email"},
    b"ada@example.com",
)
```

The client is `sdk/python/encryptoglyph_client.py`. The browser equivalent is `sdk/js/encryptoglyph.js`. Set `EG_URL` to the sidecar origin. No secret belongs in the repo or in that environment variable.

A GoDesk app (GitGoat, RailYard, Portkyl, Komboe, Cerebro, or another service) vendors one client and calls `session` then `seal`. The same record context must be presented to open the blob.

## Console inventory metadata

The Inventory view and `/v1` share a temporary, session-scoped tenant → site → device
hierarchy. Open a session using `POST /v1/sessions`; send its `session_id` as
`x-eg-session` on every inventory request. These are operator labels, not custody
namespaces, device enrollment, authorization boundaries, or connections to OpenBao.
Do not put credentials or recovery material in metadata names.

| Collection | Required POST JSON fields |
| --- | --- |
| `/v1/tenants` | `id`, `name` |
| `/v1/sites` | `id`, `name`, `tenant_id` |
| `/v1/devices` | `id`, `name`, `site_id` |

Each collection supports `POST` (201, created record), `GET` (an object containing
the collection array), and `GET /v1/<collection>/<id>` (one record). IDs contain
1–64 ASCII letters, digits, `.`, `_`, `:`, or `-` (excluding `.` and `..`); names are trimmed and contain
1–120 characters without control characters. Unknown fields are rejected (400).
Parents must exist in the same session (404), and IDs are unique per collection
within a session (409). Each collection is limited to 1,000 records per session.
Missing or expired sessions return 401. Metadata is lost on session expiry
(eight hours), reset, or process restart; separate workers do not share it.
This slice does not supply persistent storage or production tenant isolation.

`GET /v1/keys` extends each fingerprint record with `rotation_status` (`current`
or `retired`), `created_unix`, and nullable `retired_unix` timestamps in Unix
seconds. Rotation retires the previous key for new seals while retaining it for
opening and rewrapping existing envelopes. There is no rotation schedule, overdue
policy, or bulk rewrap worker. Shredded keys disappear from the inventory.
Keys remain session-scoped and are not assigned to inventory sites or tenants.

Custody exposes `backup_health`, `restore_tests`, and `escrow_approvals` as
`not-implemented`; OpenBao is `not-connected` and restic is `not-configured`.
The existing sealed fingerprint download is not a key backup or restore test.

## Updates

`VERSION` is the product version. `GET /v1/update` compares it with the public GitHub release for `GoDeskio/Encryptoglyph` and returns `update_available` without downloading anything.

```bash
python scripts/encryptoglyph-update.py --check
python scripts/encryptoglyph-update.py --download /tmp/encryptoglyph-next
```

The downloader accepts only `https://api.github.com/repos/GoDeskio/Encryptoglyph/tarball/<tag>`, checks the gzip header, and extracts into a new directory. It does not run the archive.

Tagged releases (`v*`) are checked by `.github/workflows/release.yml`, which fails if the tag disagrees with `VERSION`. Publishing the GitHub release is a separate maintainer step. This tree does not deploy.
