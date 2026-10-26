# Cocoon

> [!WARNING]
> I migrated and have been running my main account on this PDS for months now without issue, however, I am still not responsible if things go awry, particularly during account migration. Please use caution.

Cocoon is a PDS implementation in Go. It is highly experimental, and is not ready for any production use.

## Quick Start with Docker Compose

### Prerequisites

- Docker and Docker Compose installed
- A domain name pointing to your server (for automatic HTTPS)
- Ports 80 and 443 open in i.e. UFW

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/haileyok/cocoon.git
   cd cocoon
   ```

2. **Create your configuration file**
   ```bash
   cp .env.example .env
   ```

3. **Edit `.env` with your settings**

   Required settings:
   ```bash
   COCOON_DID="did:web:your-domain.com"
   COCOON_HOSTNAME="your-domain.com"
   COCOON_CONTACT_EMAIL="you@example.com"
   COCOON_RELAYS="https://bsky.network"

   # Generate with: openssl rand -hex 16
   COCOON_ADMIN_PASSWORD="your-secure-password"

   # Generate with: openssl rand -hex 32
   COCOON_SESSION_SECRET="your-session-secret"
   ```

4. **Start the services**
   ```bash
   # Pull pre-built image from GitHub Container Registry
   docker-compose pull
   docker-compose up -d
   ```

   Or build locally:
   ```bash
   docker-compose build
   docker-compose up -d
   ```

   **For PostgreSQL deployment:**
   ```bash
   # Add POSTGRES_PASSWORD to your .env file first!
   docker-compose -f docker-compose.postgres.yaml up -d
   ```

5. **Get your invite code**

   On first run, an invite code is automatically created. View it with:
   ```bash
   docker-compose logs create-invite
   ```

   Or check the saved file:
   ```bash
   cat keys/initial-invite-code.txt
   ```

   **IMPORTANT**: Save this invite code! You'll need it to create your first account.

6. **Monitor the services**
   ```bash
   docker-compose logs -f
   ```

### What Gets Set Up

The Docker Compose setup includes:

- **init-keys**: Automatically generates cryptographic keys (rotation key and JWK) on first run
- **cocoon**: The main PDS service running on port 8080
- **create-invite**: Automatically creates an initial invite code after Cocoon starts (first run only)
- **caddy**: Reverse proxy with automatic HTTPS via Let's Encrypt

### Data Persistence

The following directories will be created automatically:

- `./keys/` - Cryptographic keys (generated automatically)
  - `rotation.key` - PDS rotation key
  - `jwk.key` - JWK private key
  - `initial-invite-code.txt` - Your first invite code (first run only)
- `./data/` - SQLite database and blockstore
- Docker volumes for Caddy configuration and certificates

### Optional Configuration

#### Database Configuration

By default, Cocoon uses SQLite which requires no additional setup. For production deployments with higher traffic, you can use PostgreSQL:

```bash
# Database type: sqlite (default) or postgres
COCOON_DB_TYPE="postgres"

# PostgreSQL connection string (required if db-type is postgres)
# Format: postgres://user:password@host:port/database?sslmode=disable
COCOON_DATABASE_URL="postgres://cocoon:password@localhost:5432/cocoon?sslmode=disable"

# Or use the standard DATABASE_URL environment variable
DATABASE_URL="postgres://cocoon:password@localhost:5432/cocoon?sslmode=disable"
```

For SQLite (default):
```bash
COCOON_DB_TYPE="sqlite"
COCOON_DB_NAME="/data/cocoon/cocoon.db"
```

> **Note**: When using PostgreSQL, database backups to S3 are not handled by Cocoon. Use `pg_dump` or your database provider's backup solution instead.

#### Backups and Restore Rehearsal

Set `COCOON_BACKUP_DIR=/private/backups/cocoon` (or `--backup-dir`) for
hourly local SQLite snapshots, independently of S3. Provision this directory
beforehand with owner-only access (mode 0700); Cocoon does not create it or change
existing directory permissions. With neither a local
directory nor S3 backups enabled, there is **no built-in backup schedule**.
Snapshots use `VACUUM INTO`, are synced and atomically published with mode
0600, and include database-held account signing keys and SQLite blob payloads.
S3 backups stream the snapshot from disk; they do not buffer the whole database.
One process performs backups serially. A failed S3 upload retains a completed
local snapshot when local backups are enabled, without recording full success.

Backups run on startup if the last successful backup is missing or more than
an hour old, then hourly. Inspect logs and `last-backup.txt` in the local backup
directory (working directory for S3-only backups). An incomplete S3 backup
configuration disables the schedule even if a local directory is configured.
Monitor free disk space and copy snapshots off-host with encryption and access
controls. Automatic pruning is deliberately absent: define retention only after
verifying a restore, and never expose snapshots through a public bucket/CDN.

A database snapshot is **not a complete recovery bundle**. Securely preserve
the PDS rotation-key file, JWK file, session secret, configuration, DPoP nonce
secret, and independently held recovery keys. Back up S3 blob objects separately,
including historical key layouts; the database contains only their metadata.
Keep the exact binary/image version and its configuration with the recovery plan.

Rehearse with disposable identities first. Copy a snapshot into a fresh isolated
directory, open it with SQLite and require `PRAGMA integrity_check` to return
`ok`; verify account keys, repository heads/blocks and representative blobs.
Restore external keys/configuration and S3 payloads into isolated destinations.
Block outbound network access before starting restored data, disable Spaces and
KEM backfill, and test sign-in, repository export and blob reads locally. Those
flags alone do not isolate a restored PDS. Do not run two copies of a real
identity, publish PLC changes, or switch traffic as part of a rehearsal.
For an actual restore, stop the PDS first and preserve its old database **and
WAL/SHM files together** before selecting the verified snapshot; never mix old
WAL files with a restored database. Production restore/cutover requires a separate
operator decision.

#### SMTP Email Settings
```bash
COCOON_SMTP_USER="your-smtp-username"
COCOON_SMTP_PASS="your-smtp-password"
COCOON_SMTP_HOST="smtp.example.com"
COCOON_SMTP_PORT="587"
COCOON_SMTP_EMAIL="noreply@example.com"
COCOON_SMTP_NAME="Cocoon PDS"
```

#### Blob Upload Limit

`com.atproto.repo.uploadBlob` accepts at most 5 MiB (5,242,880 bytes) by default,
including requests without a Content-Length header. Set `COCOON_BLOB_UPLOAD_LIMIT`
or `--blob-upload-limit` to a positive byte count to change it; zero uses the
default and negative values are rejected. Larger uploads return `BlobTooLarge`.

Uploads spool to temporary files before persistence, so provision temporary disk
space for concurrent uploads. SQLite blob metadata and parts commit together.
Failed S3 uploads receive best-effort cleanup. Objects are retained when a
database commit's outcome is uncertain, to avoid deleting committed data. This
is not crash-safe garbage collection or an aggregate storage quota.

#### Signing-Key Reservations

The public migration endpoint accepts JSON bodies up to 16 KiB. New key
generation is limited to one per second with a burst of five per server process,
independent of proxy/IP headers. It returns HTTP 429 when that allowance is
exhausted. Admission stops at 10,000 stored reservations per database (HTTP 503);
existing DID reservations remain reusable at either limit. All writers must run
the bounded implementation for the database-wide ceiling to hold.

Reserved private keys **do not expire**: a migrating DID may already publish one
before account creation finishes. Failed migrations retain them, and successful
creation removes only the consumed reservation after the same private key is
stored in the account. Preserve/export key material before any manual cleanup;
age alone is not evidence that deletion is safe. A public caller can eventually
fill the bounded pool, denying new reservations; limits prevent unbounded growth,
not all denial of service. Existing databases above the ceiling are not truncated.

#### S3 Storage

Cocoon supports S3-compatible storage for both database backups (SQLite only) and blob storage (images, videos, etc.):

```bash
# Enable S3 backups (SQLite databases only - hourly backups)
COCOON_S3_BACKUPS_ENABLED=true

# Enable S3 for blob storage (images, videos, etc.)
# When enabled, blobs are stored in S3 instead of the database
COCOON_S3_BLOBSTORE_ENABLED=true

# S3 configuration (works with AWS S3, MinIO, Cloudflare R2, etc.)
COCOON_S3_REGION="us-east-1"
COCOON_S3_BUCKET="your-bucket"
COCOON_S3_ENDPOINT="https://s3.amazonaws.com"
COCOON_S3_ACCESS_KEY="your-access-key"
COCOON_S3_SECRET_KEY="your-secret-key"

# Optional: CDN/public URL for blob redirects
# When set, com.atproto.sync.getBlob redirects to this URL instead of proxying
COCOON_S3_CDN_URL="https://cdn.example.com"
```

**Blob Storage Options:**
- `COCOON_S3_BLOBSTORE_ENABLED=false` (default): Blobs stored in the database
- `COCOON_S3_BLOBSTORE_ENABLED=true`: Blobs stored in S3 bucket under `blobs/{did}/{cid}`

**Blob Serving Options:**
- Without `COCOON_S3_CDN_URL`: Blobs are proxied through the PDS server
- With `COCOON_S3_CDN_URL`: `getBlob` returns a 302 redirect to `{CDN_URL}/blobs/{did}/{cid}`

**Retention and access policy:** ordinary record/account deletion and reference
garbage collection do not delete S3 objects. Once blob metadata is removed,
`getBlob` for an existing active account returns `BlobNotFound` without a
redirect. This is not remote erasure or immutable retention: an already known
public bucket/CDN URL, cached response, or downloaded copy can remain accessible.
Automatic failed-upload cleanup may delete an unreferenced object, including a
failed re-upload of a key whose metadata was previously collected. Cleanup is
best-effort and can leave orphans after uncertain remote/database outcomes.
There is no automatic general S3 orphan collector or indefinite-retention guarantee.

Use a **private bucket with no public CDN URL** when access must follow PDS
checks, particularly for Spaces attachments. Do not make a bucket public merely
to enable redirects: the same configured bucket may also contain database
backups with private keys. Any deliberately public distribution must expose only
intended public content and must never expose backup prefixes or private blobs.
Cocoon does not configure bucket policies, version retention, or CDN caches.

Do not apply an age-only expiry rule to `blobs/`: old objects may still be
referenced, and backups may need objects no longer present in the current DB.
Before manual reclamation, stop writers, preserve a recoverable object inventory
and database snapshot, reconcile public and Spaces references plus required
backup history, and account for legacy nested keys and object versions. Reclamation
beyond failed-upload cleanup, retention-policy changes and CDN purges are explicit
operator actions; none is performed by an ordinary record deletion.

#### PLC Directory

Cocoon uses the public PLC directory (`https://plc.directory`) to create, update, and resolve `did:plc` identities. You can point it at a different directory, such as a local PLC instance for integration testing, so that test accounts are never registered with the real directory:

```bash
COCOON_PLC_URL="http://localhost:2582"
```

> **Warning**: Accounts created against a non-default PLC directory only exist in that directory and will not be resolvable by the wider network. Leave this unset for production deployments.

#### YubiKeys

Accounts can turn on two-factor sign-in with an authenticator app or a YubiKey from `/account/2fa`. To let people add a YubiKey just by touching it, get a free client ID and API key from [Yubico](https://upgrade.yubico.com/getapikey/) and set:

```bash
COCOON_YUBICO_CLIENT_ID="12345"
COCOON_YUBICO_API_KEY="base64-secret-key-from-yubico"
```

YubiKey codes are then checked with Yubico's YubiCloud service at `api.yubico.com`. If it can't be reached, YubiKey sign-in fails until it's back; authenticator codes and backup codes still work.

Without these settings, a YubiKey must first have a slot programmed with a secret key that the server stores (the setup page gives the `ykman` command).

#### Alpine based image

The default image is based on Debian. You can use the Alpine-based image if you prefer.

> [!NOTE]
> Currently, we do not have pre-built Alpine-based image on the GitHub Container Registry. You have to build them locally.

In the compose file, replace every `dockerfile: Dockerfile` by `dockerfile: Dockerfile.alpine`, e.g.
```yml
services:
  cocoon:
    build:
      context: .
      dockerfile: Dockerfile.alpine
```

You can also build the image locally with
```bash
docker build -f Dockerfile.alpine -t cocoon:alpine .
```

### Management Commands

Create an invite code:
```bash
docker exec cocoon-pds /cocoon create-invite-code --uses 1
```

Reset a user's password:
```bash
docker exec cocoon-pds /cocoon reset-password --did "did:plc:xxx"
```

### Updating

```bash
docker-compose pull
docker-compose up -d
```

## Implemented Endpoints

> [!NOTE]
Just because something is implemented doesn't mean it is finished. Tons of these are returning bad errors, don't do validation properly, etc. I'll make a "second pass" checklist at some point to do all of that.

### Identity

- [x] `com.atproto.identity.getRecommendedDidCredentials`
- [x] `com.atproto.identity.requestPlcOperationSignature`
- [x] `com.atproto.identity.resolveHandle`
- [x] `com.atproto.identity.signPlcOperation`
- [x] `com.atproto.identity.submitPlcOperation`
- [x] `com.atproto.identity.updateHandle`

### Repo

- [x] `com.atproto.repo.applyWrites`
- [x] `com.atproto.repo.createRecord`
- [x] `com.atproto.repo.putRecord`
- [x] `com.atproto.repo.deleteRecord`
- [x] `com.atproto.repo.describeRepo`
- [x] `com.atproto.repo.getRecord`
- [x] `com.atproto.repo.importRepo` (Works "okay". Use with extreme caution.)
- [x] `com.atproto.repo.listRecords`
- [x] `com.atproto.repo.listMissingBlobs`

### Server

- [x] `com.atproto.server.activateAccount`
- [x] `com.atproto.server.checkAccountStatus`
- [x] `com.atproto.server.confirmEmail`
- [x] `com.atproto.server.createAccount`
- [x] `com.atproto.server.createInviteCode`
- [x] `com.atproto.server.createInviteCodes`
- [x] `com.atproto.server.deactivateAccount`
- [x] `com.atproto.server.deleteAccount`
- [x] `com.atproto.server.deleteSession`
- [x] `com.atproto.server.describeServer`
- [ ] `com.atproto.server.getAccountInviteCodes`
- [x] `com.atproto.server.getServiceAuth`
- ~~[ ] `com.atproto.server.listAppPasswords`~~ - not going to add app passwords
- [x] `com.atproto.server.refreshSession`
- [x] `com.atproto.server.requestAccountDelete`
- [x] `com.atproto.server.requestEmailConfirmation`
- [x] `com.atproto.server.requestEmailUpdate`
- [x] `com.atproto.server.requestPasswordReset`
- [x] `com.atproto.server.reserveSigningKey`
- [x] `com.atproto.server.resetPassword`
- ~~[] `com.atproto.server.revokeAppPassword`~~ - not going to add app passwords
- [x] `com.atproto.server.updateEmail`

### Sync

- [x] `com.atproto.sync.getBlob`
- [x] `com.atproto.sync.getBlocks`
- [x] `com.atproto.sync.getLatestCommit`
- [x] `com.atproto.sync.getRecord`
- [x] `com.atproto.sync.getRepoStatus`
- [x] `com.atproto.sync.getRepo`
- [x] `com.atproto.sync.listBlobs`
- [x] `com.atproto.sync.listRepos`
- ~~[ ] `com.atproto.sync.notifyOfUpdate`~~ - BGS doesn't even have this implemented lol
- [x] `com.atproto.sync.requestCrawl`
- [x] `com.atproto.sync.subscribeRepos`

### Spaces (permissioned data, alpha)

Cocoon implements the ATProto Spaces alpha. See [docs/spaces.md](docs/spaces.md).

Set `COCOON_SPACES_ENABLED=false` (or `--spaces-enabled=false` before `run`)
to disable both Spaces namespaces and background notification retries. Spaces
remain enabled by default. Disabled methods return 404 instead of falling through
to the XRPC proxy. Existing Spaces data is retained and migrations still run, so
re-enabling does not discard memberships, records or pending notifications. This
switch does not control automatic PLC KEM-key backfill or account key creation.

Automatic KEM-key backfill is **off by default**. To upgrade existing accounts,
explicitly set `COCOON_KEM_BACKFILL_ENABLED=true` (or `--kem-backfill-enabled`
before `run`). It can publish signed PLC operations and firehose identity events
for accounts whose PLC rotation key and current PDS match this server. Review the
candidate release, account inventory, PLC destination and backed-up recovery keys
before opting in; rehearse with disposable identities first. A copied database
with real keys and network access is not an isolated test. New-account key
creation and user-requested identity operations are unaffected by this setting.

- [x] `com.atproto.space.createRecord`, `putRecord`, `deleteRecord`, `applyWrites`
- [x] `com.atproto.space.getRecord`, `listRecords`, `listRepoOps`, `getLatestCommit`, `getRepo`, `listSpaces`
- [x] `com.atproto.space.getBlob`, `listBlobs`
- [x] `com.atproto.space.getDelegationToken`, `getSpaceCredential`, `notifyCredentialRevoked`
- [x] `com.atproto.space.notifyWrite`, `registerNotify`, `unregisterNotify`, `listRepos`
- [x] `com.atproto.simplespace.createSpace`, `getSpace`, `updateSpace`, `deleteSpace`
- [x] `com.atproto.simplespace.putMember`, `removeMember`, `listMembers`

### Other

- [x] `com.atproto.label.queryLabels`
- [x] `com.atproto.moderation.createReport` (Note: this should be handled by proxying, not actually implemented in the PDS)
- [x] `app.bsky.actor.getPreferences`
- [x] `app.bsky.actor.putPreferences`

## License

This project is licensed under MIT license. `server/static/pico.css` is also licensed under MIT license, available at [https://github.com/picocss/pico/](https://github.com/picocss/pico/).
