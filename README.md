# Pocket

This program uses `winfsp-rs` to mount a virtual file system at the current user's `.ssh` directory (for example `C:\Users\yourname\.ssh`).
It intercepts access to `id_ed25519` and returns "hello world".

## Prerequisites

1. Install [WinFsp](https://winfsp.dev/).
2. Run as Administrator (required for mounting file systems usually).

## Usage (in-memory only)

```bash
cargo run
```

## Select backend via `config.toml`

Backend is selected at runtime by a TOML file named `config.toml`.

Search order:

1. Platform configuration directory from `directories::ProjectDirs` (for example on Windows: `%APPDATA%\hamflx\pocket\config.toml`).
2. Fallback: `config.toml` in the current working directory.

Example (pure in‑memory):

```toml
[storage]
backend = "memory"
```

Example (S3 backend):

```toml
[storage]
backend = "s3"

[storage.s3]
bucket = "your-bucket-name"
credentials = "default"              # base name (no extension) of encrypted credential file
region = "cn-hangzhou"                     # optional, overrides env if set
prefix = "optional/prefix"                # optional
endpoint = "https://oss-cn-hangzhou.aliyuncs.com"  # optional, for Aliyun OSS or other S3-compatible endpoints

# The legacy fields `access_key_id` and `secret_access_key` are still supported for
# backward compatibility but are no longer recommended. Prefer encrypted credentials.
```

Behavior when `backend = "s3"`:

- New/modified files under the mounted directory are kept in memory and uploaded to S3.
- Deletes and renames are propagated to S3 on a best‑effort basis.
- Existing objects already in the bucket (under the configured prefix, if any) are loaded into the in‑memory view at startup.

## Configure encrypted S3 credentials (CLI)

Instead of putting S3 credentials directly into `config.toml`, use the built‑in CLI to store them encrypted with the Windows Data Protection API and update the config file automatically:

```bash
pocket config-s3 \
  --bucket your-bucket-name \
  --region cn-hangzhou \
  --prefix optional/prefix \
  --endpoint https://oss-cn-hangzhou.aliyuncs.com \
  --credentials default \
  --access-key-id YOUR_ACCESS_KEY_ID \
  --secret-access-key YOUR_SECRET_ACCESS_KEY
```

This command will:

- Encrypt the access key ID and secret access key using the current Windows user and store them under a file whose base name is `credentials` (e.g. `default.bin`) in a platform‑specific configuration directory.
- Write or update `config.toml` to use the S3 backend and reference the encrypted credential file via `[storage.s3].credentials`.

## Installation as a Windows Service (Auto-start)

To install Pocket as a service that automatically starts when Windows boots:

```bash
pocket install
```

This command will:

- Copy the executable to `%LOCALAPPDATA%\hamflx\pocket\data\bin\pocket.exe`
- Add a registry entry to start Pocket automatically on Windows startup
- Start the service immediately in the background (without showing a console window)

To uninstall the service:

```bash
pocket uninstall
```

This will remove the auto-start registry entry and stop any running instances.

## Note

- While running, any existing files in the target `.ssh` directory will be hidden.
- Upon stopping (Press Enter), the original directory contents will reappear.
