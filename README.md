# Pocket

Pocket is a Windows‑focused virtual filesystem built on top of WinFsp. It mounts one or more local directories and backs their contents by either an in‑memory store or an S3‑compatible object store, with a CRDT‑based index.

## Features

- WinFsp‑based user‑mode filesystem.
- Multiple mount points, each with its own backend and optional S3 key prefix.
- Pluggable storage backends:
  - `memory` – ephemeral in‑process store for testing and development.
  - `s3` – persists file contents and index in an S3 bucket (or compatible service).
- Index metadata stored as a Loro (CRDT) document and snapshotted to the backend.
- Encrypted S3 credentials on Windows using the Data Protection API (DPAPI).
- Optional background service that auto‑starts with Windows.

## Prerequisites

1. Windows with [WinFsp](https://winfsp.dev/) installed.
2. Administrator privileges (usually required to mount WinFsp filesystems).
3. A Rust toolchain (if building from source).

## Build

```bash
cargo build --release
```

On Windows this produces `target\release\pocket.exe`.

## Configuration (`config.toml`)

Pocket discovers configuration as follows:

1. `config.toml` in the platform configuration directory from `directories::ProjectDirs` (for example on Windows: `%APPDATA%\hamflx\pocket\config.toml`).
2. Fallback: `config.toml` in the current working directory.

The configuration file has two main parts:

- `storages` – named backends (memory or S3).
- `mounts` – local directories to mount, each bound to a storage.

Pocket expands the following inside `mount_path`:
- `~` – user's home directory
- `$VAR` or `${VAR}` – any environment variable (e.g. `$APPDATA`, `${USERPROFILE}`)

### Minimal in‑memory example

This example mounts `~/.pocket-tmp` using the built‑in `memory` backend:

```toml
[[mounts]]
name = "mem"
mount_path = "~/.pocket-tmp"
storage = "memory"
```

Files created under the mount are kept purely in memory and disappear after the process exits.

### S3 backend example

First define an S3 storage named `default` and mount it at your SSH directory:

```toml
[storages.default]
backend = "s3"

[storages.default.s3]
bucket = "your-bucket-name"
region = "cn-hangzhou"                           # optional
endpoint = "https://oss-cn-hangzhou.aliyuncs.com"  # optional, S3-compatible endpoint
credentials = "default"                          # base name (no extension) of encrypted credential file

[[mounts]]
name = "ssh"
mount_path = "~/.ssh"
storage = "default"
prefix = "ssh/"                                  # optional S3 key prefix for this mount
```

Behavior when using the S3 backend:

- File contents are stored as objects under `data/<object-id>` inside the bucket (with the configured prefix).
- A CRDT‑based index is stored under `index/*`, with the latest snapshot referenced by `index/head`.
- Existing files referenced by the index become visible under the mount at startup.
- Deletes and renames update the index and are reflected in S3 on a best‑effort basis.

## CLI: configure encrypted S3 credentials (Windows)

Instead of putting S3 credentials directly into `config.toml`, use the built‑in CLI to store them encrypted with the Windows Data Protection API and update the config:

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

- Encrypt the access key ID and secret access key for the current Windows user and write them to a file named `<credentials>.bin` under a `credentials` directory in the same configuration directory as `config.toml` (for example `%APPDATA%\hamflx\pocket\credentials\default.bin`).
- Create or update `config.toml` to define `[storages.default]` with `backend = "s3"` and an S3 section referencing the encrypted credential profile via `[storages.default.s3].credentials`.

You still need to add at least one `[[mounts]]` entry manually to choose where the filesystem is mounted.

On non‑Windows platforms this command returns an error because DPAPI is not available.

## Running (foreground)

From the project root (with a valid `config.toml`):

```bash
cargo run
```

Pocket will:

- Load the configuration and initialize all configured mounts.
- On Windows, mount each directory using WinFsp and block until you press ENTER in the console.
- When exiting, unmount all filesystems so that the underlying real directories (for example your original `.ssh` folder) become visible again.

## Installation as a Windows background service (auto‑start)

To install Pocket so it starts automatically when you log into Windows:

```bash
pocket install
```

This command will:

- Copy the executable to `%LOCALAPPDATA%\hamflx\pocket\bin\pocket.exe`.
- Register a `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` entry named `Pocket`.
- Start `pocket.exe` in the background without a console window.

To uninstall:

```bash
pocket uninstall
```

This will:

- Remove the Windows startup registry entry.
- Stop any running `pocket.exe` processes.
- Remove the installed binary from `%LOCALAPPDATA%\hamflx\pocket\bin\pocket.exe`.

On non‑Windows platforms `install` and `uninstall` currently return an error.

## Notes and limitations

- Pocket currently targets Windows and depends on WinFsp for mounting.
- The `memory` backend does not persist any data across restarts.
- File permissions on the virtual filesystem are based on a security descriptor that grants full control to the current user.
- Logging goes to a file under the platform data directory (for example `%LOCALAPPDATA%\hamflx\pocket\logs\pocket.log` on Windows).
