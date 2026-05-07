# USB-Vault

Windows USB deterministic password generator.

USB-Vault is intentionally Windows-only in this folder so the USB stays clean and matches how you actually use it.

## What To Click

On Windows, click:

```powershell
1-CLICK-THIS-ON-WINDOWS.bat
```

That is the main launcher.

## What It Does

- Runs from the USB drive.
- Creates `vault\seed.enc` on first run.
- Derives deterministic passwords from your master password and website input.
- Stores profile metadata only if you choose to save a profile.
- Does not store generated passwords.

## Important Security Notes

- Lost master password means permanent loss of access.
- Lost `seed.enc` means permanent loss of access.
- Back up `vault\seed.enc` to a separate secure place.
- Protect the USB drive like a physical key.
- Do not use this on untrusted or infected computers.

## First Run

1. Plug in the USB.
2. Open the USB folder.
3. Double-click `1-CLICK-THIS-ON-WINDOWS.bat`.
4. Type `I AGREE` when prompted.
5. Create your master password.
6. At `Website/Domain`, type a site like `gmail.com`.
7. Copy the generated password.

Password typing is hidden. Nothing appears on screen while you type the master password. That is normal.

## Normal Use

1. Double-click `1-CLICK-THIS-ON-WINDOWS.bat`.
2. Enter your master password.
3. Enter the same website/domain, username, version, and length.
4. The same password is recreated 1:1.

To recreate a password, use the exact same inputs:

- same master password
- same website/domain
- same username/login
- same version
- same length

## Cryptographic Components

Password generation:

- Uses `HMAC-SHA256` as the deterministic core primitive.
- The decrypted 32-byte seed acts as the HMAC key.
- The message is built from website/domain, username, version, and length.
- Same seed plus same inputs recreates the same password 1:1.

Seed encryption for storage:

- Uses `AES-256-GCM` for authenticated encryption of `vault\seed.enc`.
- Uses `PBKDF2-HMAC-SHA256` to derive the AES key from the master password.
- New seeds use a 16-byte random salt.
- New seeds use `600000` PBKDF2 iterations.
- Legacy seeds created with `200000` iterations are still supported.

Optional pepper support:

- `VAULT_PEPPER` can add an environment-variable pepper.
- `VAULT_USE_DEVICE_PEPPER=1` can include `.vault-device-id` as device pepper input.
- Pepper input is combined with the master password before PBKDF2.
- Changing pepper settings after seed creation requires migration or restoring the original settings.

## Folder Layout

```text
USB-Encrypted/
  .vault-device-id.example
  .vault-device-id (local, optional, ignored by git)
  1-CLICK-THIS-ON-WINDOWS.bat
  START_VAULT.bat
  autorun.inf
  DISCLAIMER.txt
  INSTALL.txt
  README.md
  requirements.txt
  vault/
    derive.py
    init_seed.bat
    profiles.json (optional metadata, no passwords)
    seed.enc (created on first run)
  vendor/
    bundled Python dependency files
```

## Profiles

Profiles are optional. They store only metadata:

- website/domain
- username/login
- version
- length

They do not store passwords.

Useful commands from the `vault` folder:

```powershell
python derive.py --list-profiles
python derive.py --use gmail.com
python derive.py --delete-profile gmail.com
```

## Manual Commands

From the `vault` folder:

```powershell
python derive.py gmail.com
python derive.py gmail.com alice 2
python derive.py gmail.com alice 2 24
```

## Troubleshooting

**Nothing appears while typing master password**

That is normal. Password input is hidden. Type the password and press Enter.

**Module not found**

Run from the USB root:

```powershell
python -m pip install -r requirements.txt
```

