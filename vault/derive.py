import os
import sys
import hmac
import json
import hashlib
import getpass

VENDOR_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "vendor")
if os.path.isdir(VENDOR_DIR) and VENDOR_DIR not in sys.path:
    sys.path.insert(0, VENDOR_DIR)

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

SEED_FILE = os.path.join(os.path.dirname(__file__), "seed.enc")
PROFILES_FILE = os.path.join(os.path.dirname(__file__), "profiles.json")
DEVICE_ID_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".vault-device-id")
SEED_MAGIC_V2 = b"SV2\x00"
PBKDF2_ITERATIONS = 600000
PBKDF2_LEGACY_ITERATIONS = 200000
LOWER_CHARS = "abcdefghijklmnopqrstuvwxyz"
UPPER_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGIT_CHARS = "0123456789"
SYMBOL_CHARS = "!@#$%^&*()-_=+[]{}:,.?"
ALL_CHARS = LOWER_CHARS + UPPER_CHARS + DIGIT_CHARS + SYMBOL_CHARS


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def first_run_warning() -> None:
    print("\n" + "=" * 60)
    print("LEGAL NOTICE AND DISCLAIMER")
    print("=" * 60)
    print("By proceeding, you acknowledge:")
    print("- This software is provided AS-IS with NO WARRANTIES")
    print("- You are responsible for password loss or security incidents")
    print("- Master passwords cannot be recovered if forgotten")
    print("- You must back up seed.enc after creation")
    print("- See DISCLAIMER.txt for full terms")
    while True:
        response = input("Type I AGREE to continue: ").strip()
        normalized = response.upper()
        if normalized in {"I AGREE", "AGREE", "Y", "YES"}:
            break
        if normalized in {"Q", "QUIT", "EXIT", "N", "NO"}:
            print("Exiting. Read DISCLAIMER.txt before use.")
            sys.exit(0)
        print("Input not recognized.")
        print("Type I AGREE, AGREE, Y, or YES to continue.")
        print("Type Q to exit.")
    print()
    print("Accepted.")
    print("Next step: create your master password.")
    print("IMPORTANT: when you type the master password, NOTHING will appear on screen.")
    print("That is normal for hidden password entry.")
    print()


def prompt_hidden_password(prompt_text: str) -> str:
    print(prompt_text)
    print("Your typing will be hidden. Type the password, then press Enter.")
    return getpass.getpass("")


def device_pepper_enabled() -> bool:
    return parse_bool(os.environ.get("VAULT_USE_DEVICE_PEPPER", "0"), default=False)


def validate_pepper_configuration() -> None:
    if device_pepper_enabled() and not os.path.exists(DEVICE_ID_FILE):
        print(
            "Warning: VAULT_USE_DEVICE_PEPPER is enabled but .vault-device-id was not found.",
            file=sys.stderr,
        )


def print_pepper_status() -> None:
    env_pepper = os.environ.get("VAULT_PEPPER", "")
    env_pepper_set = bool(env_pepper)
    device_enabled = device_pepper_enabled()
    device_file_exists = os.path.exists(DEVICE_ID_FILE)

    active_sources: list[str] = []
    if env_pepper_set:
        active_sources.append("env")
    if device_enabled and device_file_exists:
        active_sources.append("device")

    print("Pepper status:")
    print(f"- order: env then device")
    print(f"- env pepper set: {env_pepper_set}")
    if env_pepper_set:
        print(f"- env pepper length: {len(env_pepper)}")
    print(f"- device pepper enabled: {device_enabled}")
    print(f"- device id path: {DEVICE_ID_FILE}")
    print(f"- device id file exists: {device_file_exists}")
    print(f"- active pepper sources: {active_sources if active_sources else ['none']}")


def build_pepper(env_pepper: str, use_device_pepper: bool, strict_device: bool = False) -> bytes:
    pepper_parts: list[bytes] = []

    if env_pepper:
        pepper_parts.append(env_pepper.encode("utf-8"))

    if use_device_pepper:
        if os.path.exists(DEVICE_ID_FILE):
            try:
                with open(DEVICE_ID_FILE, "rb") as file_obj:
                    device_id = file_obj.read().strip()
                if device_id:
                    pepper_parts.append(device_id)
            except OSError:
                if strict_device:
                    raise ValueError("Failed reading .vault-device-id for device pepper")
        elif strict_device:
            raise ValueError("Device pepper enabled but .vault-device-id was not found")

    if not pepper_parts:
        return b""

    return b"|".join(pepper_parts)


def load_profiles() -> dict[str, dict[str, object]]:
    if not os.path.exists(PROFILES_FILE):
        return {}

    try:
        with open(PROFILES_FILE, "r", encoding="utf-8") as file_obj:
            data = json.load(file_obj)
    except (json.JSONDecodeError, OSError):
        return {}

    if not isinstance(data, dict):
        return {}

    cleaned: dict[str, dict[str, object]] = {}
    for name, profile in data.items():
        if not isinstance(name, str) or not isinstance(profile, dict):
            continue
        domain = str(profile.get("domain", "")).strip()
        username = str(profile.get("username", "")).strip()
        version = profile.get("version", 1)
        length = profile.get("length", 20)
        if not domain:
            continue
        try:
            version_int = int(version)
            length_int = int(length)
        except (ValueError, TypeError):
            continue
        if length_int < 4:
            continue
        cleaned[name] = {
            "domain": domain,
            "username": username,
            "version": version_int,
            "length": length_int,
        }
    return cleaned


def save_profiles(profiles: dict[str, dict[str, object]]) -> None:
    with open(PROFILES_FILE, "w", encoding="utf-8") as file_obj:
        json.dump(profiles, file_obj, indent=2, sort_keys=True)


def save_profile(name: str, domain: str, username: str, version: int, length: int) -> None:
    if not name:
        return
    profiles = load_profiles()
    profiles[name] = {
        "domain": domain,
        "username": username,
        "version": version,
        "length": length,
    }
    save_profiles(profiles)


def print_profiles() -> None:
    profiles = load_profiles()
    if not profiles:
        print("No profiles saved.")
        return

    print("Saved profiles (metadata only, no passwords):")
    for name in sorted(profiles):
        profile = profiles[name]
        print(
            f"- {name}: domain={profile['domain']}, username={profile['username']}, "
            f"version={profile['version']}, length={profile['length']}"
        )


def get_profile(name: str) -> dict[str, object] | None:
    profiles = load_profiles()
    return profiles.get(name)


def delete_profile(name: str) -> bool:
    profiles = load_profiles()
    if name not in profiles:
        return False
    del profiles[name]
    save_profiles(profiles)
    return True


def get_kdf_pepper() -> bytes:
    env_pepper = os.environ.get("VAULT_PEPPER", "")
    use_device_pepper = device_pepper_enabled()
    return build_pepper(env_pepper, use_device_pepper, strict_device=False)


def derive_key(password: bytes, salt: bytes, iterations: int, pepper: bytes = b"") -> bytes:
    key_material = password + pepper
    return PBKDF2(
        key_material,
        salt,
        dkLen=32,
        count=iterations,
        hmac_hash_module=SHA256,
    )


def encrypt_seed(seed: bytes, password: str, pepper: bytes | None = None) -> bytes:
    salt = os.urandom(16)
    pepper_bytes = get_kdf_pepper() if pepper is None else pepper
    key = derive_key(password.encode("utf-8"), salt, PBKDF2_ITERATIONS, pepper_bytes)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(seed)
    header = SEED_MAGIC_V2 + PBKDF2_ITERATIONS.to_bytes(4, "big")
    return header + salt + cipher.nonce + tag + ciphertext


def decrypt_seed_legacy(data: bytes, password: str) -> bytes:
    salt = data[:16]
    nonce = data[16:32]
    tag = data[32:48]
    ciphertext = data[48:]
    key = derive_key(password.encode("utf-8"), salt, PBKDF2_LEGACY_ITERATIONS)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def decrypt_seed_v2(data: bytes, password: str, pepper: bytes | None = None) -> bytes:
    if len(data) < 56:
        raise ValueError("seed file too short")

    if not data.startswith(SEED_MAGIC_V2):
        raise ValueError("invalid seed header")

    iterations = int.from_bytes(data[4:8], "big")
    if iterations <= 0:
        raise ValueError("invalid KDF iteration count")

    salt = data[8:24]
    nonce = data[24:40]
    tag = data[40:56]
    ciphertext = data[56:]

    pepper_bytes = get_kdf_pepper() if pepper is None else pepper
    key = derive_key(password.encode("utf-8"), salt, iterations, pepper_bytes)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def decrypt_seed(data: bytes, password: str, pepper: bytes | None = None) -> bytes:
    if data.startswith(SEED_MAGIC_V2):
        return decrypt_seed_v2(data, password, pepper=pepper)
    return decrypt_seed_legacy(data, password)


def migrate_seed() -> None:
    validate_pepper_configuration()

    if not os.path.exists(SEED_FILE):
        print("No seed.enc found to migrate.")
        return

    current_env_pepper = os.environ.get("VAULT_PEPPER", "")
    current_use_device = device_pepper_enabled()

    old_env_pepper = os.environ.get("VAULT_OLD_PEPPER", current_env_pepper)
    old_use_device = parse_bool(
        os.environ.get("VAULT_OLD_USE_DEVICE_PEPPER"), default=current_use_device
    )

    new_env_pepper = os.environ.get("VAULT_NEW_PEPPER", current_env_pepper)
    new_use_device = parse_bool(
        os.environ.get("VAULT_NEW_USE_DEVICE_PEPPER"), default=current_use_device
    )

    try:
        old_pepper = build_pepper(old_env_pepper, old_use_device, strict_device=True)
        new_pepper = build_pepper(new_env_pepper, new_use_device, strict_device=True)
    except ValueError as exc:
        print(f"Migration config error: {exc}")
        sys.exit(1)

    print("Seed migration plan:")
    print(
        f"- old pepper sources: {'env' if old_env_pepper else ''}{'+device' if old_use_device else ''}"
        or "- old pepper sources: none"
    )
    print(
        f"- new pepper sources: {'env' if new_env_pepper else ''}{'+device' if new_use_device else ''}"
        or "- new pepper sources: none"
    )

    password = getpass.getpass("Master password: ")
    with open(SEED_FILE, "rb") as file_obj:
        data = file_obj.read()

    try:
        seed = decrypt_seed(data, password, pepper=old_pepper)
    except ValueError:
        print("Migration failed: could not decrypt with OLD pepper/password settings.")
        sys.exit(1)

    backup_file = SEED_FILE + ".bak"
    with open(backup_file, "wb") as backup_obj:
        backup_obj.write(data)

    encrypted = encrypt_seed(seed, password, pepper=new_pepper)
    with open(SEED_FILE, "wb") as file_obj:
        file_obj.write(encrypted)

    print(f"Migration complete. Backup written to: {backup_file}")


def load_seed() -> bytes:
    validate_pepper_configuration()

    if not os.path.exists(SEED_FILE):
        first_run_warning()
        seed = os.urandom(32)
        password = prompt_hidden_password("Create master password:")
        confirm_password = prompt_hidden_password("Confirm master password:")
        if password != confirm_password:
            print("Passwords did not match. Seed was not created.")
            sys.exit(1)
        if not password:
            print("Master password cannot be empty.")
            sys.exit(1)
        encrypted = encrypt_seed(seed, password)
        with open(SEED_FILE, "wb") as file_obj:
            file_obj.write(encrypted)
        print("Seed created.")
        print("Reminder: back up seed.enc to a separate secure location.")
        return seed

    password = prompt_hidden_password("Master password:")
    with open(SEED_FILE, "rb") as file_obj:
        data = file_obj.read()

    try:
        return decrypt_seed(data, password)
    except ValueError:
        print("Invalid master password or corrupted seed file.")
        sys.exit(1)


def derive_password(
    seed: bytes,
    domain: str,
    username: str = "",
    version: int = 1,
    length: int = 20,
) -> str:
    if length < 4:
        raise ValueError("length must be at least 4")

    message = f"{domain}:{username}:{version}:{length}".encode("utf-8")

    def hmac_stream(tag: str, count: int) -> list[int]:
        result = []
        block_index = 0
        while len(result) < count:
            block_message = message + f":{tag}:{block_index}".encode("utf-8")
            block = hmac.new(seed, block_message, hashlib.sha256).digest()
            result.extend(block)
            block_index += 1
        return result[:count]

    base_chars = [
        LOWER_CHARS[hmac_stream("lower", 1)[0] % len(LOWER_CHARS)],
        UPPER_CHARS[hmac_stream("upper", 1)[0] % len(UPPER_CHARS)],
        DIGIT_CHARS[hmac_stream("digit", 1)[0] % len(DIGIT_CHARS)],
        SYMBOL_CHARS[hmac_stream("symbol", 1)[0] % len(SYMBOL_CHARS)],
    ]

    filler_count = length - len(base_chars)
    filler_bytes = hmac_stream("fill", filler_count)
    for byte_value in filler_bytes:
        base_chars.append(ALL_CHARS[byte_value % len(ALL_CHARS)])

    order_bytes = hmac_stream("shuffle", len(base_chars))
    indexed_chars = list(enumerate(base_chars))
    indexed_chars.sort(key=lambda pair: order_bytes[pair[0]])
    shuffled = [char for _, char in indexed_chars]
    return "".join(shuffled)


def interactive_mode(seed: bytes) -> None:
    print("\nInteractive mode")
    print("- This is a terminal prompt, not a GUI form.")
    print("- Type the website/domain when asked.")
    print("- Examples: gmail.com, github.com, amazon.com")
    print("- Leave Website/Domain blank to quit.\n")
    while True:
        domain = input("Website/Domain (example: gmail.com): ").strip()
        if not domain:
            print("Goodbye.")
            return

        username = input("Username/Login (optional): ").strip()
        version_input = input("Version [1]: ").strip()
        length_input = input("Length [20]: ").strip()

        if version_input:
            try:
                version = int(version_input)
            except ValueError:
                print("Version must be an integer. Using 1.")
                version = 1
        else:
            version = 1

        if length_input:
            try:
                length = int(length_input)
                if length < 4:
                    print("Length must be >= 4. Using 20.")
                    length = 20
            except ValueError:
                print("Length must be an integer. Using 20.")
                length = 20
        else:
            length = 20

        password = derive_password(seed, domain, username, version, length)
        print("\nGenerated password for", domain)
        print()
        print(password)
        print()

        save_answer = input("Save inputs as profile (metadata only)? [y/N]: ").strip().lower()
        if save_answer == "y":
            default_name = domain.lower()
            profile_name = input(f"Profile name [{default_name}]: ").strip() or default_name
            save_profile(profile_name, domain, username, version, length)
            print(f"Saved profile: {profile_name}")
            print()


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "--init":
        load_seed()
        print("Vault seed ready.")
        return

    if len(sys.argv) > 1 and sys.argv[1] == "--list-profiles":
        print_profiles()
        return

    if len(sys.argv) > 1 and sys.argv[1] == "--show-pepper-status":
        print_pepper_status()
        return

    if len(sys.argv) > 1 and sys.argv[1] == "--migrate-seed":
        migrate_seed()
        return

    if len(sys.argv) > 2 and sys.argv[1] == "--delete-profile":
        profile_name = sys.argv[2]
        deleted = delete_profile(profile_name)
        if not deleted:
            print(f"Profile not found: {profile_name}")
            sys.exit(1)
        print(f"Deleted profile: {profile_name}")
        return

    if len(sys.argv) > 2 and sys.argv[1] == "--use":
        profile_name = sys.argv[2]
        profile = get_profile(profile_name)
        if not profile:
            print(f"Profile not found: {profile_name}")
            sys.exit(1)
        seed = load_seed()
        password = derive_password(
            seed,
            str(profile["domain"]),
            str(profile["username"]),
            int(profile["version"]),
            int(profile["length"]),
        )
        print("\nGenerated password:\n")
        print(password)
        return

    if len(sys.argv) < 2:
        seed = load_seed()
        interactive_mode(seed)
        return

    if len(sys.argv) > 5:
        print("usage: python derive.py domain [username] [version] [length]")
        print("   or: python derive.py --list-profiles")
        print("   or: python derive.py --use profile_name")
        print("   or: python derive.py --delete-profile profile_name")
        print("   or: python derive.py --show-pepper-status")
        print("   or: python derive.py --migrate-seed")
        print("      with optional env vars:")
        print("      VAULT_OLD_PEPPER, VAULT_OLD_USE_DEVICE_PEPPER")
        print("      VAULT_NEW_PEPPER, VAULT_NEW_USE_DEVICE_PEPPER")
        sys.exit(1)

    domain = sys.argv[1]
    username = sys.argv[2] if len(sys.argv) > 2 else ""

    try:
        version = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    except ValueError:
        print("version must be an integer")
        sys.exit(1)

    try:
        length = int(sys.argv[4]) if len(sys.argv) > 4 else 20
    except ValueError:
        print("length must be an integer")
        sys.exit(1)

    if length < 4:
        print("length must be at least 4")
        sys.exit(1)

    seed = load_seed()
    password = derive_password(seed, domain, username, version, length)

    print("\nGenerated password:\n")
    print(password)


if __name__ == "__main__":
    main()
