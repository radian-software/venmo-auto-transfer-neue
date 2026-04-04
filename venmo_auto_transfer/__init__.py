import base64
from datetime import datetime, timedelta
import functools
import hmac
import json
import os
import re
import sys
import time
from typing import Any, Callable, Tuple

import base58
import cryptography.hazmat.primitives.asymmetric.x25519 as crypto_x25519
import cryptography.hazmat.primitives.ciphers as crypto_ciphers
import cryptography.hazmat.primitives.ciphers.algorithms as crypto_algs
import cryptography.hazmat.primitives.ciphers.modes as crypto_modes
import cryptography.hazmat.primitives.padding as crypto_padding
import cryptography.hazmat.primitives.hashes as crypto_hashes
import cryptography.hazmat.primitives.hmac as crypto_hmac
import cryptography.hazmat.primitives.kdf.hkdf as crypto_hkdf
import vodozemac
import requests
import venmo_api
import venmo_auto_cashout


def base64_decode_unpadded(data: str) -> bytes:
    return base64.b64decode(data + "==", validate=False)


def base64_encode_unpadded(data: bytes) -> str:
    return base64.b64encode(data).rstrip(b"=").decode()


def get_matrix_token(hostname: str, user: str, secret: str) -> str:
    sig = hmac.HMAC(secret.encode(), user.encode(), "sha512").digest().hex()
    resp = requests.post(
        f"https://{hostname}/_matrix/client/r0/login",
        json={
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.user",
                "user": user,
            },
            "password": sig,
        },
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def release_matrix_token(hostname: str, token: str):
    resp = requests.post(
        f"https://{hostname}/_matrix/client/v3/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()


def get_secret_storage_key_info(hostname: str, user: str, token: str) -> Any:
    resp = requests.get(
        f"https://{hostname}/_matrix/client/v3/user/{user}/account_data/m.secret_storage.default_key",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    key_id = resp.json()["key"]
    resp = requests.get(
        f"https://{hostname}/_matrix/client/v3/user/{user}/account_data/m.secret_storage.key.{key_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    return {**resp.json(), "id": key_id}


def reduce_xor(vec: bytes) -> int:
    return functools.reduce(lambda x, y: x ^ y, list(vec))


def decode_security_key(key: str) -> bytes:
    vec = base58.b58decode(key.replace(" ", ""), alphabet=base58.BITCOIN_ALPHABET)
    assert vec[:2] == b"\x8b\x01", f"unexpected header {vec[:2]}"
    assert (
        reduce_xor(vec[:-1]) == vec[-1]
    ), f"bad checksum {reduce_xor(vec[:-1])} != {vec[-1]}"
    return vec[2:-1]


def verify_symmetric(enc: Any, key: bytes) -> None:
    # 10.13.1.1.1 https://spec.matrix.org/v1.11/client-server-api/#msecret_storagev1aes-hmac-sha2
    assert enc["algorithm"] == "m.secret_storage.v1.aes-hmac-sha2"
    hkdf = crypto_hkdf.HKDF(
        algorithm=crypto_hashes.SHA256(), length=64, salt=bytes(32), info=b""
    )
    full_key = hkdf.derive(key)
    aes_key, mac_key = full_key[:32], full_key[32:]
    encryptor = crypto_ciphers.Cipher(
        crypto_algs.AES256(aes_key), crypto_modes.CTR(base64_decode_unpadded(enc["iv"]))
    ).encryptor()
    encrypted = encryptor.update(bytes(32)) + encryptor.finalize()
    hmac = crypto_hmac.HMAC(mac_key, crypto_hashes.SHA256())
    hmac.update(encrypted)
    hmac.verify(base64_decode_unpadded(enc["mac"]))


def get_backup_key(hostname: str, token: str, key_info: Any) -> Any:
    resp = requests.get(
        f"https://{os.environ['MATRIX_HOSTNAME']}/_matrix/client/v3/user/{os.environ['MATRIX_USER_ID']}/account_data/m.megolm_backup.v1",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    return resp.json()["encrypted"][key_info["id"]]


def decrypt_symmetric(enc: Any, key: bytes, info: bytes) -> bytes:
    # 10.13.1.2.1 https://spec.matrix.org/v1.11/client-server-api/#msecret_storagev1aes-hmac-sha2-1
    hkdf = crypto_hkdf.HKDF(
        algorithm=crypto_hashes.SHA256(),
        length=64,
        salt=bytes(32),
        info=info,
    )
    full_key = hkdf.derive(key)
    aes_key, mac_key = full_key[:32], full_key[32:]
    hmac = crypto_hmac.HMAC(mac_key, crypto_hashes.SHA256())
    hmac.update(base64_decode_unpadded(enc["ciphertext"]))
    hmac.verify(base64_decode_unpadded(enc["mac"]))
    decryptor = crypto_ciphers.Cipher(
        crypto_algs.AES256(aes_key), crypto_modes.CTR(base64_decode_unpadded(enc["iv"]))
    ).decryptor()
    pt = (
        decryptor.update(base64_decode_unpadded(enc["ciphertext"]))
        + decryptor.finalize()
    )
    return pt


def get_session_keys(hostname: str, token: str) -> Tuple[bytes, Any]:
    resp = requests.get(
        f"https://{os.environ['MATRIX_HOSTNAME']}/_matrix/client/v3/room_keys/version",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    pubkey = resp.json()["auth_data"]["public_key"]
    assert resp.json()["algorithm"] == "m.megolm_backup.v1.curve25519-aes-sha2"
    backup_ver = resp.json()["version"]
    resp = requests.get(
        f"https://{os.environ['MATRIX_HOSTNAME']}/_matrix/client/v3/room_keys/keys?version={backup_ver}",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    return resp.json()["rooms"], base64_decode_unpadded(pubkey)


def choose_session_key(session_keys: Any, room: str, session_id: str) -> Any:
    return session_keys[room]["sessions"][session_id]["session_data"]


def decrypt_asymmetric(enc: Any, key: bytes, expected_pubkey: bytes) -> Any:
    privkey = crypto_x25519.X25519PrivateKey.from_private_bytes(key)
    assert privkey.public_key().public_bytes_raw() == expected_pubkey
    # 10.12.3.2.2 https://spec.matrix.org/v1.11/client-server-api/#backup-algorithm-mmegolm_backupv1curve25519-aes-sha2
    shared_secret = privkey.exchange(
        crypto_x25519.X25519PublicKey.from_public_bytes(
            base64_decode_unpadded(enc["ephemeral"])
        )
    )
    hkdf = crypto_hkdf.HKDF(
        algorithm=crypto_hashes.SHA256(),
        length=80,
        salt=bytes(32),
        info=b"",
    )
    full_key = hkdf.derive(shared_secret)
    aes_key, mac_key, aes_iv = full_key[:32], full_key[32:64], full_key[64:]
    hmac = crypto_hmac.HMAC(mac_key, crypto_hashes.SHA256())
    assert hmac.finalize()[:8] == base64_decode_unpadded(enc["mac"])
    decryptor = crypto_ciphers.Cipher(
        crypto_algs.AES256(aes_key), crypto_modes.CBC(aes_iv)
    ).decryptor()
    unpadder = crypto_padding.PKCS7(128).unpadder()
    return json.loads(
        unpadder.update(
            decryptor.update(base64_decode_unpadded(enc["ciphertext"]))
            + decryptor.finalize()
        )
        + unpadder.finalize()
    )


def get_latest_message(hostname: str, room: str, token: str) -> Any:
    resp = requests.get(
        f"https://{hostname}/_matrix/client/v3/rooms/{room}/messages?dir=b",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )
    resp.raise_for_status()
    msg = resp.json()["chunk"][0]
    return msg


def decrypt_olm(enc: str, session: Any) -> Any:
    return json.loads(
        vodozemac.InboundGroupSession.import_session(
            vodozemac.ExportedSessionKey(session["session_key"])
        )
        .decrypt(vodozemac.MegolmMessage.from_base64(enc))
        .plaintext
    )


def main():

    print("Reading envvars.")

    VENMO_EMAIL_ADDRESS = os.environ["VENMO_EMAIL_ADDRESS"]
    VENMO_PASSWORD = os.environ["VENMO_PASSWORD"]

    # Get device_id from logging into venmo in a web browser and
    # taking note of the POST https://account.venmo.com/api/auth
    # request, specifically the deviceId key in the response payload.
    VENMO_DEVICE_ID = os.environ["VENMO_DEVICE_ID"]

    MATRIX_HOSTNAME = os.environ["MATRIX_HOSTNAME"]
    MATRIX_ROOM_ID = os.environ["MATRIX_ROOM_ID"]
    MATRIX_SECURITY_KEY = os.environ["MATRIX_SECURITY_KEY"]
    MATRIX_SHARED_SECRET = os.environ["MATRIX_SHARED_SECRET"]
    MATRIX_USER_ID = os.environ["MATRIX_USER_ID"]

    TRANSACTIONS_DB = os.environ["TRANSACTIONS_DB"]

    print("Authenticating with Matrix.")

    matrix_token = get_matrix_token(
        MATRIX_HOSTNAME,
        MATRIX_USER_ID,
        MATRIX_SHARED_SECRET,
    )

    try:

        matrix_secret_storage_key_info = get_secret_storage_key_info(
            MATRIX_HOSTNAME, MATRIX_USER_ID, matrix_token
        )
        matrix_secret_storage_key = decode_security_key(MATRIX_SECURITY_KEY)
        verify_symmetric(matrix_secret_storage_key_info, matrix_secret_storage_key)

        matrix_backup_key_enc = get_backup_key(
            MATRIX_HOSTNAME, matrix_token, matrix_secret_storage_key_info
        )
        matrix_backup_key = base64_decode_unpadded(
            decrypt_symmetric(
                matrix_backup_key_enc, matrix_secret_storage_key, b"m.megolm_backup.v1"
            ).decode()
        )

        matrix_session_keys, matrix_session_encryption_public_key = get_session_keys(
            MATRIX_HOSTNAME, matrix_token
        )

        def get_otp(start_time: datetime):

            print("Checking for SMS OTP.")

            while datetime.now() - start_time < timedelta(minutes=3):

                last_message_enc = get_latest_message(
                    MATRIX_HOSTNAME, MATRIX_ROOM_ID, matrix_token
                )

                if (
                    datetime.fromtimestamp(last_message_enc["origin_server_ts"] / 1000)
                    < start_time
                ):
                    print("Waiting 2 seconds to check again for SMS OTP.")
                    time.sleep(2)
                    continue

                matrix_session_key_enc = choose_session_key(
                    matrix_session_keys,
                    MATRIX_ROOM_ID,
                    last_message_enc["content"]["session_id"],
                )
                matrix_session_key = decrypt_asymmetric(
                    matrix_session_key_enc,
                    matrix_backup_key,
                    matrix_session_encryption_public_key,
                )

                last_message = decrypt_olm(
                    last_message_enc["content"]["ciphertext"], matrix_session_key
                )

                text = last_message["content"]["body"]
                if match := re.match(r"Venmo here! .* Code: ([0-9]+)", text):
                    print("Got SMS OTP.")
                    return match.group(1)

                raise RuntimeError(f"Got unexpected message: {repr(text)}")

            raise RuntimeError("Timed out waiting for OTP SMS")

        start_time = datetime.now()
        venmo_api.AuthenticationApi._AuthenticationApi__ask_user_for_otp_password = (
            lambda cls: get_otp(start_time)
        )

        print("Getting Venmo token.")

        venmo_token = venmo_api.Client.get_access_token(
            VENMO_EMAIL_ADDRESS, VENMO_PASSWORD, VENMO_DEVICE_ID
        )

        print("Running Venmo cashout.")

        sys.argv[1:] = [
            f"--token={venmo_token}",
            f"--transaction-db={TRANSACTIONS_DB}",
            "--allow-remaining",
        ]
        venmo_auto_cashout.run_cli()

    finally:

        print("Deauthenticating from Matrix.")
        release_matrix_token(MATRIX_HOSTNAME, matrix_token)
