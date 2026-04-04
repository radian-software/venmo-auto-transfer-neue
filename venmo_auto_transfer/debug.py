import dotenv

dotenv.load_dotenv()

from venmo_auto_transfer import *

MATRIX_HOSTNAME = os.environ["MATRIX_HOSTNAME"]
MATRIX_ROOM_ID = os.environ["MATRIX_ROOM_ID"]
MATRIX_SECURITY_KEY = os.environ["MATRIX_SECURITY_KEY"]
MATRIX_SHARED_SECRET = os.environ["MATRIX_SHARED_SECRET"]
MATRIX_USER_ID = os.environ["MATRIX_USER_ID"]

matrix_token = get_matrix_token(
    MATRIX_HOSTNAME,
    MATRIX_USER_ID,
    MATRIX_SHARED_SECRET,
)
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

last_message_enc = get_latest_message(MATRIX_HOSTNAME, MATRIX_ROOM_ID, matrix_token)

matrix_session_key_enc = choose_session_key(
    matrix_session_keys, MATRIX_ROOM_ID, last_message_enc["content"]["session_id"]
)
matrix_session_key = decrypt_asymmetric(
    matrix_session_key_enc, matrix_backup_key, matrix_session_encryption_public_key
)

last_message = decrypt_olm(
    last_message_enc["content"]["ciphertext"], matrix_session_key
)
