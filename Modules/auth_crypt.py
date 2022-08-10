""" Built-in modules """
import sys
from binascii import Error
# External modules #
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
# Custom modules #
from Modules.utils import print_err


class AuthCrypt:
    """ Class to manage cryptographic components """
    def __init__(self):
        self._aesccm = b''
        self._nonce = b''
        self._db_key = b''
        self._secret_key = b''
        self._password = b''

    def get_plain_secret(self) -> bytes:
        """
        Decrypt the encrypted hash secret.

        :return:  Decrypted password hash.
        """
        try:
            # Decrypt hashed secret #
            plain = Fernet(self._secret_key).decrypt(self._password)

        # If invalid token or encoding error #
        except (InvalidToken, TypeError, Error) as err:
            print_err(f'Error occurred during fernet secret decryption: {err}', 2)
            sys.exit(3)

        return plain

    def decrypt_db_key(self, secret: str) -> bytes:
        """
        Decrypt the database key with aesccm authenticated.

        :param secret:  Encrypted password hash to be decrypted.
        :return:  Decrypted database key.
        """
        # Initialize AESCCM algo object #
        aesccm = AESCCM(self._aesccm)

        try:
            # Decrypt database Fernet key #
            plain = aesccm.decrypt(self._nonce, self._db_key, secret)

        # If authentication tag is invalid #
        except InvalidTag as err:
            print_err(f'Database key did not successfully decrypt: {err}', 2)
            sys.exit(4)

        return plain
