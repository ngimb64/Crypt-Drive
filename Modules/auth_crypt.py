""" Built-in modules """
import binascii
import sys
# External modules #
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
# Custom modules #
from Modules.utils import print_err


class AuthCrypt:
    """ Class to manage cryptographic components """
    def __init__(self):
        self.aesccm = b''
        self.nonce = b''
        self.db_key = b''
        self.secret_key = b''
        self.password = b''

    def get_plain_secret(self) -> bytes:
        """
        Decrypt the encrypted hash secret.

        :return:  Decrypted password hash.
        """
        try:
            # Decrypt hashed secret #
            plain = Fernet(self.secret_key).decrypt(self.password)

        # If invalid token or encoding error #
        except (binascii.Error, InvalidToken, TypeError, ValueError) as crypt_err:
            print_err(f'Error occurred during fernet secret decryption: {crypt_err}', 2)
            sys.exit(3)

        return plain

    def decrypt_db_key(self, secret: str) -> bytes:
        """
        Decrypt the database key with aesccm authenticated.

        :param secret:  Encrypted password hash to be decrypted.
        :return:  Decrypted database key.
        """
        # Initialize AESCCM algo object #
        aesccm = AESCCM(self.aesccm)

        try:
            # Decrypt database Fernet key #
            plain = aesccm.decrypt(self.nonce, self.db_key, secret)

        # If authentication tag is invalid #
        except (InvalidTag, ValueError) as crypt_err:
            print_err(f'Database key did not successfully decrypt: {crypt_err}', 2)
            sys.exit(4)

        return plain
