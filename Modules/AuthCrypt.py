# Built-in modules #
import sys
from binascii import Error

# External modules #
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

# Custom modules #
from Modules.Utils import PrintErr


"""
###############
# Class Index #
########################################################################################################################
AuthCrypt:
    __init__ - Initializes authentication object.
    GetPlainSecret - Decrypt the encrypted hash secret.
    DecryptDbKey - Decrypt the database key with aesccm authenticated.
########################################################################################################################
"""


class AuthCrypt:
    def __init__(self):
        self.aesccm = b''
        self.nonce = b''
        self.db_key = b''
        self.secret_key = b''
        self.password = b''

    def GetPlainSecret(self) -> bytes:
        """ Purpose:  Decrypt the encrypted hashed secret. """
        """ Returns:  Decrypted hashed secret. """
        try:
            # Decrypt hashed secret #
            plain = Fernet(self.secret_key).decrypt(self.password)

        # If invalid token or encoding error #
        except (InvalidToken, TypeError, Error) as err:
            PrintErr(f'Error occurred during fernet secret decryption: {err}', 2)
            sys.exit(3)

        return plain

    def DecryptDbKey(self, secret: str) -> bytes:
        """  Purpose:  Decrypt the database key with aesccm authenticated. """
        """ Returns:  Dcecrypted database key. """
        # Initialize AESCCM algo object #
        aesccm = AESCCM(self.aesccm)

        try:
            # Decrypt database Fernet key #
            plain = aesccm.decrypt(self.nonce, self.db_key, secret)

        # If authentication tag is invalid #
        except InvalidTag as err:
            PrintErr(f'Database key did not successfully decrypt: {err}', 2)
            sys.exit(4)

        return plain
