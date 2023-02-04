""" Built-in modules """
import binascii
import logging
import os
import re
import sys
import time
from getpass import getpass
from io import StringIO
from pathlib import Path
# External Modules #
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from keyring import get_password
from keyring.errors import KeyringError
from pyfiglet import Figlet
# Custom Modules #
from Modules.db_handlers import db_contents, db_delete, db_insert, db_keys, db_retrieve, \
                                db_storage, db_store
from Modules.menu_functions import decryption, db_extract, db_store, import_key, key_share, \
                                   list_drive, list_storage, upload
from Modules.utils import CompiledRegex, component_handler, db_check, hd_crawl, logger, \
                          login_timeout, print_err, query_handler, recycle_check, secure_delete, \
                          sys_lock


def main_menu(db_tuple: tuple, auth_obj, clear_syntax: str):
    """
    Display command options and receives input on what command to execute.

    :param db_tuple:  The database name tuple.
    :param auth_obj:  The authentication instance.
    :param clear_syntax:  The command syntax to clear display.
    :return:  Nothing
    """
    # Compile various regexes as grouped instance #
    regex_obj = CompiledRegex()
    # Format program banner #
    custom_fig = Figlet(font='roman', width=100)

    # Clears screen per loop for clean display #
    while True:
        os.system(clear_syntax)
        # Print the program banner #
        print(custom_fig.renderText('Crypt Drive'))
        print('''
    @==============@
    |   Commands   |
    #=========================#-----------\\
    |   upload  =>  upload to drive        \\
    |   store   =>  store in storage db     |
    |   extract =>  extract from storage db |
    |   ldrive  =>  list drive contents     |
    |   lstore  =>  list storage db data    |
    |   import  =>  import key              |
    |   decrypt =>  decrypt data            |
    |   share   =>  share decrypt keys      |
    |   exit    =>  exit utility            |
    |   view    =>  view error log          |
    @=======================================@
    \n''')
        prompt = input('$#==+> ')

        # Upload encrypted data #
        if prompt == 'upload':
            upload(db_tuple, auth_obj, regex_obj.re_path)

        # Store data in storage database #
        elif prompt == 'store':
            db_store(db_tuple, auth_obj, regex_obj.re_path)

        # Extract data from storage db #
        elif prompt == 'extract':
            db_extract(db_tuple, auth_obj, regex_obj.re_path, regex_obj.re_dir)

        # List cloud contents #
        elif prompt == 'ldrive':
            list_drive()

        # List storage database contents #
        elif prompt == 'lstore':
            list_storage(db_tuple[1], auth_obj)

        # Import public key #
        elif prompt == 'import':
            import_key(db_tuple[0], auth_obj, regex_obj.re_user, regex_obj.re_pass)

        # Decrypt data in DecryptDock
        elif prompt == 'decrypt':
            decryption(db_tuple[0], auth_obj, regex_obj.re_user, regex_obj.re_path)

        # Share private key with user #
        elif prompt == 'share':
            key_share(db_tuple[0], auth_obj, regex_obj.re_email,
                      regex_obj.re_pass, regex_obj.re_phone)

        # Exit the program #
        elif prompt == 'exit':
            print('\nExiting Utility ..')
            sys.exit(0)

        # View the encrypted error log #
        elif prompt == 'view':
            logger(None, auth_obj, operation='read', handler=None)

        # Improper input handling #
        else:
            print('\nImproper Input .. try again')

        time.sleep(2.5)


def start_check(db_name: str) -> bool:
    """
    Confirms program components are preset. If missing, component recovery is attempted. If that \
    fails results in the creation of a fresh set of components.

    :param db_name:  The storage database query syntax.
    :return:  True/False boolean toggle on success/failure.
    """
    # If OS is Windows #
    if os.name == 'nt':
        # Check the recycling bin for missing items #
        misses = recycle_check()

        # If all items were recovered #
        if not misses:
            return True
    # If OS is Linux #
    else:
        misses = global_vars.MISSING

    # Attempt to recover list of missing items from hard drive #
    failures = hd_crawl(misses)

    # If hard drive recovery was not successful #
    if failures:
        # For component in list of failures #
        for fail in failures:
            # If component is in independent of key-set #
            if fail in (global_vars.DIRS[1], global_vars.DIRS[2],
                        global_vars.DIRS[4], global_vars.DBS[1]):
                # If fail item is folder #
                if fail in global_vars.DIRS:
                    # Create folder #
                    os.mkdir(fail)
                # If fail item is storage db #
                else:
                    # Create storage database #
                    query = global_vars.db_storage(db_name)
                    query_handler(db_name, query, None, operation='create')
            # If component is in the essential key-set #
            else:
                # Delete component files #
                for item in global_vars.FILES + global_vars.DBS:
                    if global_vars.file_check(item):
                        secure_delete(item)

                return False

    return True


def password_input(conf_obj: object) -> object:
    """
    Receive password input from user, verify with Argon2 hashing algorithm or create new password \
    in none exist.

    :return:  Populated program configuration instance.
    """
    count = 0
    # Initialize password hashing algorithm #
    pass_algo = PasswordHasher()

    # Clear display per iteration #
    while True:
        os.system(conf_obj.clear_cmd)

        # If user maxed attempts (3 sets of 3 failed password attempts) #
        if count == 12:
            # Attempt to lock system down and exit #:
            sys_lock()

        # After three password failures #
        if count in (3, 6, 9):
            # Display login timeout for interval of 60 seconds #
            login_timeout()

        # Prompt user for input #
        prompt = getpass('\n\nEnter your unlock password or password for creating keys: ')

        # Check input syntax & length #
        if not re.search(conf_obj.re_pass, prompt):
            print_err('Invalid password format .. minimum of 12 numbers,'
                     ' letters, _!+$@&( special characters needed', 2)
            count += 1
            continue

        # Attempt to retrieve password hash from key ring #
        try:
            keyring_hash = get_password('CryptDrive', 'CryptUser')

        # If encrypted password hash is not set in credential manager #
        except KeyringError:
            # Confirm users password before setting #
            prompt2 = getpass('Enter password again to confirm: ')

            # If input fails regex validation #
            if not re.search(conf_obj.re_pass, prompt2):
                print_err('Invalid password format .. numbers, letters,'
                         ' _!+$@&( special characters allowed', 2)
                count += 1
                continue

            # If the 2nd confirmation input does not match original #
            if prompt != prompt2:
                print_err('Two different passwords were entered .. try again', 2)
                count += 1
                continue

            # Create dirs, dbs, and keys #
            conf_obj = component_handler(conf_obj, prompt)

            return conf_obj

        # If password keyring exists, but component files are missing #
        if conf_obj.is_missing:
            print('\nCryptographic key-set seems to exist but is missing in '
                  'program directory .. attempting to recover components\n'
                  f'{"*" * 109}\n')

            # Attempt to recover missing components #
            ret = start_check(conf_obj.dbs[1])
            # If unable to recover components essential to the key-set #
            if not ret:
                print_err('Unable to recover all missing components .. recreating key-set', 2.5)
                # Create dirs, dbs, and keys #
                conf_obj = component_handler(conf_obj, prompt)

                return conf_obj

            conf_obj.is_missing = False

        # Check for database contents and set auth object #
        conf_obj = db_check(db_tuple[0], prompt.encode(), conf_obj)
        # Decrypt the password #
        check_pass = conf_obj.get_plain_secret()

        # Decrypt the keyring hash #
        try:
            plain_keyring = Fernet(conf_obj.secret_key).decrypt(keyring_hash.encode())

        # If error occurs during decryption #
        except (InvalidToken, TypeError, binascii.Error) as fern_err:
            print_err(f'Error occurred during fernet secret decryption: {fern_err}', 2)
            sys.exit(3)

        # Verify input by comparing keyring hash against algo #
        try:
            pass_algo.verify(plain_keyring, check_pass)

        # If users input does not match hashed keyring password #
        except (VerifyMismatchError, InvalidHash):
            print_err('Input does not match password hash', 2)
            count += 1
            continue

        return conf_obj


class ProgramConfig:
    """
    Configuration class to hold program compiled regex, paths, and other related components.
    """
    def __init__(self):
        # If OS is Windows #
        if os.name == 'nt':
            self.clear_cmd = 'cls'
        # If OS is Linux #
        else:
            self.clear_cmd = 'clear'

        # Compile program regex #
        self.re_pass = re.compile(r'^[a-zA-Z\d_!+$@&(]{12,40}')

        # Command syntax and database tuple #
        self.dbs = ('crypt_keys', 'crypt_storage')
        self.db_conns = []
        # Current working directory #
        self.cwd = Path.cwd()
        # Create string IO object for logging #
        self.LOG_STREAM = StringIO()
        # Configure program directories #
        self.dirs = (self.cwd / 'CryptDbs', self.cwd / 'CryptImport', self.cwd / 'CryptKeys',
                     self.cwd / 'DecryptDock', self.cwd / 'UploadDock')
        # Configure program database #
        self.dbs = (self.cwd / 'CryptDbs' / 'crypt_keys.db',
                    self.cwd / 'CryptDbs' / 'crypt_storage.db')
        # Configure program file paths #
        self.files = (self.cwd / 'CryptKeys' / 'aesgcm.txt',
                      self.cwd / 'CryptKeys' / 'nonce.txt',
                      self.cwd / 'CryptKeys' / 'db_crypt.txt',
                      self.cwd / 'CryptKeys' / 'secret_key.txt')
        # List to reference missing program components #
        self.missing = []

        # Iterate through the program dirs, dbs, and files #
        for item in (self.dirs + self.dbs + self.files):
            # If the current item does not exit #
            if not item.exists():
                # Add current item to missing list #
                self.missing.append(item)

        # If the program is missing components #
        if self.missing:
            self.is_missing = True
        # If all components are present #
        else:
            self.is_missing = False

        # Program cryptographic components #
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
            sys.exit(5)

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
            sys.exit(6)

        return plain


if __name__ == '__main__':
    try:
        # Initialize the program configuration class #
        config_obj = ProgramConfig()
        # User password authentication login #
        config_obj = password_input(config_obj)
        # Initialize logging facilities #
        logging.basicConfig(format='%(asctime)s %(lineno)4d@%(filename)-19s[%(levelname)s]>>  '
                                   '%(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG,
                                    stream=config_obj.LOG_STREAM)

    # If keyboard interrupt is detected #
    except KeyboardInterrupt:
        print('\n\n* [EXIT] Ctrl + c detected .. exiting *')
        sys.exit(0)

    # If unknown exception occurs #
    except Exception as err:
        print_err(f'Unknown error occurred in program start up: {err}', 2)
        sys.exit(1)

    # Main menu exception handled loop #
    while True:
        try:
            main_menu(dbs, auth, CMD)

        # If keyboard interrupt is detected #
        except KeyboardInterrupt:
            print('\n\n* [EXIT] Ctrl + c detected .. exiting *')

        # If unknown exception occurs #
        except Exception as err:
            print_err('Unexpected exception occurred .. check log', 2)
            logger(f'Exception occurred: {err}', auth, operation='write', handler='exception')
            continue

    sys.exit(0)
