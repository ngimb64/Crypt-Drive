""" Built-in modules """
import binascii
import logging
import os
import re
import sqlite3
import sys
import time
from getpass import getpass
from io import StringIO
from pathlib import Path
from shutil import rmtree
from threading import BoundedSemaphore
# External Modules #
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from keyring import get_password
from keyring.errors import KeyringError
from pyfiglet import Figlet
# Custom Modules #
from Modules.db_handlers import DbConnectionHandler, db_error_query
from Modules.menu_functions import decryption, db_extract, db_store, import_key, share_keyset, \
                                   list_drive, list_storage, upload
from Modules.utils import component_handler, db_check, hd_crawl, logger, login_timeout, print_err, \
                          recycle_check, sys_lock


def main_menu(config: object):
    """
    Display command options and receives input on what command to execute.

    :param config:  The program configuration instance.
    :return:  Nothing
    """
    # Format program banner #
    custom_fig = Figlet(font='roman', width=100)

    # Clears screen per loop for clean display #
    while True:
        os.system(config.clear_cmd)
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
            upload(config)

        # Store data in storage database #
        elif prompt == 'store':
            db_store(config)

        # Extract data from storage db #
        elif prompt == 'extract':
            db_extract(config)

        # List cloud contents #
        elif prompt == 'ldrive':
            list_drive()

        # List storage database contents #
        elif prompt == 'lstore':
            list_storage(config)

        # Import public key #
        elif prompt == 'import':
            import_key(config)

        # Decrypt data in DecryptDock
        elif prompt == 'decrypt':
            decryption(config)

        # Share private key with user #
        elif prompt == 'share':
            share_keyset(config)

        # Exit the program #
        elif prompt == 'exit':
            print('\nExiting Utility ..')
            sys.exit(0)

        # View the encrypted error log #
        elif prompt == 'view':
            logger(config, None, operation='read', handler=None)

        # Improper input handling #
        else:
            print('\nImproper Input .. try again')

        time.sleep(2.5)


def start_check(config: object) -> bool:
    """
    Confirms program components are preset. If missing, component recovery is attempted. If that \
    fails results in the creation of a fresh set of components.

    :param config:  The program configuration instance.
    :return:  True/False boolean toggle on success/failure.
    """
    # If OS is Windows #
    if os.name == 'nt':
        # Check the recycling bin for missing items #
        config = recycle_check(config)
        # If all items were recovered #
        if not config.missing:
            return True

    # Attempt to recover list of missing items from hard drive #
    config = hd_crawl(config)

    # If hard drive recovery was not successful #
    if config.missing:
        # Iterate through missing list #
        for fail in config.missing:
            # If component is in independent of database & key-set #
            if fail in (config.dirs[1], config.dirs[3], config.dirs[4]):
                # Create folder #
                fail.mkdir(parents=True, exist_ok=True)
                config.missing.remove(fail)
            # If component is a essential component #
            else:
                # Reset the missing list #
                config.missing = []

                # Iterate through program component dirs #
                for path in config.dirs:
                    # If the directory exists #
                    if path.exists():
                        try:
                            # Delete dir and all contents #
                            rmtree(path)

                        # If error occurs recursively deleting dir #
                        except OSError as del_err:
                            # Print error, log, and exit #
                            print_err('Error deleting program dir for component reset: '
                                      f'{del_err}', 2)
                            logger(config, 'Error deleting program dir for component reset: '
                                           f'{del_err}', operation='write', handler='error')
                            sys.exit(4)

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

            # Create dirs, db tables, and keys #
            return component_handler(conf_obj, prompt)

        # If password keyring exists, but component files are missing #
        if conf_obj.missing:
            print('\nCryptographic key-set seem to exist but are missing .. '
                  f'attempting to recover\n{"*" * 77}')

            # Attempt to recover missing components #
            ret = start_check(conf_obj)
            # If unable to recover components essential to the key-set #
            if not ret:
                print_err('Unable to recover all missing components .. recreating key-set', 2.5)
                # Create dirs, db tables, and keys #
                return component_handler(conf_obj, prompt)

        # Check for database contents and set auth object #
        conf_obj = db_check(conf_obj, prompt.encode())
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
            self.re_path = re.compile(r'^[A-Z]:(?:\\[a-zA-Z\d_\"\' .,\-]{1,260})+')
        # If OS is Linux #
        else:
            self.clear_cmd = 'clear'
            self.re_path = re.compile(r'^(?:/[a-zA-Z\d_\"\' .,\-]{1,260})+')

        # Compile program regex #
        self.re_email = re.compile(r'[a-zA-Z\d._]{2,30}@[a-zA-Z\d_.]{2,15}\.[a-z]{2,4}$')
        self.re_user = re.compile(r'^[a-zA-Z\d._]{1,30}')
        self.re_pass = re.compile(r'^[a-zA-Z\d_!+$@&(]{12,40}')
        self.re_phone = re.compile(r'^\d{10}')
        self.re_dir = re.compile(r'^[a-zA-Z\d._]{1,30}')
        self.re_no_ext = re.compile(r'(?=[a-zA-Z\d])[^\\]{1,30}(?=\.)')
        self.re_win_dir = re.compile(r'(?=[a-zA-Z\d])[^\\]{1,30}(?=$)')
        self.re_rel_winpath = re.compile(r'(?<=\\)[a-zA-Z\d_.\\\-\'\"]{1,240}')
        self.re_rel_linpath = re.compile(r'(?<=/)[a-zA-Z\d_./\-\'\"]{1,240}')

        # Create string IO object for logging #
        self.log_stream = StringIO()
        # Current working directory #
        self.cwd = Path.cwd()
        # Configure program directories #
        self.dirs = (self.cwd / 'CryptDrive_Dbs',
                     self.cwd / 'CryptDrive_Import',
                     self.cwd / 'CryptDrive_Keys',
                     self.cwd / 'CryptDrive_Decrypt',
                     self.cwd / 'CryptDrive_Upload')
        # Command syntax and database tuple #
        self.db_name = (self.dirs[0] / 'crypt_storage.db',)
        self.db_tables = ('crypt_keys', 'crypt_storage')
        # Database access semaphore and connection reference #
        self.sema_lock = BoundedSemaphore(value=1)
        self.db_conn = None
        # Configure program cryptographic key paths #
        self.files = (self.dirs[2] / 'aesgcm.txt',
                      self.dirs[2] / 'nonce.txt',
                      self.dirs[2] / 'db_crypt.txt',
                      self.dirs[2] / 'secret_key.txt')
        self.meta_exts = ('.avi', '.doc', '.docm', '.docx', '.exe', '.gif',
                          '.jpg', '.jpeg', '.m4a', '.mp3', '.mp4', '.pdf',
                          '.png', '.pptx', '.rar', '.wav', '.wma', '.zip')
        self.log_name = self.cwd / 'crypt_log.log'
        # List to reference missing program components #
        self.missing = []

        # Iterate through the program dirs, dbs, and files #
        for item in (self.dirs + self.db_name + self.files):
            # If the current item does not exit #
            if not item.exists():
                # Add current item to missing list #
                self.missing.append(item)

        # Program cryptographic components #
        self.aesgcm = b''
        self.nonce = b''
        self.db_key = b''
        self.secret_key = b''
        self.password = b''
        self.has_keys = False

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

    def decrypt_db_key(self, secret: bytes) -> bytes:
        """
        Decrypt the database key with aesgcm authenticated.

        :param secret:  Encrypted password hash to be decrypted.
        :return:  Decrypted database key.
        """
        # Initialize AESGCM algo object #
        aesgcm = AESGCM(self.aesgcm)

        try:
            # Decrypt database Fernet key #
            plain = aesgcm.decrypt(self.nonce, self.db_key, secret)

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
                                    stream=config_obj.log_stream)

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
            # Acquire semaphore lock for db access #
            with config_obj.sema_lock:
                # Establish database connection in context manager #
                with DbConnectionHandler(config_obj.db_name[0]) as db_conn:
                    # Save reference to database connection in program config #
                    config_obj.db_conn = db_conn
                    # Call main menu #
                    main_menu(config_obj)

        # If keyboard interrupt is detected #
        except KeyboardInterrupt:
            print('\n\n* [EXIT] Ctrl + c detected .. exiting *')
            break

        # If error occurs acquiring semaphore lock #
        except ValueError as sema_err:
            # Print error, log, and continue #
            print_err('Semaphore error occurred attempting to acquire a database connection: '
                      f'{sema_err}', 2)
            logger(config_obj, 'Semaphore error occurred attempting to acquire a database '
                               f'connection: {sema_err}', operation='write', handler='error')
            continue

        # If database error occurs #
        except sqlite3.Error as db_err:
            # Look up database error, log, and loop #
            db_error_query(config_obj, db_err)
            continue

        # If unknown exception occurs #
        except Exception as err:
            # Print error, log, and loop #
            print_err('Unexpected exception occurred .. check log', 2)
            logger(config_obj, f'Exception occurred: {err}', operation='write', handler='exception')
            continue

    sys.exit(0)
