# pylint: disable=E1101
""" Built-in modules """
import ctypes
import errno
import os
import logging
import re
import shlex
import shutil
import smtplib
import sqlite3
import sys
import time
from base64 import b64encode, b64decode
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from subprocess import Popen, SubprocessError, TimeoutExpired, CalledProcessError
from threading import BoundedSemaphore
from sqlite3 import Error, DatabaseError, IntegrityError, ProgrammingError, OperationalError, \
                    NotSupportedError
# External Modules #
import keyring
from argon2 import PasswordHasher
from exif import Image
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
# If OS is Windows #
if os.name == 'nt':
    from winshell import undelete, x_not_found_in_recycle_bin
# Custom Modules #
import Modules.globals as global_vars


def cha_init(key: bytes, nonce: bytes) -> Cipher:
    """
    Initializes the ChaCh20 algorithm object.

    :param key:  ChaCha20 key.
    :param nonce:  ChaCha20 nonce.
    :return:  Initialized ChaCha20 cipher instance.
    """
    # Initialize ChaCha20 encryption algo #
    algo = algorithms.ChaCha20(key, nonce)
    # Return the initialized ChaCha20 cipher object #
    return Cipher(algo, mode=None)


def cha_decrypt(auth_obj: object, db_name: str):
    """
    Retrieve ChaCha components from Keys db, decoding and decrypting them.

    :param auth_obj:  The authentication instance.
    :param db_name:  Keys database name.
    :return:  The decrypted ChaCha20 key and nonce or prints message on error.
    """
    # Get the decrypted database key #
    db_key = get_database_comp(auth_obj)
    # Attempt to Retrieve the upload key and nonce from Keys db #
    key_call, nonce_call = fetch_upload_comps(db_name, 'upload_key', 'upload_nonce', auth_obj)

    # If decrypt key doesn't exist in db #
    if not key_call or not nonce_call:
        return print_err('Database missing decrypt component ..'
                        ' exit and restart program to fix issue', 2)

    # Decrypt key & nonce #
    decrypt_key = decrypt_db_data(db_key, key_call[1])
    decrypt_nonce = decrypt_db_data(db_key, nonce_call[1])

    return decrypt_key, decrypt_nonce


class CompiledRegex:
    """ Class for grouping numerous compiled regex. """
    # If OS is Windows #
    if os.name == 'nt':
        re_path = re.compile(r'^[A-Z]:(?:\\[a-zA-Z\d_\"\' .,\-]{1,260})+')
    # If OS is Linux #
    else:
        re_path = re.compile(r'^(?:/[a-zA-Z\d_\"\' .,\-]{1,260})+')

    re_email = re.compile(r'[a-zA-Z\d._]{2,30}@[a-zA-Z\d_.]{2,15}\.[a-z]{2,4}$')
    re_user = re.compile(r'^[a-zA-Z\d._]{1,30}')
    re_pass = re.compile(r'^[a-zA-Z\d_!+$@&(]{12,30}')
    re_phone = re.compile(r'^\d{10}')
    re_dir = re.compile(r'^[a-zA-Z\d._]{1,30}')


def component_handler(db_tuple: tuple, user_input: str, auth_obj: object) -> object:
    """
    Creates various dir, db, and key components required for program operation.

    :param db_tuple:  Database name tuple.
    :param user_input:  User input secret.
    :param auth_obj:  The authentication instance.
    :return:  Populated authentication instance.
    """
    # Create any missing dirs #
    create_dirs()
    # Create database components #
    create_databases(db_tuple)
    # Create fresh cryptographic key set #
    return make_keys(db_tuple[0], user_input.encode(), auth_obj)


def create_databases(dbs: tuple):
    """
    Creates database components.

    :param dbs:  Database name tuple.
    :return:  Nothing
    """
    # Iterate through db tuple #
    for db_name in dbs:
        if db_name == 'crypt_keys':
            query = global_vars.db_keys(db_name)
        elif db_name == 'crypt_storage':
            query = global_vars.db_storage(db_name)
        else:
            continue

        query_handler(db_name, query, None, operation='create')


def create_dirs():
    """
    Creates program component directories.

    :return:  Nothing
    """
    # Iterate through folders #
    for directory in global_vars.DIRS:
        # If folder is missing #
        if directory in global_vars.MISSING:
            # Create missing folder #
            os.mkdir(directory)


def data_copy(source: str, dest: str):
    """
    Copies data from source to destination.

    :param source:  The source path of the item to be copied.
    :param dest:  The destination path where the item will be copied.
    :return:  Nothing
    """
    try:
        # Copy file, modify if already exists #
        shutil.copy(source, dest)

    # If file already exists #
    except (shutil.Error, OSError):
        pass

    # Delete source file #
    secure_delete(source)


def db_check(db_name: str, secret: bytes, auth_obj: object) -> object:
    """
    Checks the upload contents within the keys database and populates authentication object.

    :param db_name:  Keys database name.
    :param secret:  User input password to be confirmed.
    :param auth_obj:  The authentication instance.
    :return:  Populated authentication object.
    """
    # Load AESCCM decrypt components #
    key = file_handler(global_vars.FILES[0], 'rb', None, operation='read')
    nonce = file_handler(global_vars.FILES[1], 'rb', None, operation='read')
    crypt = file_handler(global_vars.FILES[2], 'rb', None, operation='read')
    secret_key = file_handler(global_vars.FILES[3], 'rb', None, operation='read')
    aesccm = AESCCM(key)

    # Unlock the local database key #
    try:
        db_key = aesccm.decrypt(nonce, crypt, secret)

    # If authentication tag is invalid #
    except (InvalidTag, TypeError, ValueError):
        print_err('Incorrect unlock password entered', 2)
        sys.exit(4)

    # Encrypt the input password #
    crypt_secret = Fernet(secret_key).encrypt(secret)

    # Populate the authentication object #
    auth_obj.aesccm = key
    auth_obj.nonce = nonce
    auth_obj.db_key = crypt
    auth_obj.secret_key = secret_key
    auth_obj.password = crypt_secret

    # Retrieve upload key from database #
    query = global_vars.db_retrieve(db_name, 'upload_key')
    upload_call = query_handler(db_name, query, None, operation='fetchone')

    # Retrieve nonce from database #
    query = global_vars.db_retrieve(db_name, 'upload_nonce')
    nonce_call = query_handler(db_name, query, None, operation='fetchone')

    # If the upload key call fails #
    if not upload_call or not nonce_call:
        # Display error and ensure it is being fixed #
        print_err('Database missing upload component .. creating new key & upload to db\n'
                 'Data will need to be re uploaded with new key otherwise decryption will fail', 2)

        if not upload_call:
            print('Creating new upload key ..')
            # Recreate 32 byte upload key and store to keys database #
            key_recreate(db_key, 32, db_name, 'upload_key')

        if not nonce_call:
            print('Creating new upload nonce')
            # Recreate 16 byte upload nonce and store to keys database #
            key_recreate(db_key, 16, db_name, 'upload_nonce')

    else:
        # Confirm retrieved upload key/nonce properly decode & decrypt #
        _ = decrypt_db_data(db_key, upload_call[1])
        _ = decrypt_db_data(db_key, nonce_call[1])

    # Return the populated auth object #
    return auth_obj


def decrypt_db_data(decrypted_key: bytes, crypt_data: bytes) -> bytes:
    """
    Decodes and decrypts database base64 cipher data.

    :param decrypted_key:  Decrypted Fernet key.
    :param crypt_data:  Cipher data to be decrypted by decrypt key.
    :return:  Decrypted cipher data.
    """
    # Decode base64 encoding on stored data #
    decoded_data = b64decode(crypt_data)

    try:
        # Decrypt decoded cipher data #
        plain_data = Fernet(decrypted_key).decrypt(decoded_data)

    # If invalid token or encoding error #
    except (InvalidToken, TypeError, Error) as err:
        print_err(f'Error occurred during fernet data decryption: {err}', 2)
        sys.exit(7)

    # Return decrypted data #
    return plain_data


def dir_recover(items: list, folder: str, curr_folder: str) -> list:
    """
    Iterates through list of passed in dirs and checks to see if current folder is the same name \
    to static assignment.

    :param items:  List of items attempting to be recovered.
    :param folder:  The folder of the current iteration of os walk procedure.
    :param curr_folder:  The path to the current iteration folder to be recovered.
    :return:  Updated items list of missing components.
    """
    # Iterate through passed in missing list #
    for item in items:
        # If the folder and item are CryptDbs #
        if folder == item == 'CryptDbs':
            # Copy and delete source folder #
            data_copy(curr_folder, global_vars.DIRS[0])
            print(f'Folder: {item} recovered')
            # Remove recovered item from missing list #
            items.remove(item)
            break

        # If the folder and item are CryptImport #
        if folder == item == 'CryptImport':
            # Copy and delete source folder #
            data_copy(curr_folder, global_vars.DIRS[1])
            print(f'Folder: {item} recovered')
            # Remove recovered item from missing list #
            items.remove(item)
            break

        # If the folder and item are CryptKeys #
        if folder == item == 'CryptKeys':
            # Copy and delete source folder #
            data_copy(curr_folder, global_vars.DIRS[2])
            print(f'Folder: {item} recovered')
            # Remove recovered item from missing list #
            items.remove(item)
            break

        # If the folder and item are DecryptDock #
        if folder == item == 'DecryptDock':
            # Copy and delete source folder #
            data_copy(curr_folder, global_vars.DIRS[3])
            print(f'Folder: {item} recovered')
            # Remove recovered item from missing list #
            items.remove(item)
            break

        # If the folder and item are UploadDock #
        if folder == item == 'UploadDock':
            # Copy and delete source folder #
            data_copy(curr_folder, global_vars.DIRS[4])
            print(f'Folder: {item} recovered')
            # Remove recovered item from missing list #
            items.remove(item)
            break

    return items


def encrypt_db_data(decrypted_key: bytes, plain_data: bytes) -> str:
    """
    Encrypts and encodes plain data for database.

    :param decrypted_key:  Decrypted Fernet key.
    :param plain_data:  Encoded plain text data to be encrypted.
    :return:  Base64 encoded encrypted data as string.
    """
    try:
        # Encrypt the plain text data #
        crypt_data = Fernet(decrypted_key).encrypt(plain_data)

    # If invalid token or encoding error #
    except (InvalidToken, TypeError, Error) as err:
        print_err(f'Error occurred during fernet data decryption: {err}', 2)
        sys.exit(8)

    # Return encrypted data in base64 format #
    return b64encode(crypt_data).decode()


def error_query(err_path: str, err_mode: str, err_obj: object):
    """
    Looks up the errno message to get description.

    :param err_path:  File path where the error occurred.
    :param err_mode:  File mode when the error occurred.
    :param err_obj:  Error message instance.
    :return:  Nothing
    """
    # If file does not exist #
    if err_obj.errno == errno.ENOENT:
        print_err(f'{err_path} does not exist', 2)

    # If the file does not have read/write access #
    elif err_obj.errno == errno.EPERM:
        print_err(f'{err_path} does not have permissions for {err_mode} file mode,'
                 ' if file exists confirm it is closed', 2)

    # File IO error occurred #
    elif err_obj.errno == errno.EIO:
        print_err(f'IO error occurred during {err_mode} mode on {err_path}', 2)

    # If other unexpected file operation occurs #
    else:
        print_err(f'Unexpected file operation occurred accessing {err_path}: {err_obj.errno}', 2)


def fetch_upload_comps(db_name: str, key_name: str, nonce_name: str, auth_obj: object) -> tuple:
    """
    Retrieves upload components from keys database.

    :param db_name:  Keys database name.
    :param key_name:  Name of key to be retrieved.
    :param nonce_name:  Name of nonce to be retrieved.
    :param auth_obj:  The authentication instance.
    :return:
    """
    # Retrieve decrypt key from database #
    query = global_vars.db_retrieve(db_name, key_name)
    decrypt_query = query_handler(db_name, query, auth_obj, operation='fetchone')

    # Retrieve nonce from database #
    query = global_vars.db_retrieve(db_name, nonce_name)
    nonce_query = query_handler(db_name, query, auth_obj, operation='fetchone')

    # Return fetched query results #
    return decrypt_query, nonce_query


def file_handler(filename: str, mode: str, auth_obj: object, operation=None, data=None):
    """
    Error validated file handler for read and write operations.

    :param filename:  Name of file where the operation will be performed.
    :param mode:  File operation mode that will be performed on file.
    :param auth_obj:  The authentication instance.
    :param operation:  Toggle to specify file read/write operation.
    :param data:  Input data to be written to file.
    :return:
    """
    count, sleep_time = 0, 1

    if mode in ('rb', 'wb'):
        encode = None
    else:
        encode = 'utf-8'

    while True:
        # If loop is past first iteration #
        if count > 0:
            # Extend sleep time by a second #
            sleep_time += 1

        try:
            with open(filename, mode, encoding=encode) as file:
                # If read operation was specified #
                if operation == 'read':
                    return file.read()

                # If write operation was specified #
                if operation == 'write':
                    return file.write(data)

                # If improper operation specified #
                print_err('File IO Error: Improper file operation attempted', 2)
                # If password is set #
                if global_vars.HAS_KEYS:
                    # Log error #
                    logger('File IO Error: Improper file operation attempted\n\n',
                           auth_obj, operation='write', handler='error')
                break

        # If error occurs during file operation #
        except (IOError, FileNotFoundError, OSError) as err:
            # Look up file error #
            error_query(filename, mode, err)

            # If password is set #
            if global_vars.HAS_KEYS:
                logger(f'File IO Error: {err}\n\n', auth_obj, operation='write', handler='error')

            # If three consecutive IO errors occur #
            if count == 3:
                print_err('Maximum consecutive File IO errors detected ..'
                         ' check log & contact support', None)
                sys.exit(9)

            time.sleep(sleep_time)
            count += 1

    return None


def file_recover(file: str, curr_file: str, items: list) -> list:
    """
    Checks to see if current iteration of os walk is the file to be recovered.

    :param file:  The name of the file attempted to be recovered.
    :param curr_file:  The path to the current file attempted to be recovered.
    :param items:  The list of missing components.
    :return:  Updated items list of missing components.
    """
    # Iterate through list of missing components #
    for item in items:
        # If file is text #
        if file.endswith('txt'):
            # If file is one of the key components #
            if file in ('aesccm.txt', 'nonce.txt', 'db_crypt.txt', 'secret_key.txt'):
                # If OS is Windows #
                if os.name == 'nt':
                    dest_file = f'{global_vars.DIRS[2]}\\{file}'
                # If OS is Linux #
                else:
                    dest_file = f'{global_vars.DIRS[2]}/{file}'

                # Copy and delete source file #
                data_copy(curr_file, dest_file)
                print(f'File: {item}.txt recovered')
                # Remove recovered item from missing list #
                items.remove(item)

        # If file is database #
        else:
            if file in ('crypt_keys.db', 'crypt_storage.db'):
                # If OS is Windows #
                if os.name == 'nt':
                    dest_file = f'{global_vars.DIRS[0]}\\{file}'
                # If OS is Linux #
                else:
                    dest_file = f'{global_vars.DIRS[0]}/{file}'

                # Copy and delete source file #
                data_copy(curr_file, dest_file)
                print(f'File: {item}.db recovered')
                # Remove recovered item from missing list #
                items.remove(item)

    return items


def get_database_comp(auth_obj: object) -> bytes:
    """
    Unlock and retrieve database cryptography component.

    :param auth_obj:  The authentication instance.
    :return:  The decrypted database decryption key.
    """
    # Decrypt the password #
    plain = auth_obj.get_plain_secret()
    # Decrypt the local database key #
    return auth_obj.decrypt_db_key(plain)


def hd_crawl(items: list) -> list:
    """
    Recursive hard drive crawler for recovering missing components.

    :param items:  List of missing item(s) to be recovered.
    :return:  Boolean True/False whether operation was success/fail.
    """
    # If OS is Windows #
    if os.name == 'nt':
        crawl_path = 'C:\\Users'
    # If OS is Linux #
    else:
        crawl_path = '\\home'

    # Crawl through user directories #
    for dir_path, dir_names, file_names in os.walk(crawl_path, topdown=True):
        # If there are no recovery items left #
        if not items:
            break

        # If there are folders in the missing list #
        if not items[0].endswith('.db') and not items[0].endswith('.txt'):
            # Iterate through folders in current dir #
            for folder in dir_names:
                # If there are no more folders in the missing list #
                if items[0].endswith('.db') and items[0].endswith('.txt') or not items:
                    break

                # If OS is Windows #
                if os.name == 'nt':
                    curr_folder = f'{dir_path}\\{folder}'
                # If OS is Linux #
                else:
                    curr_folder = f'{dir_path}/{folder}'

                # Iterate through list of missing attempts
                # and attempt to match dir to recover #
                items = dir_recover(items, folder, curr_folder)

        # Iterate through files in current dir #
        for file in file_names:
            # If OS is Windows #
            if os.name == 'nt':
                curr_file = f'{dir_path}\\{file}'
            # If OS is Linux #
            else:
                curr_file = f'{dir_path}/{file}'

            # Iterate through list of missing attempts
            # and attempt to match file to recover #
            items = file_recover(file, curr_file, items)

    return items


def key_recreate(db_key: bytes, key_size: int, db_name: str, store_comp: str):
    """
    Recreates key or nonce and insert them back into param db_name database named as store_comp.

    :param db_key:  The Fernet key to encrypt recreated keys before storing them.
    :param key_size:  The size of the key/nonce size to be recreated and stored.
    :param db_name:  The database name where the keys will be stored.
    :param store_comp:  The name of key that will be stored in the database.
    :return:
    """
    # Create new encrypted upload key #
    crypt_comp = Fernet(db_key).encrypt(os.urandom(key_size))
    # Base64 encode encrypted upload key for db storage #
    encoded_comp = b64encode(crypt_comp)

    # Send upload key to key database #
    query = global_vars.db_insert(db_name, store_comp, encoded_comp.decode('utf-8'))
    query_handler(db_name, query, None)


def logger(msg: str, auth_obj: object, operation=None, handler=None):
    """
    Encrypted logging system.

    :param msg:  Message to be logged.
    :param auth_obj:  The authentication instance.
    :param operation:  Log operation to be performed.
    :param handler:  Logging level handler.
    :return:  Nothing
    """
    text = None

    # If OS is Windows #
    if os.name == 'nt':
        log_name = f'{global_vars.CWD}\\cryptLog.log'
    # If OS is Linux #
    else:
        log_name = f'{global_vars.CWD}/cryptLog.log'

    # Decrypt the password #
    plain = auth_obj.get_plain_secret()
    # Decrypt the local database key #
    db_key = auth_obj.decrypt_db_key(plain)

    # If read operation and log file exists #
    if operation == 'read' and global_vars.file_check(log_name):
        # Get log file size in bytes #
        log_size = os.stat(log_name).st_size

        # If log has data in it #
        if log_size > 0:
            # Read the encrypted log data #
            crypt = file_handler(log_name, 'rb', auth_obj, operation='read')
            # Decrypt the encrypted log data #
            plain = decrypt_db_data(db_key, crypt)
            # Decode byte data #
            text = plain.decode()
    # If log file does not exist #
    else:
        # Set artificially low value #
        log_size = -1

    # If writing to the log #
    if operation == 'write':
        # Write error message to string object log stream #
        log_err(handler, msg)
        # Write error string object log stream as encrypted to file #
        write_log(log_name, db_key)

    # If reading the log #
    elif operation == 'read':
        # If log file is has data, read it #
        if log_size > 0:
            # Read the contents of log page by page #
            log_read(text)
        else:
            print_err('No data to read in log file', 2)

    # If operation not specified #
    else:
        # Log error to string object log stream #
        logging.error('\n\nNo logging operation specified\n')
        # Write error string object log stream as encrypted to file #
        write_log(log_name, db_key)


def login_timeout():
    """
    Displays loging timeout per second for 60 second interval.

    :return:  Nothing
    """
    print('\n* [WARNING] Too many login attempts .. 60 second timeout *')
    for sec in range(1, 61):
        msg = f'{"!" * sec} sec'
        print(msg, end='\r')
        time.sleep(1)


def log_err(handler: str, msg: str):
    """
    Logs error or exception based on passed in handler parameter.

    :param handler:  Specifies which logging operation to perform.
    :param msg:  The error message to be logged to string object stream.
    :return:  Nothing
    """
    # If writing error #
    if handler == 'error':
        # Log error to string object log stream #
        logging.error('%s\n\n', msg)
    # If writing exception #
    elif handler == 'exception':
        # Log exception to string object log stream #
        logging.exception('%s\n\n', msg)
    else:
        # Log error to string object log stream #
        logging.error('Error message write: \"%s\" provided '
                      'without proper handler parameter\n\n', msg)


def log_read(text: str):
    """
    Reads input text page by page, displaying 60 lines per page.

    :param text:  The input text to be read page by page.
    :return:  Nothing
    """
    count = 0

    # Print log page by page #
    for line in text.split('\n'):
        if count == 60:
            input('Hit enter to continue ')
            count = 0

        print(line)
        count += 1

    input('Hit enter to continue ')


def make_keys(db_names: str, password: bytes, auth_obj: object) -> object:
    """
    Creates a fresh cryptographic key set, encrypts, and inserts in keys database.

    :param db_names:  Database name tuple.
    :param password:  Hashed input password.
    :param auth_obj:  The authentication instance.
    :return:  The populated authentication instance.
    """
    # Initialize argon2 hasher #
    pass_algo = PasswordHasher()
    # Hash the input password #
    input_hash = pass_algo.hash(password)

    # Fernet Symmetric HMAC key for dbs and secret #
    db_key = Fernet.generate_key()
    secret_key = Fernet.generate_key()

    # Encrypt ChaCha20 symmetric components (256-bit key, 128-bit nonce) #
    upload_key = Fernet(db_key).encrypt(os.urandom(32))
    cha_nonce = Fernet(db_key).encrypt(os.urandom(16))

    # Base64 encode upload components for db storage #
    upload_key = b64encode(upload_key)
    cha_nonce = b64encode(cha_nonce)

    # Encrypt the hashed input #
    crypt_hash = Fernet(secret_key).encrypt(input_hash.encode())

    # AESCCM password authenticated key #
    key = AESCCM.generate_key(bit_length=256)
    aesccm = AESCCM(key)
    nonce = os.urandom(13)

    # Encrypt the db fernet key with AESCCM password key & write to file #
    crypt_db = aesccm.encrypt(nonce, db_key, password)

    # Add encrypted password hash to key ring #
    keyring.set_password('CryptDrive', 'CryptUser', crypt_hash.decode('utf-8'))

    # Set authentication object variables #
    auth_obj.aesccm = key
    auth_obj.nonce = nonce
    auth_obj.db_key = crypt_db
    auth_obj.secret_key = secret_key
    auth_obj.password = crypt_hash

    # Send encrypted ChaCha20 key to key's database #
    query = global_vars.db_insert(db_names, 'upload_key', upload_key.decode('utf-8'))
    query_handler(db_names, query, None)

    # Send encrypted ChaCha20 nonce to keys database #
    query = global_vars.db_insert(db_names, 'upload_nonce', cha_nonce.decode('utf-8'))
    query_handler(db_names, query, None)

    # Write AESCCM key and nonce to files #
    file_handler(global_vars.FILES[0], 'wb', None, operation='write', data=key)
    file_handler(global_vars.FILES[1], 'wb', None, operation='write', data=nonce)

    # Write db key and secret key to files #
    file_handler(global_vars.FILES[2], 'wb', None, operation='write', data=crypt_db)
    file_handler(global_vars.FILES[3], 'wb', None, operation='write', data=secret_key)

    global_vars.HAS_KEYS = True

    return auth_obj


def meta_strip(file_path: str) -> bool:
    """
    Attempts striping metadata from passed in file. If attempt fails, waiting a second and tries \
    again while adding a second of waiting time per failure. After 3 failed attempts, it returns a \
    False boolean value.

    :param file_path:  The path to the file whose metadata to be stripped.
    :return:  Boolean True/False toggle on success/failure.
    """
    count, sleep_time = 0, 1

    while True:
        if count > 0:
            sleep_time += 1

        try:
            # Read the data of the file to be scrubbed #
            with open(file_path, 'rb') as in_file:
                meta_file = Image(in_file)

            # Delete all metadata #
            meta_file.delete_all()

            # Overwrite file with scrubbed data #
            with open(file_path, 'wb') as out_file:
                out_file.write(meta_file.get_file())

        # If unable to scrub unknown keys #
        except KeyError:
            pass

        # If error occurs during byte unpack operation #
        except ValueError:
            return False

        # If file IO error occurs #
        except (AttributeError, IOError):
            # If 3 failed attempts #
            if count == 3:
                return False

            time.sleep(sleep_time)
            count += 1
            continue

        return True


def msg_format(send_email: str, receiver: str, body: str, files: str) -> MIMEMultipart:
    """
    Format email message headers and attach passed in files.

    :param send_email:  Senders email address.
    :param receiver:  Receivers email address.
    :param body:  Message body.
    :param files:  Files to be attached to the message.
    :return:  The formatted message with attachments.
    """
    # Initial message object & format headers/body #
    msg = MIMEMultipart()
    msg['From'] = send_email
    msg['To'] = receiver
    msg['Subject'] = 'Cloud Encryptor Package'
    msg.attach(MIMEText(body, 'plain'))

    # Iterate through msg files #
    for file in files:
        # If there are no more files #
        if not file:
            return msg

        # Initialize stream to attach data #
        payload = MIMEBase('application', 'octet-stream')
        # Open file and read data as attachment #
        with open(file, 'rb') as attachment:
            payload.set_payload(attachment.read())

        # Encode & attach current file #
        encoders.encode_base64(payload)
        # Add header to attachment #
        payload.add_header('Content-Disposition', f'attachment;filename = {file}')
        # Attach attachment to email #
        msg.attach(payload)

    return msg


def msg_send(send_email: str, receiver: str, password: str, msg: MIMEMultipart, auth_obj: object):
    """
    Facilitate the sending of formatted emails.

    :param send_email:  Senders email address.
    :param receiver:  Receivers email address.
    :param password:  Account generated application password..
    :param msg:  Email message instance.
    :param auth_obj: The authentication instance.
    :return:
    """
    # Initialize SMTP session with gmail server #
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as session:
            # Upgrade session To TLS encryption #
            session.starttls()
            # Login #
            session.login(send_email, password)
            # Send email through established session #
            session.sendmail(send_email, receiver, msg.as_string())
            # Disconnect session #
            session.quit()

    # If error occurs during SMTP session #
    except smtplib.SMTPException as err:
        print_err('Remote email server connection failed', 2)
        logger(f'SMTP Error: {err}\n\n', auth_obj, operation='write', handler='error')


def print_err(msg: str, seconds):
    """
    Displays error message via stderr for supplied time interval.

    :param msg:  Error message to be displayed.
    :param seconds:  Time interval in which the message will be displayed.
    :return:  Nothing
    """
    print(f'\n* [ERROR] {msg} *\n', file=sys.stderr)
    # If seconds has value (not None) #
    if seconds:
        time.sleep(seconds)


def query_handler(db_name: str, query: str, auth_obj: object, operation=None):
    """
    Facilitates MySQL database query execution.

    :param db_name:  Database in which the query will be executed.
    :param query:  The query that will be executed upon the database.
    :param auth_obj:  The authentication instance.
    :param operation:  Performs various operations if specified (create, fetchone, or fetchall).
    :return:  Nothing
    """
    # Change directory #
    os.chdir(global_vars.DIRS[0])
    # Sets maximum number of allowed db connections #
    max_conns = 1
    # Locks allowed connections to database #
    sema_lock = BoundedSemaphore(value=max_conns)

    # Attempts to connect, continues if already connected #
    with sema_lock:
        try:
            # Connect to passed in database #
            conn = sqlite3.connect(f'{db_name}.db')

        # If database already exists #
        except Error:
            pass

        # Executes query passed in #
        try:
            db_call = conn.execute(query)

            # If creating database close connection
            # and moves back a directory #
            if operation == 'create':
                conn.close()
                os.chdir(global_vars.CWD)
                return None

            # Fetches entry from database then closes
            # connection and moves back a directory #
            if operation == 'fetchone':
                row = db_call.fetchone()
                conn.close()
                os.chdir(global_vars.CWD)
                return row

            # Fetches all database entries then closes
            # connection and moves back a directory #
            if operation == 'fetchall':
                rows = db_call.fetchall()
                conn.close()
                os.chdir(global_vars.CWD)
                return rows

            # Commit query to db #
            conn.commit()

        # Database query error handling #
        except (Error, DatabaseError, IntegrityError, ProgrammingError, OperationalError,
                NotSupportedError) as err:
            # Prints general error #
            print_err(f'SQL error: {err}', 2)

            # If password is set #
            if global_vars.HAS_KEYS:
                # Passes log message to logging function #
                logger(f'SQL error: {err}\n\n', auth_obj, operation='write', handler='error')

        # Close connection #
        conn.close()
        # Move back a directory #
        os.chdir(global_vars.CWD)

    return None


def recycle_check() -> list:
    """
    Checks the recycling bin for missing program components.

    :return:  List of any missing components that were unable to be recovered.
    """
    miss_list = []
    # Compile parsing regex's #
    re_no_ext = re.compile(r'(?=[a-zA-Z\d])[^\\]{1,30}(?=\.)')
    re_dir = re.compile(r'(?=[a-zA-Z\d])[^\\]{1,30}(?=$)')

    # Iterate through missing components #
    for item in global_vars.MISSING:
        # If item is file #
        if item in global_vars.FILES + global_vars.DBS:
            # Parse file without extension #
            re_item = re.search(re_no_ext, item)
        # If item is folder #
        else:
            # Parse folder for winshell recycling bin check #
            re_item = re.search(re_dir, item)

        # Append item path to program root dir #
        parse = f'{global_vars.CWD}{re_item.group(0)}'
        try:
            # Check recycling bin for item #
            undelete(parse)

            # If item is a text file #
            if item in global_vars.FILES:
                os.rename(parse, f'{parse}.txt')
            # If item is a database #
            elif item in global_vars.DBS:
                os.rename(parse, f'{parse}.db')

            print(f'{item} was found in recycling bin')

        # If attempt to recover component from recycling bin fails #
        except x_not_found_in_recycle_bin:
            print(f'{item} not found in recycling bin')
            miss_list.append(item)

    return miss_list


def secure_delete(path: str, passes=5):
    """
    Overwrite file data with random data number of specified passes and delete.

    :param path:  Path to the file to be overwritten and deleted.
    :param passes:  Number of pass to perform random data overwrite.
    :return:  Nothing
    """
    try:
        # Get the file size in bytes #
        length = os.stat(path).st_size

        # Open file and overwrite the data for number of passes #
        with open(path, 'wb') as file:
            for _ in range(passes):
                # Point file pointer to start of file #
                file.seek(0)
                # Write random data #
                file.write(os.urandom(length))

    # If file error occurs #
    except (OSError, IOError) as err:
        print_err(f'Error overwriting file for secure delete: {err}', 2)

    os.remove(path)


def system_cmd(cmd: str, stdout, stderr, exec_time: int):
    """
    Execute shell-escaped command.

    :param cmd:  Command syntax to be executed.
    :param stdout:  Standard output
    :param stderr:  Standard error.
    :param exec_time:  Execution timeout.
    :return:  Nothing
    """
    # Shell-escape command syntax #
    exe = shlex.quote(cmd)

    # For built-in shell commands like (cls, clear) #
    with Popen(exe, stdout=stdout, stderr=stderr, shell=True) as command:
        try:
            # Execute command with passed in timeout threshold #
            command.communicate(timeout=exec_time)

        # Handles process timeouts and errors #
        except (SubprocessError, TimeoutExpired, CalledProcessError, OSError, ValueError):
            command.kill()
            command.communicate()


def sys_lock():
    """
    Attempts to lockdown (Windows) or power-off system (Linux), if either fail the program exits \
    with error code.

    :return:  Nothing
    """
    # Code can be added to notify administrator or
    # raise an alert to remote system #

    # If OS is Windows #
    if os.name == 'nt':
        # Lock the system #
        ctypes.wind11.user32.LockWorkStation()
    # If OS is Linux #
    else:
        # Turn off the system #
        system_cmd('poweroff -p', None, None, 2)

    # Exit when unlocked or poweroff fails #
    sys.exit(2)


def write_log(log_name: str, db_key: bytes):
    """
    Parse new log message to old data and write encrypted result to log.

    :param log_name:  Log file name.
    :param db_key:  Database key for encrypting log data.
    :return:  Nothing
    """
    # Get log message in variable #
    log_msg = global_vars.LOG_STREAM.getvalue()

    try:
        with open(log_name, 'w', encoding='utf-8') as file:
            # Encrypt log data & store on file #
            crypt = encrypt_db_data(db_key, log_msg.encode())
            file.write(crypt)

    except (IOError, OSError) as err:
        print_err(f'Error occurred writing {log_msg} to Logger:\n{err}', 2)
        sys.exit(10)
