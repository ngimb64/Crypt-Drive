# pylint: disable=E1101
""" Built-in modules """
import ctypes
import errno
import os
import logging
import re
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
from pathlib import Path
# External Modules #
import keyring
from argon2 import PasswordHasher
from exif import Image
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# If OS is Windows #
if os.name == 'nt':
    from winshell import undelete, x_not_found_in_recycle_bin
# Custom Modules #
import Modules.db_handlers as db_handlers


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


def cha_decrypt(conf_obj: object):
    """
    Retrieve ChaCha components from Keys db, decoding and decrypting them.

    :param conf_obj:  The program configuration instance.
    :return:  The decrypted ChaCha20 key and nonce or prints message on error.
    """
    # Get the decrypted database key #
    db_key = get_database_comp(conf_obj)
    # Attempt to Retrieve the upload key and nonce from Keys db #
    key_call, nonce_call = fetch_upload_comps(conf_obj, 'upload_key', 'upload_nonce')

    # If decrypt key doesn't exist in db #
    if not key_call or not nonce_call:
        return print_err('Database missing decrypt component ..'
                        ' exit and restart program to fix issue', 2)

    # Decrypt key & nonce #
    decrypt_key = decrypt_db_data(db_key, key_call[1])
    decrypt_nonce = decrypt_db_data(db_key, nonce_call[1])

    return decrypt_key, decrypt_nonce


def component_handler(config_obj: object, user_input: str) -> object:
    """
    Creates various dir, db, and key components required for program operation.

    :param config_obj:  Program configuration instance.
    :param user_input:  User input secret.
    :return:  Populated authentication instance.
    """
    # Iterate through program folders #
    for folder in config_obj.dirs:
        # Create missing folder #
        folder.mkdir(parents=True, exist_ok=True)

    try:
        # Acquire semaphore lock in context manager #
        with config_obj.sema_lock:
            # Connect to program database in context manager #
            with db_handlers.DbConnectionHandler(config_obj.db_name[0]) as db_conn:
                # Set connection in program config #
                config_obj.db_conn = db_conn
                # Get query to create database tables #
                create_query = db_handlers.db_create(config_obj.db_tables)
                # Execute table creation query #
                db_handlers.query_handler(config_obj, create_query, exec_script=True)
                # Create fresh cryptographic key set #
                return make_keys(config_obj, user_input.encode())

    # If error occurs acquiring semaphore lock #
    except ValueError as sema_err:
        print_err('Semaphore error occurred attempting to acquire a database connection: '
                  f'{sema_err}', 2)
        sys.exit(3)

    # If database error occurs #
    except sqlite3.Error as db_err:
        print_err(f'Error occurred during database operation: {db_err}', 2)
        sys.exit(3)


def data_copy(source: Path, dest: Path):
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


def db_check(config: object, secret: bytes) -> object:
    """
    Checks the upload contents within the keys database and populates authentication object.

    :param config:  The program configuration instance.
    :param secret:  User input password to be confirmed.
    :return:  Populated authentication object.
    """
    # Load AESCCM decrypt components #
    key = file_handler(config, config.files[0], 'rb', operation='read')
    nonce = file_handler(config, config.files[1], 'rb', operation='read')
    crypt = file_handler(config, config.files[2], 'rb', operation='read')
    secret_key = file_handler(config, config.files[3], 'rb', operation='read')
    aesgcm = AESGCM(key)

    # Unlock the local database key #
    try:
        db_key = aesgcm.decrypt(nonce, crypt, secret)

    # If authentication tag is invalid #
    except (InvalidTag, TypeError, ValueError):
        print_err('Incorrect unlock password entered', 2)
        sys.exit(4)

    # Encrypt the input password #
    crypt_secret = Fernet(secret_key).encrypt(secret)

    # Populate the authentication object #
    config.aesgcm = key
    config.nonce = nonce
    config.db_key = crypt
    config.secret_key = secret_key
    config.password = crypt_secret

    try:
        # Acquire semaphore lock for db access #
        with config.sema_lock:
            # Establish database connection in context manager #
            with db_handlers.DbConnectionHandler(config.db_name[0]) as db_conn:
                # Save reference to database connection in program config #
                config.db_conn = db_conn
                # Retrieve upload key from database #
                query = db_handlers.db_retrieve(config.db_tables[0])
                upload_call = db_handlers.query_handler(config, query, 'upload_key',
                                                        fetch='one')
                # Retrieve nonce from database #
                query = db_handlers.db_retrieve(config.db_tables[0])
                nonce_call = db_handlers.query_handler(config, query, 'upload_nonce',
                                                       fetch='one')
                # If the upload key call fails #
                if not upload_call or not nonce_call:
                    # Display error and ensure it is being fixed #
                    print_err('Database missing upload component .. creating new key & upload to '
                              'db\nData will need to be re uploaded with new key otherwise '
                              'decryption will fail', 2)

                    if not upload_call:
                        print('Creating new upload key ..')
                        # Recreate 32 byte upload key and store to keys database #
                        key_recreate(config, db_key, 256 // 8, config.db_tables[0], 'upload_key')

                    if not nonce_call:
                        print('Creating new upload nonce')
                        # Recreate 16 byte upload nonce and store to keys database #
                        key_recreate(config, db_key, 128 // 8, config.db_tables[0], 'upload_nonce')

                else:
                    # Confirm retrieved upload key/nonce properly decode & decrypt #
                    _ = decrypt_db_data(db_key, upload_call[1])
                    _ = decrypt_db_data(db_key, nonce_call[1])

    # If error occurs acquiring semaphore lock #
    except ValueError as sema_err:
        # Print error, log, and continue #
        print_err('Semaphore error occurred attempting to acquire a database connection: '
                  f'{sema_err}', 2)
        logger(config, 'Semaphore error occurred attempting to acquire a database '
                           f'connection: {sema_err}', operation='write', handler='error')
        sys.exit(5)

    # If database error occurs #
    except sqlite3.Error as db_err:
        # Look up database error, log, and loop #
        db_handlers.db_error_query(config, db_err)
        sys.exit(5)

    # Return the populated auth object #
    return config


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
    except (InvalidToken, TypeError, ValueError) as err:
        print_err(f'Error occurred during fernet data decryption: {err}', 2)
        sys.exit(7)

    # Return decrypted data #
    return plain_data


def dir_recover(config: object, curr_folder: Path, dir_map: dict) -> object:
    """
    Iterates through list of passed in dirs and checks to see if current folder is the same name \
    to static assignment.

    :param config:  The program configuration instance.
    :param curr_folder:  The path to the current iteration folder to be recovered.
    :param dir_map:  A dict to map the program dir names to associated paths.
    :return:  Updated program config instance.
    """
    try:
        # Check dict to see if dir name key exits #
        lookup_dir = dir_map[curr_folder.name]
        # Copy dir in current location to original program dir #
        data_copy(curr_folder, lookup_dir)
        # Print success and remove from the missing list #
        print(f'Folder: {lookup_dir} recovered')
        config.missing.remove(lookup_dir)

    # If current iteration folder is not program dir #
    except KeyError:
        pass

    return config


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
    except (InvalidToken, TypeError, ValueError) as err:
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


def fetch_upload_comps(config_obj: object, key_name: str, nonce_name: str) -> tuple:
    """
    Retrieves upload components from keys database.

    :param config_obj:  The program configuration instance.
    :param key_name:  Name of key to be retrieved.
    :param nonce_name:  Name of nonce to be retrieved.
    :return:
    """
    # Retrieve decrypt key from keys table #
    query = db_handlers.db_retrieve(config_obj.db_tables[0])
    decrypt_query = db_handlers.query_handler(config_obj, query, key_name, fetch='one')

    # Retrieve nonce from keys table #
    query = db_handlers.db_retrieve(config_obj.db_tables[0])
    nonce_query = db_handlers.query_handler(config_obj, query, nonce_name, fetch='one')

    # Return fetched query results #
    return decrypt_query, nonce_query


def file_handler(conf: object, filename: Path, mode: str, operation=None,
                 data=None) -> str | bytes | None:
    """
    Error validated file handler for read and write operations.

    :param conf:  The program configuration instance.
    :param filename:  Name of file where the operation will be performed.
    :param mode:  File operation mode that will be performed on file.
    :param operation:  Toggle to specify file read/write operation.
    :param data:  Input data to be written to file.
    :return:  Either data as string or bytes for read operation, an None for write.
    """
    if mode in ('rb', 'wb'):
        encode = None
    else:
        encode = 'utf-8'

    try:
        with filename.open(mode, encoding=encode) as file:
            # If read operation was specified #
            if operation == 'read':
                return file.read()

            # If write operation was specified #
            if operation == 'write':
                return file.write(data)

            # If improper operation specified #
            print_err('Error occurred during file operation: Improper file operation '
                      'attempted', 2)
            # If password is set #
            if conf.has_keys:
                # Log error #
                logger(conf, 'Error occurred during file operation: Improper file operation '
                             'attempted', operation='write', handler='error')

    # If error occurs during file operation #
    except (IOError, FileNotFoundError, OSError) as err:
        # Look up file error #
        error_query(filename, mode, err)
        # If password is set #
        if conf.has_keys:
            logger(conf, f'Error occurred during file operation: {err}',
                   operation='write', handler='error')

        sys.exit(9)

    return None


def file_recover(config: object, curr_file: Path) -> object:
    """
    Checks to see if current iteration of os walk is the file to be recovered.

    :param config:  The program configuration instance.
    :param curr_file:  The path to the current file attempted to be recovered.
    :return:  Updated program config instance.
    """
    # Iterate through list of missing components #
    for item in config.missing:
        # If file is one of the key components #
        if item.name == curr_file.name and item.name.endswith('.txt'):
            # Set the recover destination path #
            dest_file = config.dirs[2] / curr_file.name
            # Copy and delete source file #
            data_copy(curr_file, dest_file)
            print(f'File: {curr_file.name} recovered in file system')
            # Remove recovered item from missing list #
            config.missing.remove(item)

        # If file is the database #
        if item.name == curr_file.name and item.name.endswith('.db'):
            # Set the recover destination path #
            dest_file = config.dirs[0] / curr_file.name
            # Copy and delete source file #
            data_copy(curr_file, dest_file)
            print(f'File: {curr_file.name} recovered in file system')
            # Remove recovered item from missing list #
            config.missing.remove(item)

    return config


def get_database_comp(conf_obj: object) -> bytes:
    """
    Unlock and retrieve database cryptography component.

    :param conf_obj:  The program configuration instance.
    :return:  The decrypted database decryption key.
    """
    # Decrypt the password #
    plain_pass = conf_obj.get_plain_secret()
    # Decrypt the local database key #
    return conf_obj.decrypt_db_key(plain_pass)


def hd_crawl(config_obj: object) -> object:
    """
    Recursive hard drive crawler for recovering missing components.

    :param config_obj:  The program configuration instance.
    :return:  Update program config instance.
    """
    # If OS is Windows #
    if os.name == 'nt':
        crawl_path = 'C:\\Users'
    # If OS is Linux #
    else:
        crawl_path = '/home'

    # Map program dir names to associated paths #
    program_dirs = {'CryptDrive_Dbs': config_obj.dirs[0],
                    'CryptDrive_Import': config_obj.dirs[1],
                    'CryptDrive_Keys': config_obj.dirs[2],
                    'CryptDrive_Decrypt': config_obj.dirs[3],
                    'CryptDrive_Upload': config_obj.dirs[4]}

    # Crawl through user directories #
    for dir_path, dir_names, file_names in os.walk(crawl_path, topdown=True):
        # If there are no recovery items left #
        if not config_obj.missing:
            break

        # If there are folders in the missing list #
        if not str(config_obj.missing[0]).endswith('.db') \
        and not str(config_obj.missing[0]).endswith('.txt'):
            # Iterate through folders in current dir #
            for folder in dir_names:
                # If there are no more folders in the missing list #
                if not config_obj.missing or str(config_obj.missing[0]).endswith('.db'):
                    break

                # Set current iteration path #
                curr_item = Path(dir_path) / folder
                # Iterate through list of missing attempts
                # and attempt to match dir to recover #
                config_obj = dir_recover(config_obj, curr_item, program_dirs)

        # Iterate through files in current dir #
        for file in file_names:
            # If there are no recovery items left #
            if not config_obj.missing:
                break

            # Set current iteration path #
            curr_item = Path(dir_path) / file
            # Iterate through list of missing attempts
            # and attempt to match file to recover #
            config_obj = file_recover(config_obj, curr_item)

    return config_obj


def key_recreate(conf_obj: object, db_key: bytes, key_size: int, db_table: str, store_comp: str):
    """
    Recreates key or nonce and insert them back into param db_name database named as store_comp.

    :param conf_obj:  The program configuration instance.
    :param db_key:  The Fernet key to encrypt recreated keys before storing them.
    :param key_size:  The size of the key/nonce size to be recreated and stored.
    :param db_table:  The database name where the keys will be stored.
    :param store_comp:  The name of key that will be stored in the database.
    :return:
    """
    # Create new encrypted upload key #
    crypt_comp = Fernet(db_key).encrypt(os.urandom(key_size))
    # Base64 encode encrypted upload key for db storage #
    encoded_comp = b64encode(crypt_comp)

    # Send upload key to key database #
    query = db_handlers.key_insert(db_table)
    db_handlers.query_handler(conf_obj, query, store_comp, encoded_comp.decode('utf-8'))


def logger(conf_obj: object, msg: str, operation=None, handler=None):
    """
    Encrypted logging system.

    :param conf_obj:  The program configuration object.
    :param msg:  Message to be logged.
    :param operation:  Log operation to be performed.
    :param handler:  Logging level handler.
    :return:  Nothing
    """
    text = None
    # Decrypt the password #
    plain = conf_obj.get_plain_secret()
    # Decrypt the local database key #
    db_key = conf_obj.decrypt_db_key(plain)

    # If read operation and log file exists #
    if operation == 'read' and conf_obj.log_name.exists():
        # Get log file size in bytes #
        log_size = conf_obj.log_name.stat().st_size

        # If log has data in it #
        if log_size > 0:
            # Read the encrypted log data #
            crypt = file_handler(conf_obj, conf_obj.log_name, 'rb', operation='read')
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
        write_log(conf_obj, db_key)

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
        write_log(conf_obj, db_key)


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


def make_keys(config: object, password: bytes) -> object:
    """
    Creates a fresh cryptographic key set, encrypts, and inserts in keys database.

    :param config:  The program configuration instance.
    :param password:  Hashed input password.
    :return:  The populated authentication instance.
    """
    # Initialize argon2 hasher #
    pass_algo = PasswordHasher()
    # Hash the input password #
    input_hash = pass_algo.hash(password)

    # Fernet Symmetric HMAC key for dbs and secret #
    db_key = Fernet.generate_key()
    secret_key = Fernet.generate_key()

    # Encrypt the hashed input #
    crypt_hash = Fernet(secret_key).encrypt(input_hash.encode())
    # Add encrypted password hash to key ring #
    keyring.set_password('CryptDrive', 'CryptUser', crypt_hash.decode('utf-8'))

    # Encrypt AESGCM symmetric upload components (256-bit key, 96-bit nonce) #
    upload_key = Fernet(db_key).encrypt(AESGCM.generate_key(bit_length=256))
    upload_nonce = Fernet(db_key).encrypt(os.urandom(96 // 8))
    # Base64 encode upload components for db storage #
    upload_key = b64encode(upload_key)
    upload_nonce = b64encode(upload_nonce)

    # AESCCM password authenticated key #
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(96 // 8)
    aesgcm = AESGCM(key)
    # Encrypt the db fernet key with AESCCM password key & write to file #
    crypt_db = aesgcm.encrypt(nonce, db_key, password)

    # Set authentication object variables #
    config.aesgcm = key
    config.nonce = nonce
    config.db_key = crypt_db
    config.secret_key = secret_key
    config.password = crypt_hash

    # Send encrypted ChaCha20 key to key's database #
    query = db_handlers.key_insert(config.db_tables[0])
    db_handlers.query_handler(config, query, 'upload_key', upload_key.decode('utf-8'))

    # Send encrypted ChaCha20 nonce to keys database #
    query = db_handlers.key_insert(config.db_tables[0])
    db_handlers.query_handler(config, query, 'upload_nonce', upload_nonce.decode('utf-8'))

    # Write AESCCM key and nonce to files #
    file_handler(config, config.files[0], 'wb', operation='write', data=key)
    file_handler(config, config.files[1], 'wb', operation='write', data=nonce)

    # Write db key and secret key to files #
    file_handler(config, config.files[2], 'wb', operation='write', data=crypt_db)
    file_handler(config, config.files[3], 'wb', operation='write', data=secret_key)

    config.has_keys = True

    return config


def meta_strip(file_path: Path) -> bool:
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
            with file_path.open('rb') as in_file:
                meta_file = Image(in_file)

            # Delete all metadata #
            meta_file.delete_all()

            # Overwrite file with scrubbed data #
            with file_path.open('wb') as out_file:
                out_file.write(meta_file.get_file())

        # If unable to scrub unknown keys #
        except KeyError:
            pass

        # If error occurs during byte unpack operation #
        except ValueError:
            return False

        # If file IO error occurs #
        except (AttributeError, IOError, OSError):
            # If 3 failed attempts #
            if count == 3:
                return False

            time.sleep(sleep_time)
            count += 1
            continue

        return True


def msg_format(send_email: str, receiver: str, body: str, files: tuple) -> MIMEMultipart:
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
        with file.open('rb') as attachment:
            payload.set_payload(attachment.read())

        # Encode & attach current file #
        encoders.encode_base64(payload)
        # Add header to attachment #
        payload.add_header('Content-Disposition', f'attachment;filename = {str(file.name)}')
        # Attach attachment to email #
        msg.attach(payload)

    return msg


def msg_send(conf_obj: object, send_email: str, receiver: str, password: str, msg: MIMEMultipart):
    """
    Facilitate the sending of formatted emails.

    :param conf_obj:  The program configuration instance.
    :param send_email:  Senders email address.
    :param receiver:  Receivers email address.
    :param password:  Account generated application password..
    :param msg:  Email message instance.
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
        print_err(f'Remote email server connection failed: {err}', 2)
        logger(conf_obj, f'SMTP Error: {err}', operation='write', handler='error')


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


def recycle_check(config_obj: object) -> object:
    """
    Checks the recycling bin for missing program components.

    :param config_obj:  The program configuration instance.
    :return:  List of any missing components that were unable to be recovered.
    """
    miss_list = []

    # Iterate through missing components #
    for item in config_obj.missing:
        # If item is file #
        if item in (config_obj.db_name + config_obj.files):
            # Parse file without extension out of path #
            re_item = re.search(config_obj.re_no_ext, str(item))
            # If the item is a cryptographic file #
            if item in config_obj.files:
                path = config_obj.dirs[2]
            # If the item is database #
            else:
                path = config_obj.dirs[0]
        # If item is folder #
        else:
            # Parse folder out of path #
            re_item = re.search(config_obj.re_win_dir, str(item))
            path = config_obj.cwd

        # If regex parse was successful #
        if re_item:
            # Append item path to program root dir #
            parse = path / re_item.group(0)
        # If regex parse failed #
        else:
            continue

        try:
            # Check recycling bin for item #
            undelete(str(parse))

            # If item is a text file #
            if item in config_obj.files:
                os.rename(str(parse), f'{parse}.txt')

            # If item is the database #
            if item.name == config_obj.db_name[0].name:
                os.rename(str(parse), f'{parse}.db')

            print(f'{item.name} was found in recycling bin')

        # If attempt to recover component from recycling bin fails #
        except x_not_found_in_recycle_bin:
            print(f'{item.name} not found in recycling bin')
            miss_list.append(item)

    # Assign missing list to config #
    config_obj.missing = miss_list
    return config_obj


def secure_delete(path: Path, passes=10):
    """
    Overwrite file data with random data number of specified passes and delete.

    :param path:  Path to the file to be overwritten and deleted.
    :param passes:  Number of pass to perform random data overwrite.
    :return:  Nothing
    """
    try:
        # Get the file size in bytes #
        length = path.stat().st_size

        # Open file and overwrite the data for number of passes #
        with path.open('wb') as file:
            for _ in range(passes):
                # Point file pointer to start of file #
                file.seek(0)
                # Write random data #
                file.write(os.urandom(length))

    # If file error occurs #
    except (IOError, OSError) as err:
        print_err(f'Error overwriting file for secure delete: {err}', 2)

    # Delete the file #
    path.unlink()


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
        os.system('poweroff -p')

    # Exit when unlocked or poweroff fails #
    sys.exit(2)


def write_log(conf: object, db_key: bytes):
    """
    Parse new log message to old data and write encrypted result to log.

    :param conf:  The program configuration instance.
    :param db_key:  Database key for encrypting log data.
    :return:  Nothing
    """
    # Get log message in variable #
    log_msg = conf.log_stream.getvalue()
    # Encrypt log data #
    crypt = encrypt_db_data(db_key, log_msg.encode())

    try:
        # Write encrypted log data to file #
        with conf.log_name.open('w', encoding='utf-8') as file:
            file.write(crypt)

    except (IOError, OSError) as err:
        print_err(f'Error occurred writing {log_msg} to Logger:\n{err}', 2)
        sys.exit(10)
