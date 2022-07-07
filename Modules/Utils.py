# Built-in Modules #
import errno
import os
import logging
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
from sqlite3 import Warning, Error, DatabaseError, IntegrityError, \
                    ProgrammingError, OperationalError, NotSupportedError

# External Modules #
import keyring
from argon2 import PasswordHasher
from exif import Image
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

# Custom Modules #
import Modules.Globals as Globals


"""
##################
# Function Index #
########################################################################################################################
ChaAlgoInit - Initializes the ChaCh20 algorithm object.
ChaChaDecrypt - Retrieve ChaCha components from Keys db, decode and decrypt, then initialize algo object.
ComponentHandler - Creates various dir, db, and key components required for program operation.
CreateDatabases - Creates database components.
CreateDirs - Creates program component directories.
DataCopy - Copies data from source to destination.
DbCheck - Checks the upload contents within the keys database and populates authentication object.
DecryptDbData - Decodes and decrypts database base64 cipher data.
EncryptDbData - Encrypts and encodes plain data for database.
ErrorQuery - Looks up errno message to get description.
FetchUploadComps - Retrieves upload components from keys database.
FileHandler - Handles file read / write operations.
GetDatabaseComp - Unlock and retrieve database cryptography component.
HdCrawl - Checks user file system for missing component.
KeyHandler - Deletes existing keys & dbs, calls function to make new components.
Logger - Encrypted logging system.
MetaStrip - Attempts to strip the metadata from passed in file. If attempt fails, it waits a second and tries again. \
            If 3 failed attempts occur, it returns a False boolean value.
MsgFormat - Formats email message headers, data, and attachments.
MsgSend - Facilitates sending email via TLS connection.
PrintErr - Prints error message the duration of the integer passed in.
QueryHandler - MySQL database query handling function for creating, populating, and retrieving data from dbs.
SystemCmd - Executes system shell command.
WriteLog - Parse new log message to old data and write encrypted result to log.
########################################################################################################################
"""


"""
########################################################################################################################
Name:       ChaAlgoInit
Purpose:    Initializes the ChaCh20 algorithm object.
Parameters: The key and nonce to initialize the algorithm.
Returns:    Initialized algorithm object.
########################################################################################################################
"""
def ChaAlgoInit(key: bytes, nonce: bytes) -> object:
    # Initialize ChaCha20 encryption algo #
    algo = algorithms.ChaCha20(key, nonce)
    # Return the initialized ChaCha20 cipher object #
    return Cipher(algo, mode=None)


"""
########################################################################################################################
Name:       ChaChaDecrypt
Purpose:    Retrieve ChaCha components from Keys db, decoding and decrypting them.
Parameters: The authentication object and keys database.
Returns:    The decrypted ChaCha20 key and nonce.
########################################################################################################################
"""
def ChaChaDecrypt(auth_obj: object, db: str) -> tuple:
    # Get the decrypted database key #
    db_key = GetDatabaseComp(auth_obj)
    # Attempt to Retrieve the upload key and nonce from Keys db #
    key_call, nonce_call = FetchUploadComps(db, 'upload_key', 'upload_nonce', auth_obj)

    # If decrypt key doesn't exist in db #
    if not key_call or not nonce_call:
        PrintErr('Database missing decrypt component .. exit and restart program to fix issue', 2)
        return

    # Decrypt key & nonce #
    decrypt_key = DecryptDbData(db_key, key_call[1])
    decrypt_nonce = DecryptDbData(db_key, nonce_call[1])

    return decrypt_key, decrypt_nonce


"""
########################################################################################################################
Name:       ComponentHandler
Purpose:    Creates various dir, db, and key components required for program operation.
Parameters: The database tuple, user secret input, and authentication object.
Returns:    Populated authentication object.
########################################################################################################################
"""
def ComponentHandler(db_tuple: tuple, user_input: str, auth_obj: object) -> object:
    # Create any missing dirs #
    CreateDirs()
    # Create database components #
    CreateDatabases(db_tuple)
    # Create fresh cryptographic key set #
    return MakeKeys(db_tuple[0], user_input, auth_obj)


"""
########################################################################################################################
name:       CreateDatabases
purpose:    creates database components.
parameters: the database tuple.
returns:    Nothing
########################################################################################################################
"""
def CreateDatabases(dbs: tuple):
    # Iterate through db tuple #
    for db in dbs:
        if db == 'crypt_keys':
            query = Globals.DB_KEYS(db)
        elif db == 'crypt_storage':
            query = Globals.DB_STORAGE(db)
        else:
            continue

        QueryHandler(db, query, None, create=True)


"""
########################################################################################################################
Name:       CreateDirs
Purpose:    Creates program component directories.
Parameters: Nothing
Returns:    Nothing
########################################################################################################################
"""
def CreateDirs():
    # Iterate through folders #
    for directory in Globals.DIRS:
        # If folder is missing #
        if directory in Globals.MISSING:
            # Create missing folder #
            os.mkdir(directory)


"""
########################################################################################################################
Name:       DataCopy
Purpose:    Copies data from source to destination.
Parameters: The source path of item to be copied and the destination path where the item will be copied, then deletes \
            the source file.
Returns:    Nothing
########################################################################################################################
"""
def DataCopy(source: str, dest: str):
    try:
        # Copy file, modify if already exists #
        shutil.copy(source, dest)

    # If file already exists #
    except (shutil.Error, OSError):
        pass

    # Delete source file #
    SecureDelete(source)


"""
########################################################################################################################
Name:       DbCheck
Purpose:    Checks the upload contents within the keys database and populates authentication object.
Parameters: Database tuple, input password to be confirmed, and authentication object.
Returns:    Populated authentication object.
########################################################################################################################
"""
def DbCheck(db: str, secret: bytes, auth_obj: object) -> object:
    # Load AESCCM decrypt components #
    key = FileHandler(Globals.FILES[0], 'rb', None, operation='read')
    nonce = FileHandler(Globals.FILES[1], 'rb', None, operation='read')
    crypt = FileHandler(Globals.FILES[2], 'rb', None, operation='read')
    secret_key = FileHandler(Globals.FILES[3], 'rb', None, operation='read')
    aesccm = AESCCM(key)
    db_key = None

    # Unlock the local database key #
    try:
        db_key = aesccm.decrypt(nonce, crypt, secret)

    # If authentication tag is invalid #
    except (InvalidTag, TypeError):
        PrintErr('Incorrect unlock password entered', 2)
        exit(2)

    # Encrypt the input password #
    crypt_secret = Fernet(secret_key).encrypt(secret)

    # Populate the authentication object #
    auth_obj.aesccm = key
    auth_obj.nonce = nonce
    auth_obj.db_key = crypt
    auth_obj.secret_key = secret_key
    auth_obj.password = crypt_secret

    # Retrieve upload key from database #
    query = Globals.DB_RETRIEVE(db, 'upload_key')
    upload_call = QueryHandler(db, query, None, fetchone=True)

    # Retrieve nonce from database #
    query = Globals.DB_RETRIEVE(db, 'upload_nonce')
    nonce_call = QueryHandler(db, query, None, fetchone=True)

    # If the upload key call fails #
    if not upload_call or not nonce_call:
        # Display error and ensure it is being fixed #
        PrintErr('Database missing upload component .. creating new key & upload to db\n'
                 'Data will need to be re uploaded with new key otherwise decryption will fail', 2)

        if not upload_call:
            print('Creating new upload key ..')
            # Create new encrypted upload key #
            crypt_key = Fernet(db_key).encrypt(os.urandom(32))
            # Base64 encode encrypted upload key for db storage #
            upload_key = b64encode(crypt_key)

            # Send upload key to key database #
            query = Globals.DB_INSERT(db, 'upload_key', upload_key.decode('utf-8'))
            QueryHandler(db, query, None)

        if not nonce_call:
            print('Creating new upload nonce')
            # Create new encrypted upload nonce #
            crypt_nonce = Fernet(db_key).encrypt(os.urandom(16))
            # Base64 encoded encrypted upload nonce for storage #
            nonce = b64encode(crypt_nonce)

            # Send nonce to keys database #
            query = Globals.DB_INSERT(db, 'upload_nonce', nonce.decode('utf-8'))
            QueryHandler(db, query, None)
    else:
        # Confirm retrieved upload key/nonce properly decode & decrypt #
        _ = DecryptDbData(db_key, upload_call[1])
        _ = DecryptDbData(db_key, nonce_call[1])

    # Return the populated auth object #
    return auth_obj


"""
########################################################################################################################
name:       DecryptDbData     
purpose:    Decodes and decrypts database base64 cipher data.
parameters: The decrypted Fernet key and the cipher data to be decrypted.
returns:    Decrypted cipher data.
########################################################################################################################
"""
def DecryptDbData(decrypted_key: bytes, crypt_data: bytes) -> bytes:
    # Decode base64 encoding on stored data #
    decoded_data = b64decode(crypt_data)

    try:
        # Decrypt decoded cipher data #
        plain_data = Fernet(decrypted_key).decrypt(decoded_data)

    # If invalid token or encoding error #
    except (InvalidToken, TypeError, Error) as err:
        PrintErr(f'Error occurred during fernet data decryption: {err}', 2)
        sys.exit(4)

    # Return decrypted data #
    return plain_data


"""
########################################################################################################################
name:       EncryptDbData  
purpose:    Encrypts and encodes plain data for database.
parameters: The decrypted Fernet key and the plain text data to be encrypted.
returns:    The encoded cipher data ready for database storage.
########################################################################################################################
"""
def EncryptDbData(decrypted_key: bytes, plain_data: bytes) -> str:
    try:
        # Encrypt the plain text data #
        crypt_data = Fernet(decrypted_key).encrypt(plain_data)

    # If invalid token or encoding error #
    except (InvalidToken, TypeError, Error) as err:
        PrintErr(f'Error occurred during fernet data decryption: {err}', 2)
        sys.exit(5)

    # Return encrypted data in base64 format #
    return b64encode(crypt_data).decode()


"""
########################################################################################################################
Name:       ErrorQuery
Purpose:    Looks up the errno message to get description.
Parameters: Errno message, file mode, and error message object.
Returns:    Nothing
########################################################################################################################
"""
def ErrorQuery(err_path: str, err_mode: str, err_obj: object):
    # If file does not exist #
    if err_obj.errno == errno.ENOENT:
        PrintErr(f'{err_path} does not exist', 2)

    # If the file does not have read/write access #
    elif err_obj.errno == errno.EPERM:
        PrintErr(f'{err_path} does not have permissions for {err_mode} file mode, if file exists confirm it is closed', 2)

    # File IO error occurred #
    elif err_obj.errno == errno.EIO:
        PrintErr(f'IO error occurred during {err_mode} mode on {err_path}', 2)

    # If other unexpected file operation occurs #
    else:
        PrintErr(f'Unexpected file operation occurred accessing {err_path}: {err_obj.errno}', 2)


"""
########################################################################################################################
Name:       FetchUploadComps
Purpose:    Retrieves upload components from keys database. 
Parameters: The keys database, key name to be retrieved, nonce name to be retrieved, and authentication object.
Returns:    Decrypt key and nonce query results.
########################################################################################################################
"""
def FetchUploadComps(db: str, key_name: str, nonce_name: str, auth_obj: object) -> tuple:
    # Retrieve decrypt key from database #
    query = Globals.DB_RETRIEVE(db, key_name)
    decrypt_query = QueryHandler(db, query, auth_obj, fetchone=True)

    # Retrieve nonce from database #
    query = Globals.DB_RETRIEVE(db, nonce_name)
    nonce_query = QueryHandler(db, query, auth_obj, fetchone=True)

    # Return fetched query results #
    return decrypt_query, nonce_query


"""
########################################################################################################################
Name:       FileHandler
Purpose:    Error validated file handler for read and write operations.
Parameters: The filename, file operation, password object, read/write operation toggle, and input data toggle. 
Returns:    Nothing
########################################################################################################################
"""
def FileHandler(filename: str, op: str, auth_obj: object, operation=None, data=None):
    count, sleep_time = 0, 1

    while True:
        # If loop is past first iteration #
        if count > 0:
            # Extend sleep time by a second #
            sleep_time += 1

        try:
            with open(filename, op) as file:
                # If read operation was specified #
                if operation == 'read':
                    return file.read()
                # If write operation was specified #
                elif operation == 'write':
                    return file.write(data)
                # If improper operation specified #
                else:
                    PrintErr('File IO Error: Improper file operation attempted', 2)
                    # If password is set #
                    if Globals.HAS_KEYS:
                        # Log error #
                        Logger('File IO Error: Improper file operation attempted\n\n',
                               auth_obj, operation='write', handler='error')
                    return

        # If error occurs during file operation #
        except (IOError, FileNotFoundError, OSError) as err:
            # Look up file error #
            ErrorQuery(filename, op, err)

            # If password is set #
            if Globals.HAS_KEYS:
                Logger(f'File IO Error: {err}\n\n', auth_obj, operation='write', handler='error')

            # If three consecutive IO errors occur #
            if count == 3:
                PrintErr('Maximum consecutive File IO errors detected .. check log & contact support', None)
                exit(6)

            time.sleep(sleep_time)
            count += 1


"""
########################################################################################################################
Name:       GetDatabaseComp
Purpose:    Unlock and retrieve database cryptography component.
Parameters: The authentication object.
Returns:    The decrypted database decryption key.
########################################################################################################################
"""
def GetDatabaseComp(auth_obj: object) -> bytes:
    # Decrypt the password #
    plain = auth_obj.GetPlainSecret()
    # Decrypt the local database key #
    return auth_obj.DecryptDbKey(plain)


"""
########################################################################################################################
Name:       HdCrawl
Purpose:    Recursive hard drive crawler for recovering missing components.
Parameters: The list of missing item(s) to be recovered.
Returns:    Boolean True/False whether operation was success/fail.
########################################################################################################################
"""
def HdCrawl(items: list) -> list:
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
                if items[0].endswith('.db') and items[0].endswith('.txt'):
                    break

                # Iterate through passed in missing list #
                for item in items:
                    # If the folder and item are CryptDbs #
                    if folder == item == 'CryptDbs':
                        # Copy and delete source folder #
                        DataCopy(f'{dir_path}\\{folder}', Globals.DIRS[0])
                        print(f'Folder: {item} recovered')
                        # Remove recovered item from missing list #
                        items.remove(item)
                        break

                    # If the folder and item are CryptImport #
                    elif folder == item == 'CryptImport':
                        # Copy and delete source folder #
                        DataCopy(f'{dir_path}\\{folder}', Globals.DIRS[1])
                        print(f'Folder: {item} recovered')
                        # Remove recovered item from missing list #
                        items.remove(item)
                        break

                    # If the folder and item are CryptKeys #
                    elif folder == item == 'CryptKeys':
                        # Copy and delete source folder #
                        DataCopy(f'{dir_path}\\{folder}', Globals.DIRS[2])
                        print(f'Folder: {item} recovered')
                        # Remove recovered item from missing list #
                        items.remove(item)
                        break

                    # If the folder and item are DecryptDock #
                    elif folder == item == 'DecryptDock':
                        # Copy and delete source folder #
                        DataCopy(f'{dir_path}\\{folder}', Globals.DIRS[3])
                        print(f'Folder: {item} recovered')
                        # Remove recovered item from missing list #
                        items.remove(item)
                        break

                    # If the folder and item are UploadDock #
                    elif folder == item == 'UploadDock':
                        # Copy and delete source folder #
                        DataCopy(f'{dir_path}\\{folder}', Globals.DIRS[4])
                        print(f'Folder: {item} recovered')
                        # Remove recovered item from missing list #
                        items.remove(item)
                        break

        # Iterate through files in current dir #
        for file in file_names:
            # Iterate through passed in failed items #
            for item in items:
                # If item is not a file #
                if not item.endswith('.dbs') or not item.endswith('.txt'):
                    continue

                # If file is text #
                if file.endswith('txt') and file == item:
                    # If file is one of the key components #
                    if file in ('aesccm.txt', 'nonce.txt', 'db_crypt.txt', 'secret_key.txt'):
                        # Copy and delete source file #
                        DataCopy(f'{dir_path}\\{file}', f'{Globals.DIRS[2]}\\{file}')
                        print(f'File: {item}.txt recovered')
                        # Remove recovered item from missing list #
                        items.remove(item)
                        break

                # If file is database #
                elif file.endswith('.db') and file == item:
                    if file in ('crypt_keys.db', 'crypt_storage.db'):
                        # Copy and delete source file #
                        DataCopy(f'{dir_path}\\{file}', f'{Globals.DIRS[0]}\\{file}')
                        print(f'File: {item}.db recovered')
                        # Remove recovered item from missing list #
                        items.remove(item)
                        break

    return items


"""
########################################################################################################################
Name:       Logger
Purpose:    Encrypted logging system.
Parameters: Message to be logged, hashed password, log operation, and logging level handler.
Returns:    Nothing
########################################################################################################################
"""
def Logger(msg: str, auth_obj: object, operation=None, handler=None):
    log_name = f'{Globals.CWD}\\cryptLog.log'
    text = None

    # Decrypt the password #
    plain = auth_obj.GetPlainSecret()
    # Decrypt the local database key #
    db_key = auth_obj.DecryptDbKey(plain)

    # If read operation and log file exists #
    if operation == 'read' and Globals.FILE_CHECK(log_name):
        # Get log file size in bytes #
        log_size = os.stat(log_name).st_size

        # If log has data in it #
        if log_size > 0:
            # Read the encrypted log data #
            crypt = FileHandler(log_name, 'rb', auth_obj, operation='read')
            # Decrypt the encrypted log data #
            plain = DecryptDbData(db_key, crypt)
            # Decode byte data #
            text = plain.decode()
    # If log file does not exist #
    else:
        # Set artificially low value #
        log_size = -1

    # If writing to the log #
    if operation == 'write':
        # If writing error #
        if handler == 'error':
            logging.error(f'\n\n{msg}\n')
        # If writing exception #
        elif handler == 'exception':
            logging.exception(f'\n\n{msg}\n')
        else:
            logging.error(f'\n\nError message write: \"{msg}\" provided '
                          'without proper handler parameter\n')

        # If the file already has text #
        if text:
            WriteLog(log_name, db_key)
        else:
            WriteLog(log_name, db_key)

    # If reading the log #
    elif operation == 'read':
        # If log file is has data, read it #
        if log_size > 0:
            count = 0

            # Print log page by page #
            for line in text.split('\n'):
                if count == 60:
                    input('Hit enter to continue ')
                    count = 0

                print(line)
                count += 1

            input('Hit enter to continue ')
        else:
            PrintErr('No data to read in log file', 2)

    # If operation not specified #
    else:
        logging.error('\n\nNo logging operation specified\n')

        # If the file already has text #
        if text:
            WriteLog(log_name, db_key)
        else:
            WriteLog(log_name, db_key)


"""
########################################################################################################################
Name:       MakeKeys
Purpose:    Creates a fresh cryptographic key set, encrypts, and inserts in keys database.
Parameters: The database tuple, hashed password, and authentication object.
Returns:    The populated authentication object.
########################################################################################################################
"""
def MakeKeys(db: str, password: str, auth_obj: object) -> object:
    bytes_pass = password.encode()

    # Initialize argon2 hasher #
    pass_algo = PasswordHasher()
    # Hash the input password #
    input_hash = pass_algo.hash(bytes_pass)

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
    crypt_db = aesccm.encrypt(nonce, db_key, bytes_pass)

    # Add encrypted password hash to key ring #
    keyring.set_password('CryptDrive', 'CryptUser', crypt_hash.decode('utf-8'))

    # Set authentication object variables #
    auth_obj.aesccm = key
    auth_obj.nonce = nonce
    auth_obj.db_key = crypt_db
    auth_obj.secret_key = secret_key
    auth_obj.password = crypt_hash

    # Send encrypted ChaCha20 key to key's database #
    query = Globals.DB_INSERT(db, 'upload_key', upload_key.decode('utf-8'))
    QueryHandler(db, query, None)

    # Send encrypted ChaCha20 nonce to keys database #
    query = Globals.DB_INSERT(db, 'upload_nonce', cha_nonce.decode('utf-8'))
    QueryHandler(db, query, None)

    # Write AESCCM key and nonce to files #
    FileHandler(Globals.FILES[0], 'wb', None, operation='write', data=key)
    FileHandler(Globals.FILES[1], 'wb', None, operation='write', data=nonce)

    # Write db key and secret key to files #
    FileHandler(Globals.FILES[2], 'wb', None, operation='write', data=crypt_db)
    FileHandler(Globals.FILES[3], 'wb', None, operation='write', data=secret_key)

    Globals.HAS_KEYS = True

    return auth_obj


"""
########################################################################################################################
Name:       MetaStrip
Purpose:    Attempts striping metadata from passed in file. If attempt fails, waiting a second and tries again while \
            adding a second of waiting time per failure. After 3 failed attempts, it returns a False boolean value.
Parameters: The path to the file who's metadata to be stripped.
Returns:    Boolean, True if successful and False if fail.
########################################################################################################################
"""
def MetaStrip(file_path: str) -> bool:
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

        # If file IO error occurs #
        except (AttributeError, KeyError, IOError):
            # If 3 failed attempts #
            if count == 3:
                return False

            # If not false KeyError #
            if not KeyError:
                time.sleep(sleep_time)
                count += 1
                continue

        return True


"""
########################################################################################################################
Name:       MsgFormat
Purpose:    Format email message headers and attach passed in files.
Parameters: Senders email address, receivers email address, message body, and files to be attached.
Returns:    The formatted message with attachments.
########################################################################################################################
"""
def MsgFormat(send_email: str, receiver: str, body: str, files: str) -> object:
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
        p = MIMEBase('application', 'octet-stream')
        # Open file and read data as attachment #
        with open(file, 'rb') as attachment:
            p.set_payload(attachment.read())

        # Encode & attach current file #
        encoders.encode_base64(p)
        # Add header to attachment #
        p.add_header('Content-Disposition', f'attachment;filename = {file}')
        # Attach attachment to email #
        msg.attach(p)

    return msg


"""
########################################################################################################################
Name:       MsgSend
Purpose:    Facilitate the sending of formatted emails.
Parameters: Senders email address, receivers email address, hashed password, formatted message to be sent.
Returns:    Nothing
########################################################################################################################
"""
def MsgSend(send_email: str, receiver: str, password: str, msg: object, auth_obj: object):
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
        PrintErr('Remote email server connection failed', 2)
        Logger(f'SMTP Error: {err}\n\n', auth_obj, operation='write', handler='error')


"""
########################################################################################################################
Name        PrintErr
Purpose:    Displays error message for supplied time interval.
Parameters: The message to be displayed and the time interval to be displayed in seconds.
Returns:    Nothing
########################################################################################################################
"""
def PrintErr(msg: str, seconds):
    print(f'\n* [ERROR] {msg} *\n', file=sys.stderr)
    # If seconds has value (not None) #
    if seconds:
        time.sleep(seconds)


"""
########################################################################################################################
Name:       QueryHandler
Purpose:    Facilitates MySQL database query execution.
Parameters: Database to execute query, query to be executed, password object, create toggle, fetchone toggle, and \
            fetchall toggle.
Returns:    Nothing
########################################################################################################################
"""
def QueryHandler(db: str, query: str, auth_obj: object, create=False, fetchone=False, fetchall=False):
    # Change directory #
    os.chdir(Globals.DIRS[0])
    # Sets maximum number of allowed db connections #
    maxConns = 1
    # Locks allowed connections to database #
    sema_lock = BoundedSemaphore(value=maxConns)

    # Attempts to connect, continues if already connected #
    with sema_lock:
        try:
            # Connect to passed in database #
            conn = sqlite3.connect(f'{db}.db')

        # If database already exists #
        except Error:
            pass

        # Executes query passed in #
        try:
            db_call = conn.execute(query)

            # If creating database close connection
            # and moves back a directory #
            if create:
                conn.close()
                os.chdir(Globals.CWD)
                return

            # Fetches entry from database then closes
            # connection and moves back a directory #
            elif fetchone:
                row = db_call.fetchone()
                conn.close()
                os.chdir(Globals.CWD)
                return row

            # Fetches all database entries then closes
            # connection and moves back a directory #
            elif fetchall:
                rows = db_call.fetchall()
                conn.close()
                os.chdir(Globals.CWD)
                return rows

            # Commit query to db #
            conn.commit()

        # Database query error handling #
        except (Warning, Error, DatabaseError, IntegrityError,
                ProgrammingError, OperationalError, NotSupportedError) as err:
            # Prints general error #
            PrintErr(f'SQL error: {err}', 2)

            # If password is set #
            if Globals.HAS_KEYS:
                # Passes log message to logging function #
                Logger(f'SQL error: {err}\n\n', auth_obj, operation='write', handler='error')

        # Close connection #
        conn.close()
        # Move back a directory #
        os.chdir(Globals.CWD)


"""
########################################################################################################################
Name:       SecureDelete
Purpose:    Overwrite file data with random data number of specified passes and delete.
Parameters: Path to the file to overwritten and deleted and the number of passes.
Returns:    Nothing
########################################################################################################################
"""
def SecureDelete(path: str, passes=5):
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
        PrintErr(f'Error overwriting file for secure delete: {err}', 2)

    os.remove(path)


"""
########################################################################################################################
Name:       SystemCmd
Purpose:    Execute shell-escaped system command.
Parameters: Command to be executed, standard output, standard error, execution timeout, exif toggle, cipher toggle.
Returns:    Nothing
########################################################################################################################
"""
def SystemCmd(cmd: str, stdout, stderr, exec_time: int):
    # Shell-escape command syntax #
    exe = shlex.quote(cmd)
    # For built-in shell commands like (cls, clear) #
    command = Popen(exe, stdout=stdout, stderr=stderr, shell=True)

    try:
        # Execute command with passed in timeout threshold #
        command.communicate(exec_time)

    # Handles process timeouts and errors #
    except (SubprocessError, TimeoutExpired, CalledProcessError, OSError, ValueError):
        command.kill()
        command.communicate()


"""
########################################################################################################################
Name:       WriteLog
Purpose:    Parse new log message to old data and write encrypted result to log.
Parameters: Log name and database key.
Returns:    Nothing
########################################################################################################################
"""
def WriteLog(log_name: str, db_key: bytes):
    # Get log message in variable #
    log_msg = Globals.LOG_STREAM.getvalue()

    try:
        with open(log_name, 'w') as file:
            # Encrypt log data & store on file #
            crypt = EncryptDbData(db_key, log_msg.encode())
            file.write(crypt)

    except (IOError, FileNotFoundError, Exception) as err:
        PrintErr(f'Error occurred writing {log_msg} to Logger:\n{err}', 2)
        sys.exit(9)
