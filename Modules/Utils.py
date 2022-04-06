# Built-in Modules #
import os
import logging
import shlex
import shutil
import smtplib
import sqlite3
import sys
from base64 import b64encode
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from subprocess import Popen, SubprocessError, TimeoutExpired, CalledProcessError
from threading import BoundedSemaphore
from time import sleep
from sqlite3 import Warning, Error, DatabaseError, IntegrityError, \
                    ProgrammingError, OperationalError, NotSupportedError

# Third-party Modules #
import keyring
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.fernet import Fernet

# Custom Modules #
import Modules.Globals as Globals

"""
###################
#  Function Index #
########################################################################################################################
FileHandler - Handles file read / write operations.
HdCrawl - Checks user file system for missing component.
KeyHandler - Deletes existing keys & dbs, calls function to make new components.
Logger - Encrypted logging system.
MakeKeys - Creates/encrypts keys and dbs, stores hash in application keyring.
MsgFormat - Formats email message headers, data, and attachments.
MsgSend - Facilitates sending email via TLS connection.
PrintErr - Prints error message the duration of the integer passed in.
QueryHandler - MySQL database query handling function for creating, populating, and retrieving data from dbs.
SystemCmd - Executes system shell command.
########################################################################################################################
"""


"""
########################################################################################################################
Name:       FileHandler
Purpose:    Error validated file handler for read and write operations.
Parameters: The filename, file operation, hashed password, read/write operation toggle, and input data toggle. 
Returns:    None
########################################################################################################################
"""
def FileHandler(filename: str, op: str, password: bytes, operation=None, data=None):
    count = 0

    # If no operation was specified #
    if not operation:
        Logger('File IO Error: File operation not specified\n', password, operation='write', handler='error')
        PrintErr('\n* File IO Error: File operation not specified *\n', 2)
        return

    # If read operation and file is missing #
    if operation == 'read' and not Globals.FILE_CHECK(filename):
        Logger('File IO Error: File read attempted on either missing file\n', password,
               operation='write', handler='error')
        PrintErr('\n* File IO Error: File read attempted on either missing file *\n', 2)
        return

    # If read operation and file does not have access #
    if operation == 'read' and not os.access(filename, os.R_OK):
        Logger('File IO Error: File read attempted on file with no access .. potentially already in use\n', password,
               operation='write', handler='error')
        PrintErr('\n* File IO Error: File read attempted on file with no access .. potentially already in use *\n', 2)
        return

    # If write operation and file exists, but does not have access #
    if operation == 'write' and Globals.FILE_CHECK(filename) and not os.access(filename, os.W_OK):
        Logger('File IO Error: File write attempted on file with no access .. potentially already in use\n', password,
               operation='write', handler='error')
        PrintErr('\n* File IO Error: File operation not specified *\n', 2)
        return

    while True:
        try:
            with open(filename, op) as file:
                # If read operation was specified #
                if operation == 'read':
                    return file.read()

                # If write operation was specified #
                elif operation == 'write':
                    # If no data is present #
                    if not data:
                        Logger('File IO Error: Empty file buffered detected\n', password,
                               operation='write', handler='error')
                        return

                    return file.write(data)

                # If improper operation specified #
                else:
                    Logger('File IO Error: Improper file operation attempted\n',
                           password, operation='write', handler='error')
                    return

        # File error handling #
        except (IOError, FileNotFoundError, Exception) as err:
            if count == 3:
                PrintErr('\n* [ERROR] Maximum consecutive File IO errors'
                         ' detected .. check log & contact support *\n', 4)
                exit(3)

            print(f'\nIO Error: {err}\n')

            Logger(f'File IO Error: {err}\n', password, operation='write', handler='error')
            PrintErr('\n* [ERROR] File Lock/IO failed .. waiting 5'
                     ' seconds before attempting again *\n', 2)
            count += 1


"""
########################################################################################################################
Name:       HdCrawl
Purpose:    Recursive hard drive crawler for recovering missing components.
Parameters: Name of the item to be recovered.
Returns:    Boolean True/False whether operation was success/fail.
########################################################################################################################
"""
def HdCrawl(item: str) -> bool:
    # Crawl through user directories #
    for dir_path, dir_names, file_names in os.walk('C:\\Users\\', topdown=True):
        for folder in dir_names:
            if folder == item == 'Dbs':
                shutil.move(f'{dir_path}\\{folder}', '.\\Dbs')
                print(f'Folder: {item} recovered')
                return True

            elif folder == item == 'DecryptDock':
                shutil.move(f'{dir_path}\\{folder}', '.\\DecryptDock')
                print(f'Folder: {item} recovered')
                return True

            elif folder == item == 'Import':
                shutil.move(f'{dir_path}\\{folder}', '.\\Import')
                print(f'Folder: {item} recovered')
                return True

            elif folder == item == 'Keys':
                shutil.move(f'{dir_path}\\{folder}', '.\\Keys')
                print(f'Folder: {item} recovered')
                return True

            elif folder == item == 'UploadDock':
                shutil.move(f'{dir_path}\\{folder}', '.\\UploadDock')
                print(f'Folder: {item} recovered')
                return True

        for file in file_names:
            # If item matches .txt, move to Keys dir #
            if file == (item + '.txt'):
                shutil.move(f'{dir_path}\\{file}', '.\\Keys\\' + file)
                print(f'File: {item}.txt recovered')
                return True

            # If item matches .db, move to DBs dir #
            elif file == (item + '.db'):
                shutil.move(f'{dir_path}\\{file}', '.\\Dbs\\' + file)
                print(f'File: {item}.db recovered')
                return True

    return False


"""
########################################################################################################################
Name:       KeyHandler
Purpose:    Delete existing keys, create dbs, and call function to create new key set.
Parameters: The database tuple and hashed password.
Returns:    None
########################################################################################################################
"""
def KeyHandler(dbs: tuple, password: bytes):
    # Delete files if they exist #
    for file in ('.\\Keys\\db_crypt.txt', '.\\Keys\\aesccm.txt', '.\\Keys\\nonce.txt',
                 '.\\Dbs\\keys.db', '.\\Dbs\\storage.db'):
        if Globals.FILE_CHECK(file):
            os.remove(file)

    # Create databases #
    for db in dbs:
        if db == 'keys':
            query = Globals.DB_KEYS(db)
        elif db == 'storage':
            query = Globals.DB_STORAGE(db)
        else:
            continue

        QueryHandler(db, query, password, create=True)

    # Create encryption keys #
    MakeKeys(dbs[0], password)


"""
########################################################################################################################
Name:       Logger
Purpose:    Encrypted logging system.
Parameters: Message to be logged, hashed password, log operation, and logging level handler.
Returns:    None
########################################################################################################################
"""
def Logger(msg: str, password: bytes, operation=None, handler=None):
    if Globals.LOG:
        log_name = '.\\cryptLog.log'
        text = None

        # Check to see cryptographic components are present #
        key_check, nonce_check, dbKey_check = Globals.FILE_CHECK('.\\Keys\\aesccm.txt'), \
                                              Globals.FILE_CHECK('.\\Keys\\nonce.txt'), \
                                              Globals.FILE_CHECK('.\\Keys\\db_crypt.txt')

        # If cryptographic component is missing print error & exit function #
        if not key_check or not nonce_check or not dbKey_check:
            PrintErr('\n* [ERROR] Attempt to access decrypt log missing'
                     f' unlock components logging ..\n{msg} *\n', 2)
            return

        # Load AESCCM components #
        key = FileHandler('.\\Keys\\aesccm.txt', 'rb', password, operation='read')
        nonce = FileHandler('.\\Keys\\nonce.txt', 'rb', password, operation='read')
        aesccm = AESCCM(key)

        # Decrypt the local database key #
        crypt = FileHandler('.\\Keys\\db_crypt.txt', 'rb', password, operation='read')
        db_key = aesccm.decrypt(nonce, crypt, password)

        # If data exists in log file #
        if Globals.FILE_CHECK(log_name):
            # Get log file size in bytes #
            log_size = os.stat(log_name).st_size

            # If log has data in it #
            if log_size > 0:
                # Decrypt the cryptLog #
                crypt = FileHandler(log_name, 'rb', password, operation='read')
                plain = Fernet(db_key).decrypt(crypt)
                text = plain.decode()
        else:
            # Set artificially low value #
            log_size = -1

        # If writing to the log #
        if operation == 'write':
            # If writing error #
            if handler == 'error':
                logging.error(msg)
            # If writing exception #
            elif handler == 'exception':
                logging.exception(msg)
            else:
                logging.error(f'Error message write: \"{msg}\" provided without proper handler parameter\n')

            # Get log message in variable #
            log_msg = Globals.LOG_STREAM.getvalue()

            try:
                with open(log_name, 'wb') as file:
                    # If log has data & is less than the 25 mb max size #
                    if 0 < log_size < 26214400:
                        # Append new log message to existing log #
                        log_parse = text + '\n' + log_msg
                        # Encrypt log data & store on file #
                        crypt = Fernet(db_key).encrypt(log_parse.encode())
                        file.write(crypt)
                    else:
                        # Encrypt log data & store on file #
                        crypt = Fernet(db_key).encrypt(log_msg.encode())
                        file.write(crypt)

            except (IOError, FileNotFoundError, Exception):
                PrintErr(f'\n* [ERROR] Error occurred writing {msg} to Logger *\n', 2)

        # If reading the log #
        elif operation == 'read':
            # If log file exists
            if Globals.FILE_CHECK(log_name):
                # If log file is empty .. return function #
                if log_size == 0:
                    return
                else:
                    count = 0

                    # Print log page by page #
                    for line in text.split('\n'):
                        if count == 60:
                            input('Hit enter to continue ')
                            count = 0

                        print(line)
                        count += 1

                    input('Hit enter to continue ')

        # If operation not specified #
        else:
            logging.error('No logging operation specified')

            # Get log message in variable #
            log_msg = Globals.LOG_STREAM.getvalue()
            try:
                with open(log_name, 'wb') as file:
                    # If log has data & is less than the 25 mb max size #
                    if 0 < log_size < 26214400:
                        # Append new log message to existing log #
                        log_parse = text + '\n' + log_msg
                        # Encrypt log data & store on file #
                        crypt = Fernet(db_key).encrypt(log_parse.encode())
                        file.write(crypt)
                    else:
                        # Encrypt log data & store on file #
                        crypt = Fernet(db_key).encrypt(log_msg.encode())
                        file.write(crypt)

            except (IOError, FileNotFoundError, Exception):
                PrintErr(f'\n* [ERROR] Error occurred writing {msg} to Logger *\n', 2)
    else:
        PrintErr(f'\n* [ERROR] Exception occurred on startup script: {msg} *\n', 2)


"""
########################################################################################################################
Name:       MakeKeys
Purpose:    Creates a fresh cryptographic key set, encrypts, and inserts in keys database.
Parameters: The database tuple, hashed password.
Returns:    None
########################################################################################################################
"""
def MakeKeys(db: str, password: bytes):
    # Fernet Symmetric HMAC key for dbs #
    db_key = Fernet.generate_key()

    # ChaCha20 symmetric key (256-bit key, 128-bit nonce) #
    upload_key = b64encode(os.urandom(32))
    cha_nonce = b64encode(os.urandom(16))

    # Encrypt ChaCha20 upload components #
    upload_key = Fernet(db_key).encrypt(upload_key)
    cha_nonce = Fernet(db_key).encrypt(cha_nonce)

    # Send encrypted ChaCha20 key to key's database #
    query = Globals.DB_INSERT(db, 'upload_key', upload_key.decode('utf-8'))
    QueryHandler(db, query, password)

    # Send encrypted ChaCha20 nonce to keys database # 
    query = Globals.DB_INSERT(db, 'upload_nonce', cha_nonce.decode('utf-8'))
    QueryHandler(db, query, password)

    # AESCCM password authenticated key #
    key = AESCCM.generate_key(bit_length=256)
    aesccm = AESCCM(key)
    nonce = os.urandom(13)

    # Encrypt the db fernet key with AESCCM password key & write to file #
    crypt = aesccm.encrypt(nonce, db_key, password)
    FileHandler('.\\Keys\\db_crypt.txt', 'wb', password, operation='write', data=crypt)

    # Add password hash to key ring #
    keyring.set_password('CryptDrive', 'CryptUser', password.decode('utf-8'))

    # Write AESCCM key and nonce to files #     
    FileHandler('.\\Keys\\aesccm.txt', 'wb', password, operation='write', data=key)
    FileHandler('.\\Keys\\nonce.txt', 'wb', password, operation='write', data=nonce)


"""
########################################################################################################################
Name:       MsgFormat
Purpose:    Format email message headers and attach passed in files.
Parameters: Senders email address, receivers email address, message body, and files to be attached.
Returns:    The formatted message with attachments.
########################################################################################################################
"""
def MsgFormat(send_email: str, receiver: str, body: str, files: str):
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
        with open(file, 'rb') as attachment:
            p.set_payload(attachment.read())

        # Encode & attach current file #
        encoders.encode_base64(p)
        p.add_header('Content-Disposition', f'attachment;filename = {file}')
        msg.attach(p)

    return msg


"""
########################################################################################################################
Name:       MsgSend
Purpose:    Facilitate the sending of formatted emails.
Parameters: Senders email address, receivers email address, hashed password, formatted message to be sent.
Returns:    None
########################################################################################################################
"""
def MsgSend(send_email: str, receiver: str, password: bytes, msg):
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
    except smtplib.SMTPException as err:
        PrintErr('\n* [ERROR] Remote email server connection failed *\n', 2)
        Logger(f'SMTP Error: {err}', password, operation='write', handler='error')


"""
########################################################################################################################
Name        PrintErr
Purpose:    Displays error message for supplied time interval.
Parameters: The message to be displayed and the time interval to be displayed in seconds.
Returns:    None
########################################################################################################################
"""
def PrintErr(msg: str, seconds: int):
    print(msg, file=sys.stderr)
    sleep(seconds)


"""
########################################################################################################################
Name:       QueryHandler
Purpose:    Facilitates MySQL database query execution.
Parameters: Database to execute query, query to be executed, hashed password, create toggle, fetchone toggle, and \
            fetchall toggle.
Returns:    None
########################################################################################################################
"""
def QueryHandler(db: str, query: str, password: bytes, create=False, fetchone=False, fetchall=False):
    # Change directory #
    os.chdir('.\\Dbs')
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
                os.chdir('.\\..')
                return

            # Fetches entry from database then closes
            # connection and moves back a directory #
            elif fetchone:
                row = db_call.fetchone()
                conn.close()
                os.chdir('.\\..')
                return row

            # Fetches all database entries then closes
            # connection and moves back a directory #
            elif fetchall:
                rows = db_call.fetchall()
                conn.close()
                os.chdir('.\\..')
                return rows

            # Commit query to db #
            conn.commit()
            # Move back a directory #
            os.chdir('.\\..')

        # Database query error handling #
        except (Warning, Error, DatabaseError, IntegrityError,
                ProgrammingError, OperationalError, NotSupportedError) as err:
            # Prints general error #
            PrintErr('\n* [ERROR] Database error occurred *\n', 2)
            # Moves back a directory #
            os.chdir('.\\..')
            # Passes log message to logging function #
            Logger(f'SQL error: {err}\n', password, operation='write', handler='error')

        # Close connection #
        conn.close()


"""
########################################################################################################################
Name:       SystemCmd
Purpose:    Execute shell-escaped system command.
Parameters: Command to be executed, standard output, standard error, execution timeout, exif toggle, cipher toggle.
Returns:    None
########################################################################################################################
"""
def SystemCmd(cmd: str, stdout, stderr, exec_time: int, exif=False, cipher=False):
    # Shell escape command string #
    exe = shlex.quote(cmd)

    # Exif command to strip metadata #
    if exif:
        command = Popen(['python', '-m', 'exif_delete', '-r', exe], stdout=stdout, stderr=stderr, shell=False)
    # Cipher command to scrub deleted data from hd #
    elif cipher:
        command = Popen(['cipher', f'/w:{exe}'], stdout=stdout, stderr=stderr, shell=False)
    # For built-in Windows shell commands like cls #
    else:
        command = Popen(exe, stdout=stdout, stderr=stderr, shell=True)

    try:
        command.communicate(exec_time)

    # Handles process timeouts and errors #
    except (SubprocessError, TimeoutExpired, CalledProcessError, OSError, ValueError):
        command.kill()
        command.communicate()
