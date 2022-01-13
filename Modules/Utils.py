# Built-in Modules #
from base64 import b64encode
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from subprocess import Popen, SubprocessError, TimeoutExpired, CalledProcessError
from sys import stderr
from threading import BoundedSemaphore
from time import sleep
from sqlite3 import Warning, Error, DatabaseError, IntegrityError, \
                    ProgrammingError, OperationalError, NotSupportedError
import os, logging, re, shlex, shutil, smtplib, sqlite3 

# Third-party Modules #
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.fernet import Fernet
from filelock import FileLock, Timeout
import keyring

# Custom Modules #
import Modules.Globals as Globals

# # Function Index #
# -------------------
# - FileHandler:    handlers file read / write operations
# - HdCrawl:        checks user file system for missing component 
# - KeyHandler:     deletes existing keys & dbs, calls function to make new components
# - Logger:         encrypted logging system
# - MakeKeys:       creates/encrypts keys and dbs, stores hash in application keyring
# - MsgFormat:      formats email message headers, data, and attachments
# - MsgSend:        facilitates sending email via TLS connection
# - PrintErr:       prints er message the duration of the integer passed in
# - QueryHandler:   Mydatabase query handling function for creating, populating, and retrieving data from dbs
# - SystemCmd:      executes system shell command

# File operation handler #
def FileHandler(filename, op, password, operation=None, data=None):
    count = 0

    while True:
        try:
            # Set file lock #
            with FileLock(filename + '.lock', timeout=3):
                # Open file #
                with open(filename, op) as file:
                    # If no operation was specified #
                    if operation == None:
                        Logger('File IO Error: File opertion not specified\n', password, \
                                operation='write', handler='error')
                        return

                    # If read operation was specified #
                    elif operation == 'read':
                        return file.read()

                    # If write operatiob was specified #
                    elif operation == 'write':
                        # If no data is present #
                        if data == None:
                            Logger('File IO Error: Empty file buffered detected\n', password, \
                                    operation='write', handler='error')
                            return

                        return file.write(data)
                        
                    # If improper operation specified #
                    else:
                        Logger('File IO Error: Improper file opertion attempted\n', password, \
                                operation='write', handler='error')
            break

        # File error handling #
        except (Timeout, IOError, FileNotFoundError, Exception) as err:
            if count == 4:
                PrintErr('\n* [ERROR] Maximum consecutive File Lock/IO errors detected .. check log & contact support *\n', 4)
                exit(3)

            Logger(f'File Lock/IO Error: {err}\n', password, \
                    operation='write', handler='error')
            PrintErr('\n* [ERROR] File Lock/IO failed .. waiting 5 seconds before attempting again *\n', 2)
            count += 1

def HdCrawl(item):
    # Crawl through user directories #
    for dirpath, dirnames, filenames in os.walk('C:\\Users\\', topdown=True):
        for folder in dirnames:
            if folder == item == 'Dbs':
                shutil.move(dirpath + '\\' + folder, '.\\Dbs')
                return True
            elif folder == item == 'DecryptDock':
                shutil.move(dirpath + '\\' + folder, '.\\DecryptDock')
                return True
            elif folder == item == 'Import':
                shutil.move(dirpath + '\\' + folder, '.\\Import')
                return True
            elif folder == item == 'Keys':
                shutil.move(dirpath + '\\' + folder, '.\\Keys')
                return True
            elif folder == item == 'UploadDock':
                shutil.move(dirpath + '\\' + folder, '.\\UploadDock')
                return True

        for file in filenames:
            # If item matches .txt, move to Keys dir #
            if file == (item + '.txt'):
                shutil.move(dirpath + '\\' + file, '.\\Keys\\' + file)
                print(f'{item}.txt recovered')
                return True

            # If item matches .db, move to DBs dir #
            elif file == (item + '.db'):
                shutil.move(dirpath + '\\' + file, '.\\Dbs\\' + file)
                print(f'{item}.db recovered')
                return True

    return False

# Delete existing keys, create dbs, and call 
# function to make a new set of keys #
def KeyHandler(dbs, password):
    # Delete files if they exist #
    for file in ('.\\Keys\\db_crypt.txt', '.\\Keys\\aesccm.txt', \
    '.\\Keys\\nonce.txt', '.\\Dbs\\keys.db', '.\\Dbs\\storage.db'): 
        if Globals.file_check(file) == True:
            os.remove(file)

    # Create databases #
    for db in dbs:
        query =  Globals.db_create(db)
        QueryHandler(db, query, password, create=True)

    # Create encryption keys #
    MakeKeys(dbs[0], password)

# Encrypted log handler #
def Logger(msg, password, operation=None, handler=None):
    if Globals.log:
        # Check to see cryptographic components are present #
        key_check, nonce_check, dbKey_check = Globals.file_check('.\\Keys\\aesccm.txt'), \
                                              Globals.file_check('.\\Keys\\nonce.txt'), \
                                              Globals.file_check('.\\Keys\\db_crypt.txt')

        # If cryptographic component is missing print error & exit function #
        if not key_check or not nonce_check or not dbKey_check:
            PrintErr(f'\n* [ERROR] Attempt to access decrypt log missing unlock components logging ..\n{msg} *\n', 2)
            return

        # Load AESCCM components #
        key = FileHandler('.\\Keys\\aesccm.txt', 'rb', password, operation='read')
        nonce = FileHandler('.\\Keys\\nonce.txt', 'rb', password, operation='read')
        aesccm = AESCCM(key)

        # Decrypt the local database key #
        crypt = FileHandler('.\\Keys\\db_crypt.txt', 'rb', password, operation='read')
        db_key = aesccm.decrypt(nonce, crypt, password)

        # If data exists in log file #
        if os.stat('cryptLog.log').st_size > 0:
            # Decrypt the cryptLog #
            crypt = FileHandler('cryptLog.log', 'rb', password, operation='read')
            plain = Fernet(db_key).decrypt(crypt)
            FileHandler('cryptLog.log', 'wb', password, operation='write', data=plain)

        # If writing to the log #
        if operation == 'write':
            try:
                with FileLock('cryptLog.log.lock', timeout=3):
                    # If writing error #
                    if handler == 'error':
                        logging.error(msg)
                    # If writing exception #
                    elif handler == 'exception':
                        logging.exception(msg)
                    else:
                        logging.error(f'Error message write: \"{msg}\" provided without proper handler parameter\n')
            except Timeout:
                PrintErr('\n* [ERROR] CryptLog failed to obtain file lock *\n', 2)

        # If reading the log #
        elif operation == 'read':
            # If no data to read .. exit function #        
            if os.stat('cryptLog.log').st_size == 0:
                return
            else:
                count = 0

                # Print log page by page #
                for line in plain.split('\n'):
                    if count == 60:
                        input('Hit enter to continue')
                        count = 0

                    print(line)
                    count += 1

                input('Hit enter to continue')
        else:
            try:
                with FileLock('cryptLog.log.lock', timeout=30):
                    logging.error('No logging operation specified')
            except Timeout:
                PrintErr('\n* [ERROR] CryptLog failed to obtain file lock *\n', 2)

        # If no data in log .. exit function #
        if os.stat('cryptLog.log').st_size == 0:
            return

        # Encrypt the cryptLog #
        plain = FileHandler('cryptLog.log', 'rb', password, operation='read')
        crypt = Fernet(db_key).encrypt(plain)
        FileHandler('cryptLog.log', 'wb', password, operation='write', data=crypt)
    else:
        PrintErr(f'\n* [ERROR] Exception occured on startup script: {msg} *\n', 2)

# Make cryptographic key-set #
def MakeKeys(db, password):
    # Fernet Symmetric HMAC key for dbs #
    db_key = Fernet.generate_key()

    # ChaCha20 symmetric key (256 bit key, 128 bit nonce) #
    upload_key = b64encode(os.urandom(32))
    cha_nonce = b64encode(os.urandom(16))

    # Encrypt ChaCha20 upload components #
    upload_key = Fernet(db_key).encrypt(upload_key)
    cha_nonce = Fernet(db_key).encrypt(cha_nonce)

    # Send encrypted ChaCha20 key to keys database #
    query =  Globals.db_insert(db, 'upload_key', upload_key.decode('utf-8'))
    QueryHandler(db, query, password)

    # Send encrypted ChaCha20 nonce to keys database # 
    query =  Globals.db_insert(db, 'upload_nonce', cha_nonce.decode('utf-8'))
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

# Format email message #
def MsgFormat(send_email, receiver, body, files):
    # Initial message object & format headers/body #
    msg = MIMEMultipart()
    msg['From'] = send_email
    msg['To'] = receiver
    msg['Subject'] = 'Cloud Encryptor Package'
    msg.attach(MIMEText(body, 'plain'))

    # Iterate through msg files #
    for file in files:
        if file == None:
            return msg

        # Initalize stream to attach data #
        p = MIMEBase('application', 'octet-stream')
        with open(file, 'rb') as attachment:
            p.set_payload(attachment.read())

        # Encode & attach current file #
        encoders.encode_base64(p)
        p.add_header('Content-Disposition', f'attachment;filename = {file}')
        msg.attach(p)

    return msg

# Facilitate sending email #
def MsgSend(send_email, receiver, password, msg):
    # Initialize SMTP session with gmail server #
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as session:
            # Upgrade session To TLS encryption & login #
            session.starttls() ; session.login(send_email, password)
            # Send email through established session #
            session.sendmail(send_email, receiver, msg.as_string())
            # Disconnect session #
            session.quit()
    except smtplib.SMTPException as err:
        PrintErr('\n* [ERROR] Remote email server connection failed *\n', 2)
        Logger(f'SMTP Error: {err}', password, \
                operation='write', handler='error')

# Timed error message #
def PrintErr(msg, seconds):
    print(msg, file=stderr)
    sleep(seconds)

# MySQL database query handler #
def QueryHandler(db, query, password, create=False, fetchone=False):
    os.chdir('.\\Dbs')
    maxConns = 1
    # Locks allowed connections to database #
    sema_lock = BoundedSemaphore(value=maxConns)

    # Attempts to connnect .. continues if already connected #
    with sema_lock:
        try:
            conn = sqlite3.connect(f'{db}.db')  
        except:
            pass

        # Executes query, either fetches data or commits queries #
        try:
            db_call = conn.execute(query)

            if create == True:
                conn.close()
                os.chdir('.\\..')
                return

            elif fetchone == True:
                row = db_call.fetchone()
                conn.close()
                os.chdir('.\\..')
                return row

            conn.commit()

        # Database query error handling #
        except (Warning, Error, DatabaseError, IntegrityError, \
        ProgrammingError, OperationalError, NotSupportedError) as err:
            PrintErr('\n* [ERROR] Database error occured *\n', 2)
            Logger(f'SQL error: {err}\n', password, \
                    operation='write', handler='error')

        conn.close()
        os.chdir('.\\..')

# Run system command #
def SystemCmd(cmd, stdout, stderr, exec_time):
    exe = shlex.quote(cmd)
    try:
        command = Popen(exe, stdout=stdout, stderr=stderr, shell=True)
        outs, errs = command.communicate(exec_time)
    except (SubprocessError, TimeoutExpired, CalledProcessError, OSError, ValueError):
        command.kill()
        outs, errs = command.communicate()