from filelock import FileLock
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.fernet import Fernet
from base64 import b64encode
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from time import sleep
from sys import stderr
from threading import BoundedSemaphore
from subprocess import Popen, SubprocessError, TimeoutExpired, CalledProcessError
import shlex, logging, re, os, sqlite3, winshell, smtplib
from sqlite3 import Warning, Error, DatabaseError, IntegrityError, \
                    ProgrammingError, OperationalError, NotSupportedError
import Modules.Globals as Globals

# Check recycling bin for file #
def bin_check(filename):
    # Retrieve recycling bin contents as list #
    rBin = list(winshell.recycle_bin())
    # Iterate through list #
    for file in rBin:
        # If either file type is matched .. 
        # restore from recycling bin #
        if file == filename + '.txt':
            winshell.undelete('.\\Keys\\' + file)
            return True
        elif file == filename + '.db':
            winshell.undelete('.\\Dbs\\' + file)
            return True
        else:
            pass

    return False

# File operation handler #
def file_handler(filename, op, password, operation=None, data=None):
    try:
        # Set file lock #
        with FileLock(filename + '.lock'):
            # Open file #
            with open(filename, op) as file:
                # If no operation was specified #
                if operation == None:
                    logger('File IO Error: File opertion not specified\n', password, \
                            operation='write', handler='error')
                    return
                # If read operation was specified #
                elif operation == 'read':
                    return file.read()
                # If write operatiob was specified #
                elif operation == 'write':
                    # If no data is present #
                    if data == None:
                        logger('File IO Error: Empty file buffered detected\n', password, \
                                operation='write', handler='error')
                        return

                    return file.write(data)
                # If improper operation specified #
                else:
                    logger('File IO Error: Improper file opertion attempted\n', password, \
                            operation='write', handler='error')

    # File error handling #
    except (IOError, FileNotFoundError, Exception) as err:
        logger(f'File IO Error: {err}\n', password, \
                operation='write', handler='error')

# Delete existing keys and call function
# to make a new set of keys #
def key_handler(dbs, password):
    # Delete files if they exist #
    for file in ('.\\Keys\\db_crypt.txt', '.\\Keys\\aesccm.txt', \
    '.\\Keys\\nonce.txt', '.\\Dbs\\keys.db', '.\\Dbs\\storage.db'): 
        if Globals.file_check(file) == True:
            os.remove(file)

    # Create databases #
    for db in dbs:
        query = Globals.db_create(db)
        query_handler(db, query, password, create=True)

    # Create encryption keys #
    make_keys(dbs[0], password)

# Encrypted log handler #
def logger(msg, password, operation=None, handler=None):
    # Load AESCCM components #
    key = file_handler('.\\Keys\\aesccm.txt', 'rb', password, operation='read')
    nonce = file_handler('.\\Keys\\nonce.txt', 'rb', password, operation='read')
    aesccm = AESCCM(key)

    # Decrypt the local database key #
    crypt = file_handler('.\\Keys\\db_crypt.txt', 'rb', password, operation='read')
    db_key = aesccm.decrypt(nonce, crypt, password)

    # If data exists in log file #
    if os.stat('cryptLog.log').st_size > 0:
        # Decrypt the cryptLog #
        crypt = file_handler('cryptLog.log', 'rb', password, operation='read')
        plain = Fernet(db_key).decrypt(crypt)
        file_handler('cryptLog.log', 'wb', password, operation='write', data=plain)

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
    # If reading the log #
    elif operation == 'read':
        # If no data to read .. exit function #        
        if os.stat('cryptLog.log').st_size == 0:
            return
        else:
            count = 0
            plain = file_handler('cryptLog.log', 'r', password, operation='read')

            # Print log page by page #
            for line in plain:
                if count == 60:
                    input('Hit enter to continue')
                    system_cmd(cmds[0], None, None, 2)
                    count = 0

                print(line)
                count += 1
    else:
        logging.error('No logging operation specified')

    # If no data in log .. exit function #
    if os.stat('cryptLog.log').st_size == 0:
        return

    # Encrypt the cryptLog #
    plain = file_handler('cryptLog.log', 'rb', password, operation='read')
    crypt = Fernet(db_key).encrypt(plain)
    file_handler('cryptLog.log', 'wb', password, operation='write', data=crypt)

# Make cryptographic key-set #
def make_keys(db, password):
    # ChaCha20 symmetric key (256 bit key, 128 bit nonce) #
    upload_key = b64encode(os.urandom(32)).decode('utf-8')
    cha_nonce = b64encode(os.urandom(16)).decode('utf-8')

    # Send ChaCha20 key to keys database #
    query = Globals.db_insert(db, 'upload_key', upload_key)
    query_handler(db, query, password)

    # Send ChaCha20 nonce to keys database # 
    query = Globals.db_insert(db, 'upload_nonce', cha_nonce)
    query_handler(db, query, password)

    # Fernet Symmetric HMAC key for dbs #
    db_key = Fernet.generate_key()

    # Encrypt the keys db #
    db_plain = file_handler('.\\Dbs\\keys.db', 'rb', password, operation='read')
    crypt = Fernet(db_key).encrypt(db_plain)
    file_handler('.\\Dbs\\keys.db', 'wb', password, operation='write', data=crypt)

    # Encrypt the storage db #
    db_plain = file_handler('.\\Dbs\\storage.db', 'rb', password, operation='read')
    crypt = Fernet(db_key).encrypt(db_plain)
    file_handler('.\\Dbs\\storage.db', 'wb', password, operation='write', data=crypt)

    # AESCCM password authenticated key #
    key = AESCCM.generate_key(bit_length=256)
    aesccm = AESCCM(key)
    nonce = os.urandom(13)

    # Encrypt the db fernet key with AESCCM password key & write to file #
    crypt = aesccm.encrypt(nonce, db_key, password)
    file_handler('.\\Keys\\db_crypt.txt', 'wb', password, operation='write', data=crypt)

    # Write AESCCM key and nonce to files # 
    file_handler('.\\Keys\\aesccm.txt', 'wb', password, operation='write', data=key)
    file_handler('.\\Keys\\nonce.txt', 'wb', password, operation='write', data=nonce)

# Format email message #
def msg_format(send_email, receiver, body, files):
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
def msg_send(send_email, receiver, password, msg):
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
        print_err('* [ERROR] Remote email server connection failed *\n', 2)
        logger(f'SMTP Error: {err}', password, \
                operation='write', handler='error')

# Timed error message #
def print_err(msg, seconds):
    print(msg, file=stderr)
    sleep(seconds)

# MySQL database query handler #
def query_handler(db, query, password, create=False, fetchone=False):
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
            print_err('* [ERROR] Database error occured *\n', 2)
            logger(f'SQL error: {err}\n', password, \
                    operation='write', handler='error')

        conn.close()
        os.chdir('.\\..')

# Run system command #
def system_cmd(cmd, stdout, stderr, exec_time):
    exe = shlex.quote(cmd)
    try:
        command = Popen(exe, stdout=stdout, stderr=stderr, shell=True)
        outs, errs = command.communicate(exec_time)
    except (SubprocessError, TimeoutExpired, CalledProcessError, OSError, ValueError):
        command.kill()
        outs, errs = command.communicate()