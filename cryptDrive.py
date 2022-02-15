# Built-in Modules #
from base64 import b64encode
from getpass import getpass
from time import sleep
import ctypes, logging, os, re, shutil

# Third-party Modules #
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from filelock import FileLock, Timeout
from pyfiglet import Figlet
import keyring, winshell

# Custom Modules #
import Modules.Globals as Globals
from Modules.MenuFunctions import *
from Modules.Utils import FileHandler, HdCrawl, KeyHandler, Logger, \
                          PrintErr, QueryHandler, SystemCmd

# # Function Index #
# -------------------
# - MainMenu:           displays command options, executes selected options
# - DbCheck:            function in StartCheck for checking upload components in keys db
# - StartCheck:         startup script to handle password hash & confirm program components exist
# - PasswordInput:      password hashing function to verify hash in keyring or create new password hash

# Main menu with command options #
def MainMenu(dbs, password, cmds, abs_path):
    # Compile regex patterns #
    re_path = re.compile(r'^C:(?:\\[a-zA-Z0-9\_\"\' \.\,\-]{1,60})+')
    re_email = re.compile(r'.+?@[a-zA-Z0-9\_\.]{4,20}\.[a-z]{2,4}$')
    re_user = re.compile(r'^[a-zA-Z0-9\_]{1,30}')
    re_pass = re.compile(r'^[a-zA-Z0-9\_!+$@&(]{10,30}')
    re_phone = re.compile(r'^[0-9]{10}')
    custom_fig = Figlet(font='roman', width=100)

    # Clears screen per loop for clean display #
    while True:
        SystemCmd(cmds[0], None, None, 2)
        print(custom_fig.renderText('Crypt Drive'))
        print('''
    @===============@
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
            while True:
                local_path = input('\nSpecify path to folder C:\\like\\this for upload, \"Storage\" for '
                                   'contents from storage database or enter for UploadDock:\n')
                if not re.search(re_path, local_path) and local_path != 'Storage' and  local_path != '':
                    PrintErr('\n* [ERROR] Improper format .. try again *\n', 2)
                    continue

                break

            # If user hit enter #
            if local_path == '':
                local_path = '.\\UploadDock'
            # If user entered Storage #
            elif local_path == 'Storage':
                local_path = None

            Upload(dbs, cmds[0], password, local_path, abs_path)

        # Store data in storage database #
        elif prompt == 'store':
            while True:
                local_path = input('\nSpecify path to folder C:\\like\\this for database storage or enter for Import:\n')
                if not re.search(re_path, local_path) and local_path != '':
                    PrintErr('\n* [ERROR] Improper format .. try again *\n', 2)
                    continue

                break

            if local_path == '':
                local_path = abs_path + '\\Import'

            DbStore(dbs, cmds[0], password, local_path)

        # Extract data from storage db #
        elif prompt == 'extract':
            while True:
                folder = input('Enter folder name to be recursively exported from the database: ')
                local_path = input('\nSpecify path to folder C:\\like\\this to export to or enter export in Documents\n')
                if not re.search(re_path, local_path) and local_path != '' or not re.search(r'^[a-zA-Z0-9\.\_]+', folder):
                    PrintErr('\n* [ERROR] Improper format .. try again *\n', 2)
                    continue

                break

            if local_path == '':
                local_path = None

            DbExtract(dbs, cmds[0], password, folder, local_path)

        # List cloud contents #
        elif prompt == 'ldrive':
            ListDrive()

        # List storage database contents #
        elif prompt == 'lstore':
            ListStorage(dbs, password)

        # Import public key #
        elif prompt == 'import':
            while True:
                username = input('Enter username for key to be imported: ')
                import_pass = input('Enter user decryption password in text message: ')
                if not re.search(re_user, username) or not re.search(re_pass, import_pass):
                    PrintErr('\n* [ERROR] Improper format .. try again *\n', 2)
                    continue
               
                break

            ImportKey(dbs[0], password, username, import_pass)

        # Decrypt data in DecryptDock
        elif prompt == 'decrypt':
            while True: 
                username = input('Enter username of data to decrypt or hit enter for your own data: ')
                local_path = input('\nSpecify path to folder C:\\like\\this to export to or enter export in Documents\n')
                if not re.search(re_user, username) and username != '' or \
                not re.search(re_path, local_path) and local_path != '':
                    PrintErr('\n* [ERROR] Improper format .. try again *\n', 2)
                    continue

                break

                if local_path == '':
                    local_path = '.\\DecryptDock'

            Decryption(dbs[0], cmds[0], username, password, local_path)

        # Share private key with user #
        elif prompt == 'share':
            while True:
                send_email = input('Enter your gmail email address: ')
                email_pass = getpass('Enter gmail account password: ')
                recv_email = input('Enter receivers email address for encrypted decryption key: ')
                recv_email2 = input('Enter receivers encrypted email address(Protonmail, Tutanota, Etc ..) for auth key: ')
                recv_phone = input('Enter receivers phone number (no hyphens): ')
                carrier = input('Select your phone provider (verison, sprint, at&t, t-mobile, virgin, boost, us-cellular): ')

                if not re.search(re_email, send_email) or not re.search(re_pass, email_pass) \
                or not re.search(re_email, recv_email) or not re.search(re_email, recv_email2) \
                or not re.search(re_phone, recv_phone):
                    PrintErr('\n* [ERROR] One of the inputs provided were improper .. try again *\n', 2)
                    continue

                if carrier not in ('verison', 'sprint', 'at&t', 't-mobile', 'virgin', 'boost', 'us-cellular'):
                    PrintErr('\n* [ERROR] improper provider selection made *\n', 2)
                    continue
                else:
                    if carrier == 'verison':
                        provider = 'vtext.com'
                    elif carrier == 'sprint':
                        provider = 'messaging.sprintpcs.com'
                    elif carrier == 'at&t':
                        provider = 'txt.att.net'
                    elif carrier == 't-mobile':
                        provider = 'tmomail.com'
                    elif carrier == 'virgin':
                        provider = 'vmobl.com'
                    elif carrier == 'boost':
                        provider = 'sms.myboostmobile.com'
                    elif carrier == 'us-cellular':
                        provider = 'email.uscc.net'

                break

            receivers = (recv_email, recv_email2, recv_phone + '@' + provider)                
            ShareKey(dbs[0], password, send_email, email_pass, receivers, re_pass)

        # Exit the program #
        elif prompt == 'exit':
            print('\nExiting Utility ..')
            sleep(2)
            exit(0)

        elif prompt == 'view':
            Logger(None, password, operation='read', handler=None)

        # Improper input handling #
        else:
            print('\n* [ERROR] Improper Input .. try again *')

        sleep(2.5)
 
# Called in StartCheck script for checking
# upload components from keys database #
def DbCheck(dbs, password):
    # Load AESCCM decrypt components #
    key = FileHandler('.\\Keys\\aesccm.txt', 'rb', password, operation='read')
    nonce = FileHandler('.\\Keys\\nonce.txt', 'rb', password, operation='read')
    crypt = FileHandler('.\\Keys\\db_crypt.txt', 'rb', password, operation='read')
    aesccm = AESCCM(key)

    # Unlock the local database key #
    try:
        db_key = aesccm.decrypt(nonce, crypt, password)
    except InvalidTag:
        PrintErr('\n* [ERROR] Incorrect unlock password entered *\n', 2)
        exit(2)

    # Retrieve upload key from database #
    query = Globals.DB_RETRIEVE(dbs[0], 'upload_key')
    upload_call = QueryHandler(dbs[0], query, password, fetchone=True)

    # Retrieve nonce from database #
    query = Globals.DB_RETRIEVE(dbs[0], 'upload_nonce')
    nonce_call = QueryHandler(dbs[0], query, password, fetchone=True)

    # If the upload key call fails #
    if not upload_call or not nonce_call:
        PrintErr('\n* [ERROR] Database missing upload component .. creating new key & upload to db *\n'
                  'Data will need to be re uploaded with new key otherwise decryption will fail\n', 2)
        Logger('Upload component missing .. new key created, data needs to be re-uploaded', password,
               operation='write', handler='exception')

        if not upload_call:
            # Create new upload key #
            upload_key = b64encode(os.urandom(32))

            # Encrypt upload key #
            crypt_key = Fernet(db_key).encrypt(upload_key)

            # Send upload key to keys database #
            query = Globals.DB_INSERT(dbs[0], 'upload_key', crypt_key.decode('utf-8'))
            QueryHandler(dbs[0], query, password)
        
        if not nonce_call:
            # Create new upload nonce #
            nonce = b64encode(os.urandom(16))    

            # Encrypt upload nonce #
            crypt_nonce = Fernet(db_key).encrypt(nonce)

            # Send nonce to keys database #
            query = Globals.DB_INSERT(dbs[0], 'upload_nonce', crypt_nonce.decode('utf-8'))
            QueryHandler(dbs[0], query, password)
    else:
        # Confirm upload key works with fernet #
        Fernet(db_key).decrypt(upload_call[1].encode())

        # Confirm upload key works with fernet #
        Fernet(db_key).decrypt(nonce_call[1].encode())

# Startup script checks if any directorys, keys, & files
# associated with program are missing; fixes detected issues #
def StartCheck(dbs, password, abs_path):
    global log

    failures = []
    components = ( '.\\Dbs', '.\\DecryptDock', '.\\Import', '.\\Keys', '.\\UploadDock', 
                   '.\\Keys\\aesccm.txt', '.\\Keys\\db_crypt.txt', '.\\Keys\\nonce.txt', 
                   '.\\Dbs\\keys.db', '.\\Dbs\\storage.db' )

    # Iterate each component through operations #
    for item in components:
        # If current item is a folder #
        if item in ('.\\Dbs', '.\\DecryptDock', '.\\Import', '.\\Keys', '.\\UploadDock'):
            # If folder exists #
            if Globals.DIR_CHECK(item):
                continue

        else:
            # If current item is a file #
            if Globals.FILE_CHECK(item):
                # If the file is not empty #
                if os.stat(item).st_size > 0:
                    # If the curent item is the keys db #
                    if item == '.\\Dbs\\keys.db':
                        # Check upload conents in keys db #
                        DbCheck(dbs, password)

                    continue

                # If file is empty #
                else:
                    # Delete empty file #
                    os.remove(item)
                    # Add item to failures list #
                    failures.append(item)
                    continue

        # If item is file #
        if item in ('.\\Keys\\aesccm.txt', '.\\Keys\\db_crypt.txt', '.\\Keys\\nonce.txt', \
        '.\\Dbs\\keys.db', '.\\Dbs\\storage.db'):
            re_item = re.search(r'(?<=\.)[a-zA-Z\_\\]+(?=\.)', item)
        # If item if folder #
        else:
            re_item = re.search(r'(?<=\.)[a-zA-Z\_\\]+(?=$)', item)

        # Append item path to program root dir #
        parse = abs_path + re_item.group(0)
        try:
            # Check recycling bin for item #
            winshell.undelete(parse)

            # If item is a text file #
            if item in ('.\\Keys\\aesccm.txt', '.\\Keys\\db_crypt.txt', '.\\Keys\\nonce.txt'):
                os.rename(parse, parse + '.txt')
            # If item is a database #
            elif item in ('.\\Dbs\\keys.db', '.\\Dbs\\storage.db'):
                os.rename(parse, parse + '.db')
            else:
                continue

            print(f'{item} was found in recycling bin')
        # If attempt to recover component from recycling bin fails #
        except:
            PrintErr(f'\n* {item} not found in recycling bin .. checking user storage *\n', 0.01)

            # If file is file #
            if item in ('.\\Keys\\aesccm.txt', '.\\Keys\\db_crypt.txt', '.\\Keys\\nonce.txt',
            '.\\Dbs\\keys.db', '.\\Dbs\\storage.db'):
                re_item = re.search(r'(?<=[a-zA-Z]\\)[a-zA-Z\_\\]+(?=\.)', item)
            # If file is folder #
            else:
                re_item = re.search(r'(?<=\.\\)[a-zA-Z\_\\]+(?=$)', item)

            # Attempt to recover missing item
            # from user storage in hard drive #
            recover = HdCrawl(re_item.group(0))

            # If all attempts fail, add item to failures list #
            if not recover:
                PrintErr(f'\n* {item} not found in hard drive either *\n', 2)
                failures.append(item)
            else:
                print(f'{item} was found in user storage on hard drive')

        sleep(2)

    # Enable logging to file #
    Globals.LOG = True

    # If a component could not be recovered #
    if failures:
        # For component in list of failures #
        for fail in failures:
            # If component is independent of key set #
            if fail in ('.\\DecryptDock', '.\\Import', \
            '.\\UploadDock', '.\\Dbs\\storage.db' ):
                # If fail item is folder #
                if Globals.DIR_CHECK(fail):
                    # Create folder #
                    os.mkdir(fail)
                # If fail item is file #
                else:
                    # # If fail item is stoage db #
                    if fail == '.\\Dbs\\storage.db':
                        # Create storage database #
                        query = Globals.DB_STORAGE(dbs[1])
                        QueryHandler(dbs[1], query, password, create=True)
                    else:
                        # Re-create entire key/db components #
                        KeyHandler(dbs, password)
            else:
                # Re-create entire key/db components #
                KeyHandler(dbs, password)

# Confirm pasword through hashing algorithm
# or create new hash for key set #
def PasswordInput(cmds, test):
    count = 0

    # Initialize password hashing algorithm #
    pass_algo = PasswordHasher()

    key_check, nonce_check = Globals.FILE_CHECK('.\\Keys\\aesccm.txt'), Globals.FILE_CHECK('.\\Keys\\nonce.txt')
    dbKey_check, DbCheck = Globals.FILE_CHECK('.\\Keys\\db_crypt.txt'), Globals.FILE_CHECK('.\\Dbs\\keys.db')
    storage_check = Globals.FILE_CHECK('.\\Dbs\\storage.db')

    # If all major components missing avoid StartCheck script #
    if not key_check and not nonce_check and not dbKey_check \
    and not DbCheck and not storage_check:
        test = False

    while True:
        # Clear display #
        SystemCmd(cmds[0], None, None, 2)
        
        # If user maxed attempts (3 sets of password fails) #
        if count == 12:
            # Code can be added to notify administrator or 
            # raise an alert to remote system # 

            # Lock the system #
            ctypes.wind11.user32.LockWorkStation()

        # After three password failures #
        elif count in (3, 6, 9):
            print('\n* [WARNING] Too many login attempts .. 60 second timeout *')
            for sec in range(1, 61):
                msg = '!' * sec + f' {sec}'
                print(msg, end='\r')
                sleep(1)

        # Prompt user for input #
        prompt = getpass('\n\nEnter your unlock password or password for creating keys: ')

        # Check input syntax & length #
        if not re.search(r'^[a-zA-Z0-9_!+$@&(]{12,30}', prompt):
            PrintErr('\n* [ERROR] Invalid password format .. numbers, letters, &'
                     ' _+$@&( special charaters allowed *', 2)
            count += 1
            continue

        # If files exist indicating password is set #
        if key_check and nonce_check and dbKey_check and DbCheck:
            # Attempt to retrieve password hash from key ring #
            try:
                keyring_hash = keyring.get_password('CryptDrive', 'CryptUser')
            # If credential manager is missing password hash #
            except keyring.errors.KeyringError:
                # Print error & return hashed input #
                PrintErr('\n* [ERROR] Attempted access to key that does not exist .. *', 2.5)
                return pass_algo.hash(prompt).encode(), test

            # Verify input by comparing keyring hash against algo #
            try:
                check = pass_algo.verify(keyring_hash, prompt)
            except VerifyMismatchError:
                PrintErr('\n* [ERROR] Input does not match password hash *', 2)
                count += 1
                continue

            else:
                # Return hash stored in keyring #
                return keyring_hash.encode(), test
        else:
            # Confirm users password before setting #
            prompt2 = getpass('Enter password again to confirm: ')

            if not re.search(r'^[a-zA-Z0-9_!+$@&(]{12,30}', prompt2):
                PrintErr('\n* [ERROR] Invalid password format .. numbers, letters, &'
                         ' _+$@&( special charaters allowed *', 2)
                count += 1
                continue                

            # Confirm the same password was entered twice #
            if prompt != prompt2:
                PrintErr('\n* [ERROR] Two different passwords were entered .. try again *', 2)
                count += 1
                continue

            # Return hashed input #
            return pass_algo.hash(prompt).encode(), test


if __name__ == '__main__':
    try:
        # Initalize global lambda variables #
        Globals.Initialize()
        # Commands tuple #
        cmds = ('cls',)

        # Boolean switch #
        test = True

        # Call password input function #
        password, test = PasswordInput(cmds, test)

        # Database & command tuples #
        dbs = ('keys', 'storage')

        # Initialize logging facilities #
        logging.basicConfig(level=logging.ERROR, stream=Globals.LOG_STREAM,
                            format='%(asctime)s %(levelname)s:%(message)s')

        # Get absolute path to file of execution thread #
        abs_path = os.path.dirname(os.path.abspath(__file__))

        if test:
            # Start up script for checking
            # critical operation components #
            StartCheck(dbs, password, abs_path)
        else:
            # Create folders #
            for folder in ('.\\Dbs' ,'.\\DecryptDock', '.\\Import', '.\\Keys', '.\\UploadDock'):
                if not Globals.DIR_CHECK(folder):
                    os.mkdir(folder)

            # Make new key/db setup #
            KeyHandler(dbs, password)
            # Enable logging to file #
            Globals.LOG = True

    except KeyboardInterrupt:
        PrintErr('\n* [EXIT] Ctrl + c detected .. exiting *', 2)
        exit(0)

    # Main menu exception handled loop #
    while True:
        try:
            MainMenu(dbs, password, cmds, abs_path)

        except Exception as err:
            PrintErr('\n* [EXCEPTION] Exception occured .. check log *\n', 2)
            Logger(f'Exception occured: {err}\n', password, operation='write', handler='exception')
            continue
        except KeyboardInterrupt:
            PrintErr('\n\n* [EXIT] Ctrl + c detected .. exiting *', 2)
            break