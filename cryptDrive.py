# Built-in modules #
from base64 import b64encode
from getpass import getpass
from time import sleep
import ctypes, logging, os, re, shutil

# Third-party modules #
from argon2 import PasswordHasher
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from filelock import FileLock, Timeout
from pyfiglet import Figlet
import keyring, winshell

# Custom modules #
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
def MainMenu(dbs, password, cmds):
    # Compile regex patterns #
    re_path = re.compile(r'^C:(?:\\[a-zA-Z0-9\_\"\' \.\,\-]{1,30})+')
    re_email = re.compile(r'.+?@[a-zA-Z0-9\_]{4,20}\.[a-z]{2,4}$')
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
    #=======================#-------\\
    |   u  =>  upload to drive       \\
    |   l  =>  list drive contents   |
    |   i  =>  import key            |
    |   d  =>  decrypt data          |
    |   s  =>  share decrypt keys    |
    |   e  =>  exit utility          |
    |   v  ->  view error log        |
    @================================@
    \n''')
        prompt = input('$#==+> ')

        # Upload encrypted data #
        if prompt == 'u':
            while True:
                local_path = input('\nSpecify path to folder C:\\like\\this or enter for UploadDock:\n')
                if re.search(re_path, local_path) == False:
                    PrintErr('\n* [ERROR] Improper format .. try again *', 2)
                    continue

                break

            if local_path == '':
                local_path == '.\\UploadDock'

            Upload(dbs[0], cmds[0], password, local_path)

        # List cloud contents #
        elif prompt == 'l':
            ListDrive()

        # Import public key #
        elif prompt == 'i':
            while True:
                username = input('Enter username for key to be imported: ')
                import_pass = input('Enter user decryption password in text message: ')
                if re.search(re_user, username) == False or re.search(re_pass, import_pass) == False:
                    PrintErr('\n* [ERROR] Improper format .. try again *', 2)
                    continue
               
                break

            ImportKey(dbs[0], password, username, import_pass)

        # Decrypt data in DecryptDock
        elif prompt == 'd':
            while True: 
                username = input('Enter username of data to decrypt or hit enter for your own data: ')
                if re.search(re_user, username) == False and username != '':
                    PrintErr('\n* [ERROR] Improper format .. try again *', 2)
                    continue

                break

            Decryption(dbs[0], cmds[0], username, password)

        # Share private key with user #
        elif prompt == 's':
            while True:
                send_email = input('Enter your gmail email address: ')
                email_pass = getpass('Enter gmail account password: ')
                recv_email = input('Enter receivers email address for encrypted decryption key: ')
                recv_email2 = input('Enter receivers encrypted email address(Protonmail, Tutanota, Etc ..) for auth key: ')
                recv_phone = input('Enter receivers phone number (no hyphens): ')
                carrier = input('Select your phone provider (verison, sprint, at&t, t-mobile, virgin, boost, us-cellular): ')

                if re.search(re_email, send_email) == False or re.search(re_pass, email_pass) == False \
                or re.search(re_email, recv_email) == False or re.search(re_email, recv_email2) == False \
                or re.search(re_phone, recv_phone) == False:
                    PrintErr('\n* [ERROR] One of the inputs provided were improper .. try again *\n', 2)
                    continue

                if carrier not in ('verison', 'sprint', 'at&t', 't-mobile', 'virgin', 'boost', 'us-cellular'):
                    PrintErr('\n* [ERROR] improper provider selection made *', 2)
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
        elif prompt == 'e':
            print('\nExiting Utility ..')
            sleep(2)
            exit(0)

        elif prompt == 'v':
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
    query = Globals.db_retrieve(dbs[0], 'upload_key')
    upload_call = QueryHandler(dbs[0], query, password, fetchone=True)

    # Retrieve nonce from database #
    query = Globals.db_retrieve(dbs[0], 'upload_nonce')
    nonce_call = QueryHandler(dbs[0], query, password, fetchone=True)

    # If the upload key call fails #
    if not upload_call or not nonce_call:
        PrintErr('\n* [ERROR] Database missing upload component .. creating new key & upload to db *\n'
                  'Data will need to be re uploaded with new key otherwise decryption will fail\n', 2)
        Logger('Upload component missing .. new key created, data needs to be re-uploaded', password, \
               operation='write', handler='exception')

        if upload_call == None:
            # Create new upload key #
            upload_key = b64encode(os.urandom(32))

            # Encrypt upload key #
            crypt_key = Fernet(db_key).encrypt(upload_key)

            # Send upload key to keys database #
            query = Globals.db_insert(dbs[0], 'upload_key', crypt_key.decode('utf-8'))
            QueryHandler(dbs[0], query, password)
        
        if nonce_call == None:
            # Create new upload nonce #
            nonce = b64encode(os.urandom(16))    

            # Encrypt upload nonce #
            crypt_nonce = Fernet(db_key).encrypt(nonce)

            # Send nonce to keys database #
            query = Globals.db_insert(dbs[0], 'upload_nonce', crypt_nonce.decode('utf-8'))
            QueryHandler(dbs[0], query, password)
    else:
        # Confirm upload key works with fernet #
        Fernet(db_key).decrypt(upload_call[1].encode())

        # Confirm upload key works with fernet #
        Fernet(db_key).decrypt(nonce_call[1].encode())

# Startup script checks if any directorys, keys, & files
# associated with program are missing; fixes detected issues #
def StartCheck(dbs, password):
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
            if Globals.dir_check(item):
                continue

        else:
            # If current item is a file #
            if Globals.file_check(item):
                # If the file is not empty #
                if os.stat(item).st_size > 0:
                    # If the curent item is the keys db #
                    if item == '.\\Dbs\\keys.db':
                        # Check upload conents in keys db #
                        DbCheck(dbs, password)

                    continue

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

        # Get absolute path to file of execution thread #
        item_path = os.path.dirname(os.path.abspath(__file__))
        # Append item path to program root dir #
        parse = item_path + re_item.group(0)
        try:
            # Check recycling bin for item #
            winshell.undelete(parse)

            # If item is a text file #
            if item in ('.\\Keys\\aesccm.txt', '.\\Keys\\db_crypt.txt', '.\\Keys\\nonce.txt'):
                os.rename(parse, parse + '.txt')
            # If item is a database #
            elif item in ('.\\Dbs\\keys.db', '.\\Dbs\\storage.db'):
                os.rename(parse, parse + '.db')

            print(f'{item} was found in recycling bin')
        except:
            PrintErr(f'\n* {item} not found in recycling bin .. checking user storage *\n', 0.01)

            # If file is file #
            if item in ('.\\Keys\\aesccm.txt', '.\\Keys\\db_crypt.txt', '.\\Keys\\nonce.txt', \
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
    Globals.log = True

    # If a component could not be recovered #
    if failures:
        # For component in list of failures #
        for fail in failures:
            # If component is independent of key set #
            if fail in ('.\\DecryptDock', '.\\Import', \
            '.\\UploadDock', '.\\Dbs\\storage.db' ):
                # If fail item is folder #
                if Globals.dir_check(fail):
                    # Create folder #
                    os.mkdir(fail)
                # If fail item is file #
                else:
                    # # If fail item is stoage db #
                    if fail == '.\\Dbs\\storage.db':
                        # Create storage database #
                        query = Globals.db_create(dbs[1])
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

    key_check, nonce_check = Globals.file_check('.\\Keys\\aesccm.txt'), Globals.file_check('.\\Keys\\nonce.txt')
    dbKey_check, DbCheck = Globals.file_check('.\\Keys\\db_crypt.txt'), Globals.file_check('.\\Dbs\\keys.db')
    storage_check = Globals.file_check('.\\Dbs\\storage.db')

    # If all major components missing avoid StartCheck script #
    if not key_check and not nonce_check and not dbKey_check \
    and not DbCheck and not storage_check:
        test = False

    while True:
        # Clear display #
        SystemCmd(cmds[0], None, None, 2)
        
        # If user maxed attempts #
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
        prompt = getpass('\nEnter your unlock password or password for creating keys: ')
        if re.search(r'^[a-zA-Z0-9_!+$@&(]{12,30}', prompt) == None:
            PrintErr('\n* [ERROR] Invalid password format .. numbers, letters & _+$@&( special charaters allowed *', 2)
            count += 1
            continue

        # If files exist indicating password is set #
        if key_check and nonce_check and dbKey_check and DbCheck:
            # Attempt to retrieve password hash from key ring #
            try:
                keyring_hash = keyring.get_password('CryptDrive', 'CryptUser')
            except keyring.errors.KeyringError:
                PrintErr('\n* [ERROR] Attempted access to key that does not exist .. *', 2.5)
                return

            # Verify input by comparing keyring hash against algo #
            check = pass_algo.verify(keyring_hash, prompt)
            if check == False:
                PrintErr('\n* [ERROR] Improper input provided *', 2)
                count += 1
                continue

            else:
                # Return hash stored in keyring #
                return keyring_hash.encode(), test
        else:
            # Return hashed input #
            return pass_algo.hash(prompt).encode(), test


if __name__ == '__main__':
    try:
        # Initalize global lambda variables #
        Globals.initialize()
        # Commands tuple #
        cmds = ('cls',)

        # Boolean switch #
        test = True

        # Call password input function #
        password, test = PasswordInput(cmds, test)

        # Database & command tuples #
        dbs = ('keys', 'storage')

        # Initialize logging facilities #
        logging.basicConfig(level=logging.ERROR, filename='cryptLog.log', format='%(asctime)s %(levelname)s:%(message)s')

        if test:
            # Start up script for checking
            # critical operation components #
            StartCheck(dbs, password)
        else:
            # Create folders #
                try:
                    [ os.mkdir(folder) for folder in ('.\\Dbs' ,'.\\DecryptDock', '.\\Import', '.\\Keys', '.\\UploadDock') ]
                except FileExistsError:
                    pass

            # Make new key/db setup #
            KeyHandler(dbs, password)
            # Enable logging to file #
            Globals.log = True

    except KeyboardInterrupt:
        PrintErr('\n* [EXIT] Ctrl + c detected .. exiting *', 2)
        exit(0)

    # Main menu exception handled loop #
    while True:
        try:
            MainMenu(dbs, password, cmds)

        except Exception as err:
            PrintErr('\n* [EXCEPTION] Exception occured .. check log *\n', 2)
            Logger(f'Exception occured: {err}\n', password, \
                    operation='write', handler='exception')
            continue
        except KeyboardInterrupt:
            PrintErr('\n* [EXIT] Ctrl + c detected .. exiting *', 2)
            break