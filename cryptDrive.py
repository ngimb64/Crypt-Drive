from Modules.Utils import file_handler, hd_crawl, key_handler, logger, \
                          make_keys, print_err, query_handler, system_cmd
from Modules.MenuFunctions import *
from getpass import getpass
from argon2 import PasswordHasher
from base64 import b64encode
from filelock import FileLock, Timeout
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidTag
from pyfiglet import Figlet
from time import sleep
import os, re, logging, keyring, ctypes, shutil, winshell
import Modules.Globals as Globals

# # Function Index #
# -------------------
# - main_menu:          displays command options, executes selected options
# - db_check:           function in start_check for checking upload components in keys db
# - start_check:        startup script to handle password hash & confirm program components exist
# - password_input:     password hashing function to verify hash in keyring or create new password hash

test = True

# Main menu with command options #
def main_menu(dbs, password, cmds):
    # Compile regex patterns #
    re_path = re.compile(r'^C:(?:\\[a-zA-Z0-9_\"\' \.,\-]{1,30})+')
    re_email = re.compile(r'.+?@[a-zA-Z0-9_]{4,20}\.[a-z]{2,4}$')
    re_user = re.compile(r'^[a-zA-Z0-9_]{1,30}')
    re_pass = re.compile(r'^[a-zA-Z0-9_!+$@&(]{10,30}')
    re_phone = re.compile(r'^[0-9]{10}')
    custom_fig = Figlet(font='roman', width=100)


    # Clears screen per loop for clean display #
    while True:
        system_cmd(cmds[0], None, None, 2)
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
                    print_err('\n* [ERROR] Improper format .. try again *', 2)
                    continue

                break

            if local_path == '':
                local_path == '.\\UploadDock'

            upload(dbs[0], cmds[0], password, local_path)

        # List cloud contents #
        elif prompt == 'l':
            list_drive()

        # Import public key #
        elif prompt == 'i':
            while True:
                username = input('Enter username for key to be imported: ')
                import_pass = input('Enter user decryption password in text message: ')
                if re.search(re_user, username) == False or re.search(re_pass, import_pass) == False:
                    print_err('\n* [ERROR] Improper format .. try again *', 2)
                    continue
               
                break

            import_key(dbs[0], password, username, import_pass)

        # Decrypt data in DecryptDock
        elif prompt == 'd':
            while True: 
                username = input('Enter username of data to decrypt or hit enter for your own data: ')
                if re.search(re_user, username) == False and username != '':
                    print_err('\n* [ERROR] Improper format .. try again *', 2)
                    continue

                break

            decryption(dbs[0], cmds[0], username, password)

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
                    print_err('\n* [ERROR] One of the inputs provided were improper .. try again *\n', 2)
                    continue

                if carrier not in ('verison', 'sprint', 'at&t', 't-mobile', 'virgin', 'boost', 'us-cellular'):
                    print_err('\n* [ERROR] improper provider selection made *', 2)
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
            share_key(dbs[0], password, send_email, email_pass, receivers, re_pass)

        # Exit the program #
        elif prompt == 'e':
            print('\nExiting Utility ..')
            sleep(2)
            exit(0)

        elif prompt == 'v':
            logger(None, password, operation='read', handler=None)

        # Improper input handling #
        else:
            print('\n* [ERROR] Improper Input .. try again *')


        sleep(2.5)

# Called in start_check script for checking
# upload components from keys database #
def db_check(dbs, password):
    # Load AESCCM decrypt components #
    try:
        with FileLock('.\\Keys\\aesccm.txt.lock', timeout=3):
            with open('.\\Keys\\aesccm.txt', 'rb') as file:
                key = file.read()

        with FileLock('.\\Keys\\nonce.txt.lock', timeout=3):
            with open('.\\Keys\\nonce.txt', 'rb') as file:
                nonce = file.read()

        with FileLock('.\\Keys\\db_crypt.txt.lock', timeout=3):
            with open('.\\Keys\\db_crypt.txt', 'rb') as file:
                crypt = file.read()       

    # File error handling #
    except (Timeout, IOError, FileNotFoundError, Exception):
        print_err('\n* [ERROR] File Lock/IO error reading keys .. check contents of Keys folder *\n', 4)
        exit(1)

    aesccm = AESCCM(key)

    # Unlock the local database key #
    try:
        db_key = aesccm.decrypt(nonce, crypt, password)
    except InvalidTag:
        print_err('\n* [ERROR] Incorrect unlock password entered *\n', 2)
        exit(2)

    # Decrypt the key database #
    db_crypt = file_handler('.\\Dbs\\keys.db', 'rb', password, operation='read')
    plain = Fernet(db_key).decrypt(db_crypt)
    file_handler('.\\Dbs\\keys.db', 'wb', password, operation='write', data=plain)

    # Retrieve upload key from database #
    query = Globals.db_retrieve(dbs[0], 'upload_key')
    upload_call = query_handler(dbs[0], query, password, fetchone=True)

    # Retrieve nonce from database #
    query = Globals.db_retrieve(dbs[0], 'upload_nonce')
    nonce_call = query_handler(dbs[0], query, password, fetchone=True)

    # If the upload key call fails #
    if upload_call == None:
        print_err('\n* [ERROR] Database missing upload key .. creating new key & upload to db *\n'
                  'Data will need to be re uploaded with new key otherwise decryption will fail\n', 2)
        logger('Upload key missing .. new key created, data needs to be re-uploaded', password, \
               operation='write', handler='exception')

        # Create new upload key #
        upload_key = b64encode(os.urandom(32)).decode('utf-8')
        
        # Send upload key to keys database #
        query = Globals.db_insert(dbs[0], 'upload_key', upload_key)
        query_handler(dbs[0], query, password)

    # If the nonce key fails #
    if nonce_call == None:
        print_err('\n* [ERROR] Database missing nonce .. creating new nonce & upload to db *\n'
                  'Data will need to be re uploaded with new nonce otherwise decryption will fail\n', 2)
        logger('Upload nonce missing .. new nonce created, data needs to be re-uploaded', password, \
               operation='write', handler='exception')

        # Create new nonce #
        nonce = b64encode(os.urandom(16)).decode('utf-8')
        
        # Send nonce to keys database #
        query = Globals.db_insert(dbs[0], 'upload_nonce', nonce)
        query_handler(dbs[0], query, password)

    # Re-encrypt the key database #
    plain = file_handler('.\\Dbs\\keys.db', 'rb', password, operation='read')
    db_crypt = Fernet(db_key).encrypt(plain)
    file_handler('.\\Dbs\\keys.db', 'wb', password, operation='write', data=db_crypt)

# Startup script checks if any directorys, keys, & files
# associated with program are missing; fixes detected issues #
def start_check(dbs, password):
    failures = []
    components = [ '.\\Dbs', '.\\DecryptDock', '.\\Import', '.\\Keys', '.\\UploadDock', 
                   '.\\Keys\\aesccm.txt', '.\\Keys\\db_crypt.txt', '.\\Keys\\nonce.txt', 
                   '.\\Dbs\\keys.db', '.\\Dbs\\storage.db' ]

    # Iterate each component through operations #
    for item in components:
        # If current item is a folder #
        if item in ('.\\Dbs', '.\\DecryptDock', '.\\Import', '.\\Keys', '.\\UploadDock'):
            # If folder exists #
            if Globals.dir_check(item) == True:
                continue

        else:
            # If current item is a file #
            if Globals.file_check(item):
                # If the file is not empty #
                if os.stat(item).st_size > 0:
                    # If the curent item is the keys db #
                    if item == '.\\Dbs\\keys.db':
                        # Check upload conents in keys db #
                        db_check(dbs, password)

                    continue

                # Delete empty file #
                os.remove(item)
                # Add item to failures list #
                failures.append(item)
                continue

        if item in ('.\\Keys\\aesccm.txt', '.\\Keys\\db_crypt.txt', '.\\Keys\\nonce.txt', \
        '.\\Dbs\\keys.db', '.\\Dbs\\storage.db'):
            re_item = re.search(r'(?<=\.)[a-zA-Z\_\\]+(?=\.)', item)
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
            print_err(f'\n* {item} not found in recycling bin .. checking user storage *\n', 0.01)

            if item in ('.\\Keys\\aesccm.txt', '.\\Keys\\db_crypt.txt', '.\\Keys\\nonce.txt', \
            '.\\Dbs\\keys.db', '.\\Dbs\\storage.db'):
                re_item = re.search(r'(?<=[a-zA-Z]\\)[a-zA-Z\_\\]+(?=\.)', item)
            else:
                re_item = re.search(r'(?<=\.\\)[a-zA-Z\_\\]+(?=$)', item)

            # Attempt to recover missing item
            # from user storage in hard drive #
            recover = hd_crawl(re_item.group(0))
            # If all attempts fail, add item to failures list #
            if recover == False:
                print_err(f'\n* {item} not found in hard drive either *\n', 2)
                failures.append(item)
            else:
                print(f'{item} was found in user storage on hard drive')

        sleep(2)

    if failures:
        for fail in failures:
            if fail in ('.\\DecryptDock', '.\\Import', \
            '.\\UploadDock', '.\\Dbs\\storage.db' ):
                # If fail item is folder #
                if Globals.dir_check(fail) == True:
                    # Create folder #
                    os.mkdir(fail)
                # If fail item is file #
                else:
                    # # If fail item is stoage db #
                    if fail == '.\\Dbs\\storage.db':
                        # Create storage database #
                        query = Globals.db_create(dbs[1])
                        query_handler(dbs[1], query, password, create=True)

                        # Load the AESCCM components #
                        key = file_handler('.\\Keys\\aesccm.txt', 'rb', password, operation='read')
                        nonce = file_handler('.\\Keys\\nonce.txt', 'rb', password, operation='read')
                        crypt = file_handler('.\\Keys\\db_crypt.txt', 'rb', password, operation='read')
                        aesccm = AESCCM(key)

                        # Unlock the database key #
                        db_key = aesccm.decrypt(nonce, crypt, password)

                        # Encrypt the storage db #
                        db_plain = file_handler('.\\Dbs\\storage.db', 'rb', password, operation='read')
                        crypt = Fernet(db_key).encrypt(db_plain)
                        file_handler('.\\Dbs\\storage.db', 'wb', password, operation='write', data=crypt)
                    else:
                        # Re-create entire key/db components #
                        key_handler(dbs, password)
            else:
                # Re-create entire key/db components #
                key_handler(dbs, password)

# Confirm pasword through hashing algorithm
# or create new hash for key set #
def password_input(cmds):
    global test

    count = 0

    # Initialize password hashing algorithm #
    pass_algo = PasswordHasher()

    key_check, nonce_check = Globals.file_check('.\\Keys\\aesccm.txt'), Globals.file_check('.\\Keys\\nonce.txt')
    dbKey_check, db_check = Globals.file_check('.\\Keys\\db_crypt.txt'), Globals.file_check('.\\Dbs\\keys.db')
    storage_check = Globals.file_check('.\\Dbs\\storage.db')

    # If all major components missing avoid start_check script #
    if not key_check and not nonce_check and not dbKey_check \
    and not db_check and not storage_check:
        test = False

    while True:
        # If user maxed attempts #
        if count == 12:
            # Lock the system #
            ctypes.wind11.user32.LockWorkStation()

        # After three password failures #
        elif count in (3, 6, 9):
            print('\n* [WARNING] Too many login attempts .. 60 second timeout *')
            for sec in range(1, 61):
                msg = '!' * sec + f' {sec}'
                print(msg, end='\r')
                sleep(1)

        # Clear display #
        system_cmd(cmds[0], None, None, 2)

        # Prompt user for input #
        prompt = getpass('\nEnter your unlock password or password for creating keys: ')
        if re.search(r'^[a-zA-Z0-9_!+$@&(]{12,30}', prompt) == None:
            print_err('\n* [ERROR] Invalid password format .. numbers, letters & _+$@&( special charaters allowed *', 2)
            count += 1
            continue

        # If files exist indicating password is set #
        if key_check and nonce_check and dbKey_check and db_check:
            # Attempt to retrieve password hash from key ring #
            try:
                keyring_hash = keyring.get_password('CryptDrive', 'CryptUser')
            except keyring.errors.KeyringError:
                print_err('\n* [ERROR] Attempted access to key that does not exist .. *', 2.5)
                return

            # Verify input by comparing keyring hash against algo #
            check = pass_algo.verify(keyring_hash, prompt)
            if check == False:
                print_err('\n* [ERROR] Improper input provided *', 2)
                count += 1
                continue

            else:
                # Return hash stored in keyring #
                return keyring_hash
        else:
            # Return hashed input #
            return pass_algo.hash(prompt)


if __name__ == '__main__':
    try:
        # Initalize global lambda variables #
        Globals.initialize()
        # Commands tuple #
        cmds = ('cls',)

        # Call password input function #
        password = password_input(cmds).encode()

        # Database & command tuples #
        dbs = ('keys', 'storage')

        # Initialize logging facilities #
        logging.basicConfig(level=logging.ERROR, filename='cryptLog.log', format='%(asctime)s %(levelname)s:%(message)s')

        if test:
            # Start up script for checking
            # critical operation components #
            start_check(dbs, password)
        else:
            # Create folders #
            [ os.mkdir(folder) for folder in ('.\\Dbs' ,'.\\DecryptDock', '.\\Import', '.\\Keys', '.\\UploadDock') ]
            # Make new key/db setup #
            key_handler(dbs, password)

    except KeyboardInterrupt:
        print_err('\n* [EXIT] Ctrl + c detected .. exiting *', 2)
        exit(0)

    # Main menu exception handled loop #
    while True:
        try:
            main_menu(dbs, password, cmds)

        except Exception as err:
            print_err('\n* [EXCEPTION] Exception occured .. check log *', 2)
            logger(f'Exception occured: {err}\n', password, \
                    operation='write', handler='exception')
            continue
        except KeyboardInterrupt:
            print_err('\n* [EXIT] Ctrl + c detected .. exiting *', 2)
            break