from Modules.Utils import bin_check, file_handler, key_handler, logger, \
                          make_keys, print_err, query_handler, system_cmd
from Modules.MenuFunctions import *
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidTag
from pyfiglet import Figlet
from time import sleep
import os, re, logging
import Modules.Globals as Globals

def main_menu(dbs, password):
    # Compile regex patterns #
    re_path = re.compile(r'^C:(?:\\[a-zA-Z0-9_\"\' \.,\-]{1,30})+')
    re_email = re.compile(r'.+?@[a-zA-Z0-9_]{4,20}\.[a-z]{2,4}$')
    re_user = re.compile(r'^[a-zA-Z0-9_]{1,30}')
    re_pass = re.compile(r'^[a-zA-Z0-9_!+$@&(]{10,30}')
    re_phone = re.compile(r'^[0-9]{10}')
    custom_fig = Figlet(font='roman', width=100)
    cmds = ('cls',)

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
                email_pass = input('Enter gmail account password: ')
                recv_email = input('Enter receivers email address for encrypted decryption key: ')
                recv_email2 = input('Enter receivers encrypted email address(Protonmail, Tutanota, Etc ..) for auth key: ')
                recv_phone = input('Enter receivers phone number (no hyphens): ')
                prompt = input('Select your phone provider (verison, sprint, at&t, t-mobile, virgin, boost, us-cellular): ')

                if re.search(re_email, send_email) == False or re.search(re_pass, email_pass) == False \
                or re.search(re_email, recv_email) == False or re.search(re_email, recv_email2) == False \
                or re.search(re_phone, recv_phone) == False:
                    print_err('\n* [ERROR] One of the inputs provided were improper .. try again *\n', 2)
                    continue

                if prompt not in ('verison', 'sprint', 'at&t', 't-mobile', 'virgin', 'boost', 'us-cellular'):
                    print_err('\n* [ERROR] improper provider selection made *', 2)
                    continue
                else:
                    if prompt == 'verison':
                        provider = 'vtext.com'
                    elif prompt == 'sprint':
                        provider = 'messaging.sprintpcs.com'
                    elif prompt == 'at&t':
                        provider = 'txt.att.net'
                    elif prompt == 't-mobile':
                        provider = 'tmomail.com'
                    elif prompt == 'virgin':
                        provider = 'vmobl.com'
                    elif prompt == 'boost':
                        provider = 'sms.myboostmobile.com'
                    elif prompt == 'us-cellular':
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

# Startup script checks if any directorys, keys, & files
# associated with program are missing; fixes detected issues #
def start_check(dbs, password):
    # Check if folders exist .. if not, create #
    for folder in ('.\\UploadDock', '.\\DecryptDock', '.\\Import'):
        if Globals.dir_check(folder) == False:
            os.mkdir(folder)

    # If the Dbs dir is missing .. create it #
    if Globals.dir_check('.\\Dbs') == False:
        os.mkdir('Dbs')

        # If the Keys dir exists, delete local user keys. Else create dir #
        if Globals.dir_check('.\\Keys') == True:
            for file in ('.\\Keys\\db_crypt.txt', '.\\Keys\\aesccm.txt', '.\\Keys\\nonce.txt'): 
                if Globals.file_check(file) == True:
                    os.remove(file)
        else:
            os.mkdir('Keys')

        # Create databases #
        for db in dbs:
            query = Globals.db_create(db)
            query_handler(db, query, password, create=True)

        # Create encryption keys #
        make_keys(dbs[0], password)
    else:
        # Check if needed db & files are present #
        if Globals.file_check('.\\Dbs\\keys.db') == True and Globals.file_check('.\\Keys\\aesccm.txt') == True \
        and Globals.file_check('.\\Keys\\nonce.txt') == True and Globals.file_check('.\\Keys\\db_crypt.txt') == True:
            # Load AESCCM decrypt components #            
            key = file_handler('.\\Keys\\aesccm.txt', 'rb', password, operation='read')
            nonce = file_handler('.\\Keys\\nonce.txt', 'rb', password, operation='read')

            # Unlock the local database key #
            aesccm = AESCCM(key)
            crypt = file_handler('.\\Keys\\db_crypt.txt', 'rb', password, operation='read')
            try:
                db_key = aesccm.decrypt(nonce, crypt, password)
            except InvalidTag:
                print_err('* [ERROR] Incorrect unlock password entered *', 2)
                exit(1)

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
                print_err('* [ERROR] Database missing upload key .. creating new key & upload to db *\n'
                          'Data will need to be re uploaded with new key otherwise decryption will fail\n', 2)

                # Create new upload key #
                upload_key = os.urandom(32)
                
                # Send upload key to keys database #
                query = Globals.db_insert(dbs[0], 'upload_key', upload_key)
                query_handler(dbs[0], query, password)

            # If the nonce key fails #
            if nonce_call == None:
                print_err('* [ERROR] Database missing nonce .. creating new nonce & upload to db *\n'
                          'Data will need to be re uploaded with new nonce otherwise decryption will fail\n', 2)

                # Create new nonce #
                nonce = os.urandom(16)
                
                # Send nonce to keys database #
                query = Globals.db_insert(dbs[0], 'upload_nonce', nonce)
                query_handler(dbs[0], query, password)

            # Re-encrypt the key database #
            plain = file_handler('.\\Dbs\\keys.db', 'rb', password, operation='read')
            db_crypt = Fernet(db_key).encrypt(plain)
            file_handler('.\\Dbs\\keys.db', 'wb', password, operation='write', data=db_crypt)
        else:
            print_err('* [ERROR] missing critical component .. making new db/key setup *\n', 2)
            key_handler(dbs, password)

    # If the Keys dir is missing .. create it #
    if Globals.dir_check('.\\Keys') == False:
        os.mkdir('Keys')
        print('* No Keys directory existed .. attempting to retrieve keys from recycling bin *\n')
        sleep(2)

        # Check recycling bin for missing keys #
        for key in ('db_crypt', 'aesccm', 'nonce'):
            key_check = bin_check(key)
            if key_check == False:
                print_err(f'* [ERROR] {key}.txt not found in recycling bin .. making new db/key setup *\n'
                          'Data will need to be re uploaded with new key set otherwise decryption will fail\n', 2)
                key_handler(dbs, password)


if __name__ == '__main__':
    # Prompt user for unlock password #
    while True:
        prompt = input('Enter your unlock password or password for creating keys: ')
        if re.search(r'^[a-zA-Z0-9_!+$@&(]{12,30}', prompt) == None:
            print_err('\n* [ERROR] Invalid password format .. numbers, letters & _+$@&( special charaters allowed *', 2)
            continue

        print('\n')
        password = prompt.encode()
        break

    # Initalize global lambda variables #
    Globals.initialize()

    # Database tuple #
    dbs = ('keys', 'storage')

    # Initialize logging facilities #
    logging.basicConfig(level=logging.ERROR, filename='cryptLog.log', format='%(asctime)s %(levelname)s:%(message)s')

    # Start up script for checking
    # critical operation components #
    start_check(dbs, password)

    # Main menu exception handled loop #
    while True:
        try:
            main_menu(dbs, password)

        except Exception as err:
            print_err('\n* [EXCEPTION] Exception occured .. check log *', 2)
            logger(f'Exception occured: {err}\n', password, \
                    operation='write', handler='exception')
            continue
        except KeyboardInterrupt:
            print_err('\n* [EXIT] Ctrl + C detected .. exiting *', 2)
            break