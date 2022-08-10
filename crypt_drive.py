""" Built-in modules """
import ctypes
import logging
import os
import re
import sys
import time
from binascii import Error
from getpass import getpass
# External Modules #
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken
from keyring import get_password
from keyring.errors import KeyringError
from pyfiglet import Figlet
from winshell import undelete, x_not_found_in_recycle_bin
# Custom Modules #
from Modules.auth_crypt import AuthCrypt
import Modules.globals as global_vars
from Modules.menu_functions import *
from Modules.utils import component_handler, db_check, hd_crawl, logger, print_err, query_handler, \
                          secure_delete, system_cmd


# Global variables #
global log


def main_menu(db_tuple: tuple, auth_obj, syntax_tuple: tuple):
    """
    Display command options and receives input on what command to execute.

    :param db_tuple:  The database name tuple.
    :param auth_obj:  The authentication instance.
    :param syntax_tuple:  The clear display command tuple.
    :return:  Nothing
    """
    # If OS is Windows #
    if os.name == 'nt':
        re_path = re.compile(r'^[A-Z]:(?:\\[a-zA-Z\d_\"\' .,\-]{1,260})+')
        cmd = syntax_tuple[0]
    # If OS is Linux #
    else:
        re_path = re.compile(r'^(?:\\[a-zA-Z\d_\"\' .,\-]{1,260})+')
        cmd = syntax_tuple[1]

    re_email = re.compile(r'[a-zA-Z\d._]{2,30}@[a-zA-Z\d_.]{2,15}\.[a-z]{2,4}$')
    re_user = re.compile(r'^[a-zA-Z\d._]{1,30}')
    re_pass = re.compile(r'^[a-zA-Z\d_!+$@&(]{12,30}')
    re_phone = re.compile(r'^\d{10}')
    re_dir = re.compile(r'^[a-zA-Z\d._]{1,30}')
    custom_fig = Figlet(font='roman', width=100)

    # Clears screen per loop for clean display #
    while True:
        system_cmd(cmd, None, None, 2)
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
                local_path = input('\nEnter [A-Z]:\\Windows\\path or \\Linux\\path for upload,'
                                   ' \"Storage\" for contents from storage database or enter for '
                                   'UploadDock:\n')
                # If regex fails and Storage and enter was not input #
                if not re.search(re_path, local_path) and local_path != 'Storage' \
                and local_path != '':
                    print_err('Improper format .. try again', 2)
                    continue

                break

            # If user hit enter #
            if local_path == '':
                local_path = global_vars.DIRS[4]
            # If user entered Storage #
            elif local_path == 'Storage':
                local_path = None

            upload(db_tuple, auth_obj, local_path)
            time.sleep(2)

        # Store data in storage database #
        elif prompt == 'store':
            while True:
                local_path = input('\nEnter [A-Z]:\\Windows\\path or \\Linux\\path'
                                   ' for database storage or enter for Import:\n')
                # If regex fails and enter was not input #
                if not re.search(re_path, local_path) and local_path != '':
                    print_err('Improper format .. try again', 2)
                    continue

                break

            if local_path == '':
                local_path = global_vars.DIRS[3]

            db_store(db_tuple, auth_obj, local_path)

        # Extract data from storage db #
        elif prompt == 'extract':
            while True:
                directory = input('Enter folder name to be recursively exported from the '
                                  'database: ')
                local_path = input('\nEnter [A-Z]:\\Windows\\path or \\Linux\\path to export to or'
                                   ' hit enter export in Documents:\n')
                # If path regex fails and enter was not input or folder regex fails #
                if not re.search(re_path, local_path) and local_path != '' or \
                not re.search(re_dir, directory):
                    print_err('Improper format .. try again', 2)
                    continue

                break

            if local_path == '':
                local_path = None

            db_extract(db_tuple, auth_obj, directory, local_path)

        # List cloud contents #
        elif prompt == 'ldrive':
            list_drive()

        # List storage database contents #
        elif prompt == 'lstore':
            list_storage(db_tuple[1], auth_obj)

        # Import public key #
        elif prompt == 'import':
            while True:
                username = input('Enter username for key to be imported: ')
                import_pass = input('Enter user decryption password in text message: ')
                # If username or password regex fail #
                if not re.search(re_user, username) or not re.search(re_pass, import_pass):
                    print_err('Improper format .. try again', 2)
                    continue
               
                break

            import_key(db_tuple[0], auth_obj, username, import_pass)

        # Decrypt data in DecryptDock
        elif prompt == 'decrypt':
            while True: 
                username = input('Enter username of data to decrypt or hit enter for your own '
                                 'data: ')
                local_path = input('\nEnter [A-Z]:\\Windows\\path or \\Linux\\path to export to or'
                                   ' enter for DecryptDock\n')
                # If username regex fails and enter was not entered
                # or path regex fails and enter was not entered #
                if not re.search(re_user, username) and username != '' or \
                not re.search(re_path, local_path) and local_path != '':
                    print_err('Improper format .. try again', 2)
                    continue

                break

            if local_path == '':
                local_path = global_vars.DIRS[1]

            decryption(db_tuple[0], username, auth_obj, local_path)

        # Share private key with user #
        elif prompt == 'share':
            provider = None

            app_secret = f'{global_vars.CWD}\\AppSecret.txt'

            # If AppSecret for Gmail login is missing #
            if not global_vars.file_check(app_secret):
                return print_err('Missing application password (AppSecret.txt) to login Gmail API, '
                                'generate password on Google account and save in AppSecret.txt in'
                                ' main dir', 2)

            email_pass = file_handler(app_secret, 'r', auth_obj, 'read')

            while True:
                send_email = input('Enter your gmail email address: ')
                recv_email = input('Enter receivers email address for encrypted decryption key: ')
                recv_email2 = input('Enter receivers encrypted email address(Protonmail, Tutanota,'
                                    ' Etc ..) for auth key: ')
                recv_phone = input('Enter receivers phone number (no hyphens): ')
                carrier = input('Select your phone provider (verizon, sprint, at&t, t-mobile, '
                                'virgin, boost, us-cellular): ')

                # If any of the input regex validations fail #
                if not re.search(re_email, send_email) or not re.search(re_email, recv_email) \
                or not re.search(re_email, recv_email2) or not re.search(re_phone, recv_phone):
                    print_err('One of the inputs provided were improper .. try again', 2)
                    continue

                # If improper carrier was selected #
                if carrier not in ('verizon', 'sprint', 'at&t', 't-mobile', 'virgin', 'boost',
                                   'us-cellular'):
                    print_err('Improper provider selection made', 2)
                    continue
                else:
                    if carrier == 'verizon':
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
                    else:
                        print_err('Unknown exception occurred selecting phone provider', 2)
                        continue

                break

            receivers = (recv_email, recv_email2, f'{recv_phone}@{provider}')
            key_share(db_tuple[0], auth_obj, send_email, email_pass, receivers, re_pass)

        # Exit the program #
        elif prompt == 'exit':
            print('\nExiting Utility ..')
            sys.exit(0)

        # View the encrypted error log #
        elif prompt == 'view':
            logger(None, auth_obj, operation='read', handler=None)

        # Improper input handling #
        else:
            print('\nImproper Input .. try again')

        time.sleep(2.5)


def start_check(db: str) -> bool:
    """
    Confirms program components are preset. If missing, component recovery is attempted. If that \
    fails results in the creation of a fresh set of components.

    :param db:  The storage database query syntax.
    :return:  True/False boolean toggle on success/failure.
    """
    global log
    misses = []

    # Compile parsing regex's #
    re_no_ext = re.compile(r'(?=[a-zA-Z\d])[^\\]{1,30}(?=\.)')
    re_dir = re.compile(r'(?=[a-zA-Z\d])[^\\]{1,30}(?=$)')

    # If OS is Windows where recycling bin exists #
    if os.name == 'nt':
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
                misses.append(item)

        # If all items were recovered #
        if not misses:
            return True

    # If OS is Linux #
    else:
        misses = global_vars.MISSING

    # Attempt to recover list of missing items from hard drive #
    failures = hd_crawl(misses)

    # If hard drive recovery was not successful #
    if failures:
        # For component in list of failures #
        for fail in failures:
            # If component is in independent of key-set #
            if fail in (global_vars.DIRS[1], global_vars.DIRS[2],
                        global_vars.DIRS[4], global_vars.DBS[1]):
                # If fail item is folder #
                if fail in global_vars.DIRS:
                    # Create folder #
                    os.mkdir(fail)
                # If fail item is storage db #
                else:
                    # Create storage database #
                    query = global_vars.db_storage(db)
                    query_handler(db, query, None, create=True)
            # If component is in the essential key-set #
            else:
                # Delete component files #
                for item in global_vars.FILES + global_vars.DBS:
                    if global_vars.file_check(item):
                        secure_delete(item)

                return False

    return True


def password_input(syntax_tuple: tuple, auth_obj) -> object:
    """
    Receive password input from user, verify with Argon2 hashing algorithm or create new password \
    in none exist.

    :param syntax_tuple:  Command syntax tuple to clear display.
    :param auth_obj:  The authentication instance.
    :return:  Populated authentication instance.
    """
    count = 0
    # Compile path regex #
    re_pass = re.compile(r'^[a-zA-Z\d_!+$@&(]{12,40}')

    # Initialize password hashing algorithm #
    pass_algo = PasswordHasher()

    # If OS is Windows #
    if os.name == 'nt':
        cmd = syntax_tuple[0]
    # If OS is Linux #
    else:
        cmd = syntax_tuple[1]

    while True:
        # Clear display #
        system_cmd(cmd, None, None, 2)
        
        # If user maxed attempts (3 sets of 3 failed password attempts) #
        if count == 12:
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
                # If fails exit the system #
                sys.exit(2)

        # After three password failures #
        elif count in (3, 6, 9):
            print('\n* [WARNING] Too many login attempts .. 60 second timeout *')
            for sec in range(1, 61):
                msg = f'{"!" * sec} sec'
                print(msg, end='\r')
                time.sleep(1)

        # Prompt user for input #
        prompt = getpass('\n\nEnter your unlock password or password for creating keys: ')

        # Check input syntax & length #
        if not re.search(re_pass, prompt):
            print_err('Invalid password format .. minimum of 12 numbers,'
                     ' letters, _!+$@&( special characters needed', 2)
            count += 1
            continue

        # Attempt to retrieve password hash from key ring #
        try:
            keyring_hash = get_password('CryptDrive', 'CryptUser')

        # If encrypted password hash is not set in credential manager #
        except KeyringError:
            # Confirm users password before setting #
            prompt2 = getpass('Enter password again to confirm: ')

            # If input fails regex validation #
            if not re.search(re_pass, prompt2):
                print_err('Invalid password format .. numbers, letters,'
                         ' _!+$@&( special characters allowed', 2)
                count += 1
                continue

            # If the 2nd confirmation input does not match original #
            if prompt != prompt2:
                print_err('Two different passwords were entered .. try again', 2)
                count += 1
                continue

            # Create dirs, dbs, and keys #
            auth_obj = component_handler(dbs, prompt, auth_obj)

            return auth_obj

        # If password keyring exists, but component files are missing #
        if not global_vars.HAS_KEYS:
            print('\nCryptographic key-set seems to exist but is missing in '
                  'program directory .. attempting to recover components\n'
                  f'{"*" * 109}\n')

            # Attempt to recover missing components #
            ret = start_check(dbs[1])
            # If unable to recover components essential to the key-set #
            if not ret:
                print_err('Unable to recover all missing components .. recreating key-set', 2.5)

                # Create dirs, dbs, and keys #
                auth_obj = component_handler(dbs, prompt, auth_obj)

                return auth_obj
            else:
                global_vars.HAS_KEYS = True

        # Check for database contents and set auth object #
        auth_obj = db_check(dbs[0], prompt.encode(), auth_obj)
        # Decrypt the password #
        check_pass = auth_obj.get_plain_secret()

        # Decrypt the keyring hash #
        try:
            plain_keyring = Fernet(auth_obj.secret_key).decrypt(keyring_hash.encode())

        # If error occurs during decryption #
        except (InvalidToken, TypeError, Error) as fern_err:
            print_err(f'Error occurred during fernet secret decryption: {fern_err}', 2)
            sys.exit(3)

        # Verify input by comparing keyring hash against algo #
        try:
            pass_algo.verify(plain_keyring, check_pass)

        # If users input does not match hashed keyring password #
        except (VerifyMismatchError, InvalidHash):
            print_err('Input does not match password hash', 2)
            count += 1
            continue

        return auth_obj


if __name__ == '__main__':
    # Commands tuple #
    cmds = ('cls', 'clear')
    # Database & command tuples #
    dbs = ('crypt_keys', 'crypt_storage')

    try:
        # Current working directory #
        cwd = os.getcwd()

        # Initialize AuthCrypt class #
        auth = AuthCrypt()

        # Initialize global variables and
        # check if components exist #
        global_vars.initialize(cwd)

        # User password authentication login #
        auth = password_input(cmds, auth)

        # Initialize logging facilities #
        logging.basicConfig(level=logging.ERROR, stream=global_vars.LOG_STREAM,
                            format='%(asctime)s %(levelname)s:%(message)s')

    # If keyboard interrupt is detected #
    except KeyboardInterrupt:
        print('\n\n* [EXIT] Ctrl + c detected .. exiting *')
        sys.exit(0)

    # If unknown exception occurs #
    except Exception as err:
        print_err(f'Unknown error occurred in program start up: {err}', 2)
        sys.exit(1)

    # Main menu exception handled loop #
    while True:
        try:
            main_menu(dbs, auth, cmds)

        # If keyboard interrupt is detected #
        except KeyboardInterrupt:
            print('\n\n* [EXIT] Ctrl + c detected .. exiting *')

        # If unknown exception occurs #
        except Exception as err:
            print_err('Unexpected exception occurred .. check log', 2)
            logger(f'Exception occurred: {err}\n\n', auth, operation='write', handler='exception')
            continue

    sys.exit(0)
