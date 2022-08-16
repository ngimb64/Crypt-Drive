""" Built-in modules """
import os
import re
from base64 import b64decode
from pathlib import Path
# Custom modules #
import Modules.globals as global_vars
from Modules.utils import file_handler, meta_strip, print_err, query_handler


def decrypt_input(re_user, re_path) -> tuple:
    """
    Gathers users input for database data decryption function.

    :param re_user:  Compiled regex to match username.
    :param re_path:  Compiled regex to match the path where the data is being decrypted.
    :return:  Tuple of user validated input.
    """
    while True:
        user = input('Enter username of data to decrypt or hit enter for your own '
                     'data: ')
        local_path = input('\nEnter [A-Z]:\\Windows\\path or /Linux/path to export to or'
                           ' enter for DecryptDock\n')
        # If username regex fails and enter was not entered
        # or path regex fails and enter was not entered #
        if (not re.search(re_user, user) and user != '') or \
        (not re.search(re_path, local_path) and local_path != ''):
            print_err('Improper format .. try again following instructions', 2)
            continue

        break

    if local_path == '':
        local_path = global_vars.DIRS[1]

    return user, local_path


def extract_input(re_dir, re_path) -> tuple:
    """
    Gathers users input for database data extraction function.

    :param re_path:  Compiled regex to match input file path.
    :param re_dir:  Compiled regex to match input directory name.
    :return:  Tuple of validated user input.
    """
    while True:
        dir_name = input('Enter folder name to be recursively exported from the database: ')
        exp_path = input('\nEnter [A-Z]:\\Windows\\path or /Linux/path to export to'
                     ' or hit enter export in Documents:\n')
        crypt_check = input('\nShould the data be extracted in encrypted or plain text'
                       ' (encrypted or plain)? ')
        delete_check = input('\nShould the data extracted be deleted from the data base after'
                        ' operation (y or n)? ')

        # If path regex fails and enter was not input or folder regex fails #
        if not re.search(re_dir, dir_name) or (not re.search(re_path, exp_path) and exp_path != '')\
        or crypt_check not in ('encrypted', 'plain') or delete_check not in ('y', 'n'):
            print_err('Improper format .. try again following directions', 2)
            continue

        break

    if exp_path == '':
        exp_path = None

    return dir_name, exp_path, crypt_check, delete_check


def extract_parse(re_rel_winpath, re_rel_linpath, row: list, path: str) -> str:
    """
    Attempts to match regex of recursive path on stored file path in extracted database row. If \
    match fails, document is extracted to base directory entered in non-recursive fashion. If \
    stored filepath is formatted as opposing OS, reformat it to current OS.

    :param re_rel_winpath:  Compiled regex to match Windows path.
    :param re_rel_linpath:  Compiled regex to match Linux path.
    :param row:  The extracted row from the storage database.
    :param path:  Base path user entered.
    :return:
    """
    # Use regex to strip out Documents from path #
    win_path_parse = re.search(re_rel_winpath, row[1])
    # Use regex to strip out Documents from path #
    lin_path_parse = re.search(re_rel_linpath, row[1])

    # If stored database path fails to match for both OS formats #
    if not win_path_parse or lin_path_parse:
        # If OS is Windows #
        if os.name == 'nt':
            file_path = f'{path}\\{row[0]}'
        # If OS is Linux #
        else:
            file_path = f'{path}/{row[0]}'
    else:
        # If OS is Windows #
        if os.name == 'nt':
            # If the stored path is in Linux format #
            if lin_path_parse:
                # Replace forward slash with backslash #
                path_parse = row[1].replace('/', '\\')
            else:
                path_parse = row[1]

            # Append relative path to user path to recursively rebuild #
            file_path = f'{path}\\{path_parse}\\{row[0]}'

        # If OS is Linux #
        else:
            # If the stored path is in Windows format #
            if win_path_parse:
                # Replace backwards slash with forward slash #
                path_parse = row[1].replace('\\', '/')
            else:
                path_parse = row[1]

            # Append relative path to user path to recursively rebuild #
            file_path = f'{path}/{path_parse}/{row[0]}'

    return file_path


def import_input(re_user, re_pass):
    """
    Gathers users input for key import function.

    :param re_user:  Compiled regex for matching input username.
    :param re_pass:  Compiled regex for matching input user password.
    :return:  Tuple of user validated input.
    """
    while True:
        user = input('Enter username for key to be imported: ')
        user_pass = input('Enter user decryption password in text message: ')

        # If username or password regex fail #
        if not re.search(re_user, user) or not re.search(re_pass, user_pass):
            print_err('Improper format .. try again following instructions', 2)
            continue

        return user, user_pass


def meta_handler(file_path, folder_path: str, file: str) -> bool:
    """
    Formats file path whether in recursive directory or not depending on OS. Passes formatted file \
    path into meta_strip function to strip the file metadata.

    :param file_path:  The recursive file path matched (if matched or None).
    :param folder_path:  The base path of the file to be scrubbed.
    :param file:  The name of the file to be scrubbed.
    :return:  Boolean result of meta_strip call.
    """
    # If in the base dir #
    if not file_path:
        # If OS is Windows #
        if os.name == 'nt':
            curr_file = f'{folder_path}\\{file}'
        # If OS is Linux #
        else:
            curr_file = f'{folder_path}/{file}'

        # Strip all the metadata before storing #
        return meta_strip(curr_file)
    # If in a recursive dir #
    else:
        # If OS is Windows #
        if os.name == 'nt':
            curr_file = f'{folder_path}\\{file_path}\\{file}'
        # If OS is Linux #
        else:
            curr_file = f'{folder_path}/{file_path}/{file}'

        # Strip all the metadata before storing #
        return meta_strip(curr_file)


def share_input(re_email, re_phone, re_pass):
    """
    Gathers users input for key share function.

    :param re_email:  Compiled regex for matching user input email.
    :param re_phone:  Compiled regex for matching user input phone number.
    :param re_pass: Compiled regex for matching user password.
    :return:  Tuple of user validated input.
    """
    while True:
        send_email = input('Enter your gmail email address: ')
        recv_email = input('Enter receivers email address for encrypted decryption key: ')
        recv_email2 = input('Enter receivers encrypted email address(Protonmail, Tutanota,'
                            ' Etc ..) for auth key: ')
        recv_phone = input('Enter receivers phone number (no hyphens): ')
        carrier = input('Select your phone provider (verizon, sprint, at&t, t-mobile, '
                        'virgin, boost, us-cellular): ')
        key_pass = input('Enter password to encrypt key for email transmission: ')

        # If any of the input regex validations fail #
        if not re.search(re_email, send_email) or not re.search(re_email, recv_email) \
        or not re.search(re_email, recv_email2) or not re.search(re_phone, recv_phone):
            print_err('One of the inputs provided were improper .. try again', 2)
            continue

        # If invalid input was entered #
        if not re.search(re_pass, key_pass):
            print_err('Invalid password format .. numbers, letters'
                      ' & _+$@&( special characters allowed', 2)
            continue

        # If improper carrier was selected #
        if carrier not in ('verizon', 'sprint', 'at&t', 't-mobile', 'virgin', 'boost',
                           'us-cellular'):
            print_err('Improper provider selection made', 2)
            continue

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

        return send_email, recv_email, recv_email2, recv_phone, provider, key_pass


def store_input(re_path) -> tuple:
    """
    Gathers users input for database data storage function.

    :param re_path:  Compiled regex expression to match input file path.
    :return:  Tuple of validated user input.
    """
    while True:
        store_path = input('\nEnter [A-Z]:\\Windows\\path or /Linux/path'
                           ' for database storage or enter for Import:\n')
        prompt = input('\nIs the data being stored encrypted already or in plain text'
                       ' (encrypted or plain)? ')
        prompt2 = input('\nDo you want to delete the files after stored in database (y or n)? ')

        # If regex fails and enter was not input #
        if (not re.search(re_path, store_path) and store_path != '') \
        or prompt not in ('encrypted', 'plain') or prompt2 not in ('y', 'n'):
            print_err('Improper format .. try again following directions', 2)
            continue

        break

    if store_path == '':
        store_path = global_vars.DIRS[3]

    return store_path, prompt, prompt2


def upload_dir_handler(file_path, dirname: str):
    """
    Ensures the full path to the passed in directory name is created.

    :param file_path:  The recursive file path matched (if matched or None).
    :param dirname:  The directory name to be created.
    :return:  Nothing
    """
    try:
        # If in root directory #
        if not file_path:
            # If OS is Windows #
            if os.name == 'nt':
                # Create dir in UploadDock #
                os.mkdir(f'{global_vars.DIRS[4]}\\{dirname}')
            # If OS is Linux #
            else:
                # Create dir in UploadDock #
                os.mkdir(f'{global_vars.DIRS[4]}/{dirname}')

        # If in recursive directory #
        else:
            # If OS is Windows #
            if os.name == 'nt':
                # Set the path for recursive directory creation #
                create_path = Path(f'{global_vars.CWD}\\UploadDock\\{file_path}\\{dirname}')
            # If OS is Linux #
            else:
                # Set the path for recursive directory creation #
                create_path = Path(f'{global_vars.CWD}/UploadDock/{file_path}/{dirname}')

            # Create dir path in UploadDock #
            create_path.mkdir(parents=True, exist_ok=True)

    # Ignore if dir already exists #
    except FileExistsError:
        pass


def upload_extract(dbs: tuple, auth_obj: object, folder: str, prompt3: str):
    """
    Extracts, decodes, and writes storage database contents to upload dock for cloud drive upload.

    :param dbs:  Database name tuple.
    :param auth_obj:  The authentication instance.
    :param folder:  Name of folder to be recursively extracted from database.
    :param prompt3:  y/n value to determine whether the extracted data is to be deleted.
    :return:  None on success or prints error.
    """
    # Confirm the storage database has data to extract #
    query = global_vars.db_contents(dbs[1])
    extract_call = query_handler(dbs[1], query, auth_obj, operation='fetchall')

    # If no data, exit the function #
    if not extract_call:
        print_err('No contents in storage database to upload', 2)
        return False

    # Compile regex for parsing out Documents from stored path #
    re_rel_winpath = re.compile(r'(?<=\\)[a-zA-Z\d_.\\]{1,240}')
    re_rel_linpath = re.compile(r'(?<=/)[a-zA-Z\d_./]{1,240}')
    # Set local_path to UploadDock #
    local_path = global_vars.DIRS[4]

    print(f'\nExporting stored files from folder into Upload Dock:\n{36 * "*"}\n')

    # Iterate through rows in storage db extract call #
    for row in extract_call:
        # If regex is successful #
        if re.search(f'{re.escape(folder)}', row[1]):
            # Decode base64 contents #
            text = b64decode(row[2])

            # Validate and format extraction file path #
            file_path = extract_parse(re_rel_winpath, re_rel_linpath, row, local_path)

            # Confirm all directories in file path exist #
            os.makedirs(os.path.dirname(file_path), exist_ok=True)

            # Write data to path specified by user input #
            file_handler(file_path, 'wb', auth_obj, operation='write', data=text)

            if prompt3 == 'y':
                # Delete item from storage database #
                query = global_vars.db_delete(dbs[1], row[0])
                query_handler(dbs[1], query, auth_obj)

    return True


def upload_input(re_path):
    """
     Gathers users input for data upload to cloud drive.

    :param re_path:  Compiled regex for matching user input file path.
    :return:  Tuple of validated user input.
    """
    while True:
        local_path = input('\nEnter [A-Z]:\\Windows\\path or /Linux/path for upload,'
                           ' \"Storage\" for contents from storage database or enter for '
                           'UploadDock:\n')
        # If regex fails and Storage and enter was not input #
        if not re.search(re_path, local_path) and local_path != 'Storage' and local_path != '':
            print_err('Improper format .. try again following directions', 2)
            continue

        break

    # If user hit enter #
    if local_path == '':
        local_path = global_vars.DIRS[4]

    # If user entered Storage #
    if local_path == 'Storage':
        local_path = None

    # Prompt user if data being uploaded is in encrypted or plain text #
    while True:
        prompt = input('\nIs the data being uploaded already encrypted or in plain text'
                       ' (encrypted or plain)? ')
        prompt2 = input('\nAfter uploading data to cloud should it be deleted (y or n)? ')

        # If improper combination of inputs were supplied #
        if prompt not in ('encrypted', 'plain') or (not local_path and prompt == 'plain') \
        or prompt2 not in ('y', 'n'):
            print_err('Improper input provided .. if Storage selected,'
                      ' encrypted must also be selected', 2)
            continue

        # If user hit enter and specified data is already encrypted #
        if not local_path and prompt == 'encrypted':
            folder = input('\nEnter the folder name to recursively extract'
                           ' from storage database and upload: ')
            prompt3 = input('\nShould the data extracted be deleted from the'
                            ' data base after operation (y or n)? ')

            # If regex validation fails or prompt2 is invalid #
            if not re.search(r'^[a-zA-Z\d_.]{1,30}', folder) or prompt3 not in ('y', 'n'):
                print_err('Improper input provided .. try again', 2)
                continue

            return local_path, prompt, prompt2, folder, prompt3

        return local_path, prompt, prompt2, None, None


def upload_stage(file_path, file: str, auth_obj: object, crypt: bytes):
    """
    Makes of copy of file data to be uploaded in the UploadDock folder.

    :param file_path:  The recursive file path matched (if matched or None).
    :param file:  The file name to be uploaded.
    :param auth_obj:  The authentication instance.
    :param crypt:  Encrypted data to be copied to new file in UploadDock for Upload.
    :return:  Nothing
    """
    # If in root directory #
    if not file_path:
        # If OS is Windows #
        if os.name == 'nt':
            upload_dock_file = f'{global_vars.DIRS[4]}\\{file}'
        # If OS is Linux #
        else:
            upload_dock_file = f'{global_vars.DIRS[4]}/{file}'

        # Re-write data in upload dock retaining file structure #
        file_handler(upload_dock_file, 'wb', auth_obj, operation='write', data=crypt)
    # If in recursive directory #
    else:
        # If OS is Windows #
        if os.name == 'nt':
            upload_dock_file = f'{global_vars.DIRS[4]}\\{file_path}\\{file}'
        # If OS is Linux #
        else:
            upload_dock_file = f'{global_vars.DIRS[4]}/{file_path}/{file}'

        # Re-write data in upload dock retaining file structure #
        file_handler(upload_dock_file, 'wb', auth_obj, operation='write', data=crypt)
