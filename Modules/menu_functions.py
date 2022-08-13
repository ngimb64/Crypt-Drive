# pylint: disable=W0106
""" Built-in modules """
import os
import re
from base64 import b64encode, b64decode
from getpass import getuser
from pathlib import Path
from shutil import rmtree
# External Modules #
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.exceptions import InvalidTag
from pydrive2 import auth
from pydrive2.drive import GoogleDrive
# Custom Modules #
import Modules.globals as global_vars
from Modules.utils import decrypt_db_data, cha_init, cha_decrypt, encrypt_db_data, \
                          fetch_upload_comps, file_handler, get_database_comp, meta_strip, \
                          msg_format, msg_send, print_err, query_handler, secure_delete


# Global variables #
PARENT_ID = ''


def db_extract(dbs: tuple, auth_obj: object, folder: str, path: str):
    """
    Extracts data from local storage database in encrypted or plain text.

    :param dbs:  The database name tuple.
    :param auth_obj:  The authentication instance.
    :param folder:  Folder name to be inserted into recursive regex.
    :param path:  Path where the database data will be extracted to.
    :return:  Prints successful operation or error message.
    """
    decryptor = None

    # Prompt user if data should be exported in encrypted or plain text #
    while True:
        prompt = input('\nShould the data be extracted in encrypted or plain text'
                       ' (encrypted or plain)? ')
        prompt2 = input('\nShould the data extracted be deleted from the data base after'
                        ' operation (y or n)? ')

        # If improper input is provided #
        if prompt not in ('encrypted', 'plain') or prompt2 not in ('y', 'n'):
            print_err('Improper input provided .. try again selecting inputs provided', 2)
            continue

        break

    # Confirm the storage database has data to extract #
    query = global_vars.db_contents(dbs[1])
    extract_call = query_handler(dbs[1], query, auth_obj, fetchall=True)

    # If no data, exit the function #
    if not extract_call:
        return print_err('No contents in storage database to export', 2)

    # If data is to be extracted in plain text #
    if prompt == 'plain':
        # Retrieve nonce from Keys db, then decode and decrypt #
        key, nonce = cha_decrypt(auth_obj, dbs[0])
        # Initialize the ChaCha20 algo object #
        algo = cha_init(key, nonce)
        # Set the algo object as decryptor #
        decryptor = algo.decryptor()

    # Compile regex based on folder passed in #
    re_folder = re.compile(f'{re.escape(folder)}')
    # Compile regex for parsing out Documents from stored path #
    re_rel_winpath = re.compile(r'(?<=\\)[a-zA-Z\d_.\\]{1,240}')
    re_rel_linpath = re.compile(r'(?<=/)[a-zA-Z\d_./]{1,240}')

    # Get username of currently logged-in user #
    usr = getuser()

    print(f'\nExporting stored files from {folder}:\n{(29 + len(folder)) * "*"}\n')

    # Iterate through rows from db query #
    for row in extract_call:
        # If regex is successful #
        if re.search(re_folder, row[1]):
            # Decode base64 cipher data #
            text = b64decode(row[2])

            # If data is to be extracted in plain text #
            if prompt == 'plain':
                # Decrypt the data #
                text = decryptor.update(text)

            # If user wants to use saved path in db #
            if not path:
                # If OS is Windows #
                if os.name == 'nt':
                    file_path = f'C:\\Users\\{usr}\\{row[1]}\\{row[0]}'
                # If OS is Linux #
                else:
                    file_path = f'/home/{usr}/{row[1]}/{row[0]}'

                # Confirm all directories in file path exist #
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                # Write data to path saved in db #
                file_handler(file_path, 'wb', auth_obj, operation='write', data=text)

            # User specified file path #
            else:
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

                # Confirm all directories in file path exist #
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                # Write data to path specified by user input #
                file_handler(file_path, 'wb', auth_obj, operation='write', data=text)

            print(f'File: {row[0]}')

            if prompt2 == 'y':
                # Delete item from storage database #
                query = global_vars.db_delete(dbs[1], row[0])
                query_handler(dbs[1], query, auth_obj)

    return print(f'\n\n[SUCCESS] Files from {folder} have been extracted')


def db_store(dbs: tuple, auth_obj: object, path: str):
    """
    Encrypts and inserts data into storage database.

    :param dbs: The database name tuple.
    :param auth_obj:  The authentication instance.
    :param path:  Path where the files to be stored in the database are.
    :return:  Nothing
    """
    encryptor = None

    # Prompt user if data being stored is encrypted or not #
    while True:
        prompt = input('\nIs the data being stored encrypted already or in plain text'
                       ' (encrypted or plain)? ')
        prompt2 = input('\nDo you want to delete the files after stored in database (y or n)? ')

        # If improper input is provided #
        if prompt not in ('encrypted', 'plain') or prompt2 not in ('y', 'n'):
            print_err('Improper input provided .. try again selecting inputs provided', 2)
            continue

        break

    # If the data to be stored is in plain text #
    if prompt == 'plain':
        # Retrieve nonce from Keys db, then decode and decrypt #
        key, nonce = cha_decrypt(auth_obj, dbs[0])
        # Initialize the ChaCha20 algo object #
        algo = cha_init(key, nonce)
        # Set the algo object to encryptor #
        encryptor = algo.encryptor()

    # List of metadata file extension types #
    ext = ('.avi', '.doc', '.docm', '.docx', '.exe', '.gif',
           '.jpg', '.jpeg', '.m4a', '.mp3', '.mp4', '.pdf',
           '.png', '.pptx', '.rar', '.wav', '.wma', '.zip')

    print(f'\nStoring path in database:\n{21 * "*"}\n')

    # Iterate recursively through path, encrypting &
    # storing data in the storage database #
    for dir_path, dir_names, file_names in os.walk(path):
        for file in file_names:
            # Cut any path higher in hierarchy than Documents on the path passed in.
            # Which enables the ability to recursively rebuild with any user with keys #

            # If OS is Linux #
            if os.name == 'nt':
                rel_path = re.search(r'Documents\\[a-zA-Z\d._\\]{1,240}$', dir_path)
                curr_file = f'{dir_path}\\{file}'
            # If OS is Linux #
            else:
                rel_path = re.search(r'Documents/[a-zA-Z\d._/]{1,240}$', dir_path)
                curr_file = f'{dir_path}/{file}'

            # If file contains extension with metadata #
            if file.endswith(ext):
                # Strip all the metadata before storing #
                strip = meta_strip(curr_file)
                # If metadata strip failed, avoid storing #
                if not strip:
                    continue

            # Read file data #
            file_data = file_handler(curr_file, 'rb', auth_obj, operation='read')

            # If in plain text, encrypt it #
            if prompt == 'plain':
                # Encrypt the plain text data #
                crypt = encryptor.update(file_data)
                # Encrypted data is base64 encoded for storage #
                data = b64encode(crypt).decode()
            else:
                # Cipher data is base64 encoded for storage #
                data = b64encode(file_data).decode()

            # Path is stored like "Documents\path\to\folder", file is stored as the name #
            query = global_vars.db_store(dbs[1], file, rel_path.group(0), data)
            query_handler(dbs[1], query, auth_obj)

            print(f'File: {file}')

            # If user wants to delete stored files #
            if prompt2 == 'y':
                # Delete (unlink) from file system after storage #
                secure_delete(curr_file)

    if prompt2 == 'y':
        # Recursively delete leftover empty folders
        for dir_path, dir_names, _ in os.walk(path):
            [os.rmdir(f'{dir_path}\\{folder}') if os.name == 'nt'
             else os.rmdir(f'{dir_path}/{folder}') for folder in dir_names]

    print(f'\n\n[SUCCESS] Files from {path} have been encrypted & inserted into storage database')


def decryption(db_names: str, user: str, auth_obj: object, local_path: str):
    """
    Decrypts data located on the file system.

    :param db_names:  The database name tuple.
    :param user:  Username of the data to decrypt.
    :param auth_obj:  The authentication instance.
    :param local_path:  Path to where the data is locally stored on disk.
    :return:  Prints successful operation or error message.
    """
    # If local user is specified #
    if user == '':
        user_key = 'upload_key'
        user_nonce = 'upload_nonce'
    else:
        user_key = f'{user}_decrypt'
        user_nonce = f'{user}_nonce'

    # Get the decrypted database key #
    db_key = get_database_comp(auth_obj)
    # Attempt to Retrieve the upload key and nonce from Keys db #
    decrypt_call, nonce_call = fetch_upload_comps(db_names, user_key, user_nonce, auth_obj)

    # If decrypt key doesn't exist in db #
    if not decrypt_call or not nonce_call:
        return print_err('Database missing decrypt component .. exit and'
                        ' restart program to fix issue', 2)

    # Decrypt key & nonce #
    decrypt_key = decrypt_db_data(db_key, decrypt_call[1])
    decrypt_nonce = decrypt_db_data(db_key, nonce_call[1])

    # Initialize the ChaCha20 algo object #
    algo = cha_init(decrypt_key, decrypt_nonce)
    # Set the object as decryptor #
    decryptor = algo.decryptor()

    print(f'\nDecrypting files in path:\n{26 * "*"}\n')

    # Iterate through folders/files recursively in selected path, decrypt data #
    for dir_path, _, file_names in os.walk(local_path):
        print(f'Path: {dir_path}\n')

        for file in file_names:
            print(f'File: {file}')

            # If OS is Windows #
            if os.name == 'nt':
                curr_file = f'{dir_path}\\{file}'
            # If OS is Linux #
            else:
                curr_file = f'{dir_path}/{file}'

            # Read the encrypted file data #
            file_data = file_handler(curr_file, 'rb', auth_obj, operation='read')
            # Decrypt the encrypted file data #
            plain = decryptor.update(file_data)
            # Delete the encrypted file data #
            secure_delete(curr_file)
            # Re-write the plain text data to file #
            file_handler(curr_file, 'wb', auth_obj, operation='write', data=plain)

    return print('\n\n[SUCCESS] Data has been decrypted')


def file_upload(drive: object, up_path, dir_path: str, file: str, http: object, local_path):
    """
    Recursively uploads files to Drive.

    :param drive:  Google Drive authenticated instance.
    :param up_path:  Recursive upload path.
    :param dir_path:  Base directory path.
    :param file:  Name of the file to be uploaded.
    :param http:  Http session object.
    :param local_path:  Local path where data is stored on disk.
    :return:  Nothing
    """
    # If upload is in the root dir #
    if not up_path:
        # If OS is Windows #
        if os.name == 'nt':
            curr_file = f'{dir_path}\\{file}'
        # If OS is Linux #
        else:
            curr_file = f'{dir_path}/{file}'

        # Create Drive file object #
        file_obj = drive.CreateFile({'title': file})
        # Set Drive object content to locally stored file #
        file_obj.SetContentFile(curr_file)
        # Upload file & pass http object into upload call #
        file_obj.upload(param={'http': http})
    else:
        # If OS is Windows #
        if os.name == 'nt':
            curr_file = f'{dir_path}\\{local_path}\\{file}'
        # If OS is Linux #
        else:
            curr_file = f'{dir_path}/{local_path}/{file}'

        # Get List of folders in upload path #
        folders = drive.ListFile({'q': 'title=\'' + up_path + '\' and mimeType=''\'application/vnd.'
                                       'google-apps.folder\' and trashed=false'}).GetList()
        # Iterate through folders in upload path #
        for folder in folders:
            # If folder matches extension path, create it in folder #
            if folder['title'] == up_path:
                # Create Drive file object in parent dir #
                file_obj = drive.CreateFile({'title': file, 'parents': [{'id': folder['id']}]})
                # Set Drive object content to locally stored file in recursive dir #
                file_obj.SetContentFile(curr_file)
                # Upload & pass http object into upload call #
                file_obj.upload(param={'http': http})
                break


def folder_upload(drive: object, parent_dir, dir_list: list, http: object):
    """
    Recursively uploads folders to Drive.

    :param drive:  Google Drive authenticated instance.
    :param parent_dir:  Parent directory name.
    :param dir_list:  List of subdirectories to be created.
    :param http:  Http session instance.
    :return:  Nothing
    """
    global PARENT_ID
    add_id = ''

    # If there are folders to upload #
    if dir_list:
        # Iterate through list of passed in folders #
        for directory in dir_list:
            # If upload is in the root dir #
            if not parent_dir:
                # Create folder object #
                folder = drive.CreateFile({'title': directory,
                                           'mimeType': 'application/vnd.google-apps.folder'})
                # Upload & pass http object into upload call #
                folder.upload(param={'http': http})

                print(f'Directory: {directory}')
            else:
                folder_list = drive.ListFile({'q': f'\"{PARENT_ID}\" in parents and trashed=false'}
                                             ).GetList()

                # Iterate through fetched drive folder list #
                for folder in folder_list:
                    if folder['title'] == parent_dir:
                        # Create sub-folder object & upload #
                        parent = drive.CreateFile({'title': directory,
                                                   'parents': [{'kind': 'drive#fileLink',
                                                                'id': folder['id']}],
                                                   'mimeType': 'application/vnd.google-apps.folder'}
                                                  )
                        # Upload & pass http object into upload call #
                        parent.upload(param={'http': http})

                        print(f'Directory: {directory}')

                        # Update parent id for next iteration #
                        add_id = parent['parents'][0]['id']

                        break

        if not PARENT_ID:
            # Set root as parent folder for next iteration
            PARENT_ID = 'root'
        else:
            # Set added sub-folder id $
            PARENT_ID = add_id


def import_key(db_names: str, auth_obj: object, user: str, user_pass: str):
    """
    Import user's key to the encrypted local key database.

    :param db_names:  Database name tuple.
    :param auth_obj:  The authentication instance.
    :param user:  Username associated with key import.
    :param user_pass:  Temporary key sharing password.
    :return:  Prints successful operation or error message.
    """
    # If OS is Windows #
    if os.name == 'nt':
        key_path = f'{global_vars.DIRS[1]}\\{user}_decrypt.txt'
        key_nonce_path = f'{global_vars.DIRS[1]}\\{user}_key_nonce.txt'
        aesccm_path = f'{global_vars.DIRS[1]}\\{user}_aesccm.txt'
        nonce_path = f'{global_vars.DIRS[1]}\\{user}_nonce.txt'
    # If OS is Linux #
    else:
        key_path = f'{global_vars.DIRS[1]}/{user}_decrypt.txt'
        key_nonce_path = f'{global_vars.DIRS[1]}/{user}_key_nonce.txt'
        aesccm_path = f'{global_vars.DIRS[1]}/{user}_aesccm.txt'
        nonce_path = f'{global_vars.DIRS[1]}/{user}_nonce.txt'

    # Confirm all critical files to operation are present #
    if not global_vars.file_check(key_path) or not global_vars.file_check(key_nonce_path) \
    or not global_vars.file_check(aesccm_path) or not global_vars.file_check(nonce_path):
        return print_err('A component needed for importing key is missing, 4 files are required in'
                        ' the Import directory:\n[user]_decrypt.txt, [user]_key_nonce.txt,'
                        ' [user]_aesccm.txt, [user]_nonce.txt', 2.5)

    # Load user AESCCM decrypt components #
    key = file_handler(aesccm_path, 'rb', auth_obj, operation='read')
    nonce = file_handler(nonce_path, 'rb', auth_obj, operation='read')
    aesccm = AESCCM(key)

    # Read users decrypt & nonce key #
    crypt_key = file_handler(key_path, 'rb', auth_obj, operation='read')
    crypt_nonce = file_handler(key_nonce_path, 'rb', auth_obj, operation='read')

    # Unlock users decrypt & nonce key #
    try:
        user_key = aesccm.decrypt(nonce, crypt_key, user_pass.encode())
        user_nonce = aesccm.decrypt(nonce, crypt_nonce, user_pass.encode())

    # If the authentication tag is invalid #
    except InvalidTag:
        return print_err('Incorrect unlock password entered .. try restarting program or deleting'
                        ' Keys/Dbs folders', 2)

    # Get the decrypted database key #
    db_key = get_database_comp(auth_obj)

    # Encrypt user components #
    upload_key = encrypt_db_data(db_key, user_key)
    upload_nonce = encrypt_db_data(db_key, user_nonce)

    # Send users decrypt key to key database #
    query = global_vars.db_insert(db_names, f'{user}_decrypt', upload_key)
    query_handler(db_names, query, auth_obj)

    # Send users nonce to database #
    query = global_vars.db_insert(db_names, f'{user}_nonce', upload_nonce)
    query_handler(db_names, query, auth_obj)

    # Delete file in Import dir #
    [secure_delete(file) for file in (key_path, key_nonce_path, aesccm_path, nonce_path)]

    return print(f'\n\n[SUCCESS] {user}\'s public key has been imported ..'
                 ' now in Keys directory & databases')


def list_drive():
    """
    List the contents of Google Drive storage.

    :return:  Nothing
    """
    # Authenticate drive #
    gauth = auth.GoogleAuth()
    gauth.LocalWebserverAuth()
    drive = GoogleDrive(gauth)

    # Retrieve contents of root Google Drive directory as list #
    drive_list = drive.ListFile({'q': '\'root\' in parents and trashed=false'}).GetList()

    print(f'\nDrive Contents\n{15 * "*"}\n')

    # Iterate through retrieved list and print #
    for item in drive_list:
        # If the item mimeType is folder #
        if item['mimeType'] == 'application/vnd.google-apps.folder':
            print(f'Folder:  {item["title"]}')
        # For file mimeType #
        else:
            print(f'File:  {item["title"]}')

    input('\nHit enter to continue ')


def list_storage(db_name: str, auth_obj: object):
    """
    List the contents of the local storage database.

    :param db_name:  Storage database name.
    :param auth_obj:  The authentication instance.
    :return:   Nothing
    """
    # Fetch the contents of the storage database # #
    query = global_vars.db_contents(db_name)
    list_call = query_handler(db_name, query, auth_obj, fetchall=True)

    # If no data, exit the function #
    if not list_call:
        print_err('No contents in storage database to export', 1)
        return

    print(f'\nStorage Database Contents\n{(26 * "*")}\n')
    # Print the results of the retrieved database #
    [print('File name:  {:30s}  Saved path:  {:30s}'.format(row[0], row[1])) for row in list_call]

    input('\nHit enter to continue ')


def key_share(db_name: str, auth_obj: object, send_email: str, email_pass: str, receivers: str,
              re_pass: object):
    """
    Share decryption key protected by a password through authentication-based encryption.

    :param db_name:  Keys database name.
    :param auth_obj:  The authentication instance.
    :param send_email:  Key senders email address.
    :param email_pass:  Key senders generated application password.
    :param receivers:  Receivers email and phone information.
    :param re_pass:  Compiled regex for password matching.
    :return:  Nothing
    """
    # Retrieve and decrypt ChaCha20 components #
    share_key, share_nonce = cha_decrypt(auth_obj, db_name)

    # Prompt user for password to protect key on transit #
    while True:
        key_pass = input('Enter password to encrypt key for email transmission: ')

        # If invalid input was entered #
        if not re.search(re_pass, key_pass):
            print_err('Invalid password format .. numbers, letters'
                     ' & _+$@&( special characters allowed', 2)
            continue

        break

    # Create AESCCM password authenticated key #
    key = AESCCM.generate_key(bit_length=256)
    aesccm = AESCCM(key)
    nonce = os.urandom(13)

    # Encrypt components with temporary password-based encryption #
    key_crypt = aesccm.encrypt(nonce, share_key, key_pass.encode())
    key_nonce = aesccm.encrypt(nonce, share_nonce, key_pass.encode())

    # Change directory into Keys #
    os.chdir(global_vars.DIRS[3])

    # Grab username from email with regex & format it to file names #
    user = re.search(r'\w{2,30}(?=@)', send_email)
    key_path = f'{user.group(0)}_decrypt.txt'
    key_nonce_path = f'{user.group(0)}_key_nonce.txt'
    aesccm_path = f'{user.group(0)}_aesccm.txt'
    nonce_path = f'{user.group(0)}_nonce.txt'

    # Write components to be sent in files #
    file_handler(key_path, 'wb', auth_obj, operation='write', data=key_crypt)
    file_handler(key_nonce_path, 'wb', auth_obj, operation='write', data=key_nonce)
    file_handler(aesccm_path, 'wb', auth_obj, operation='write', data=key)
    file_handler(nonce_path, 'wb', auth_obj, operation='write', data=nonce)

    # Group message data to be iterated over #
    body = ('Attached below is your encrypted decryption key .. download and move to import folder',
            'Attached below is your unlock key with & nonce .. download and move to import folder',
            f'Your unlock password is => {key_pass}')

    # Group message data to be iterated over #
    files = ((key_path, nonce_path), (aesccm_path, key_nonce_path), (None, None))

    count = 0
    # Iterate of different message destinations #
    for receiver in receivers:
        # Format email #
        msg = msg_format(send_email, receiver, body[count], files[count])
        # Send email #
        msg_send(send_email, receiver, email_pass, msg, auth_obj)
        count += 1

    # Delete sent items
    [secure_delete(file) for file in (key_path, key_nonce_path, aesccm_path, nonce_path)]

    # Change dir back into __main__ #
    os.chdir(global_vars.CWD)
    print('\n\n[SUCCESS] Keys and password successfully sent')


def upload(dbs: tuple, auth_obj: object, local_path: str):
    """
    Manages encrypted recursive upload to Google Drive.

    :param dbs:  Database name tuple.
    :param auth_obj:  The authentication instance.
    :param local_path:  Local path on disk to be uploaded.
    :return:  Prints successful operation or error message.
    """
    global PARENT_ID
    encryptor = None
    folder = None
    prompt3 = None

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
            if not re.search(r'^[a-zA-Z\d_.]{1,30}', folder) or prompt2 not in ('y', 'n'):
                print_err('Improper input provided .. try again', 2)
                continue

        break

    if prompt == 'plain':
        # Retrieve and decrypt ChaCha20 components #
        upload_key, upload_nonce = cha_decrypt(auth_obj, dbs[0])
        # Initialize ChaCha20 encryption algo #
        algo = cha_init(upload_key, upload_nonce)
        # Set algo object to encryptor #
        encryptor = algo.encryptor()

    # If local_path was passed in as None
    # due to the user selecting storage #
    if not local_path:
        # Confirm the storage database has data to extract #
        query = global_vars.db_contents(dbs[1])
        extract_call = query_handler(dbs[1], query, auth_obj, fetchall=True)

        # If no data, exit the function #
        if not extract_call:
            return print_err('No contents in storage database to upload', 2)

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

                # Use regex to strip out Documents from path #
                win_path_parse = re.search(re_rel_winpath, row[1])
                # Use regex to strip out Documents from path #
                lin_path_parse = re.search(re_rel_linpath, row[1])
                # If stored database path fails to match for both OS formats #
                if not win_path_parse or lin_path_parse:
                    # If OS is Windows #
                    if os.name == 'nt':
                        file_path = f'{local_path}\\{row[0]}'
                    # If OS is Linux #
                    else:
                        file_path = f'{local_path}/{row[0]}'
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
                        file_path = f'{local_path}\\{path_parse}\\{row[0]}'
                    # If OS is Linux #
                    else:
                        # If the stored path is in Windows format #
                        if win_path_parse:
                            # Replace backwards slash with forward slash #
                            path_parse = row[1].replace('\\', '/')
                        else:
                            path_parse = row[1]

                        # Append relative path to user path to recursively rebuild #
                        file_path = f'{local_path}/{path_parse}/{row[0]}'

                # Confirm all directories in file path exist #
                os.makedirs(os.path.dirname(file_path), exist_ok=True)

                # Write data to path specified by user input #
                file_handler(file_path, 'wb', auth_obj, operation='write', data=text)

                if prompt3 == 'y':
                    # Delete item from storage database #
                    query = global_vars.db_delete(dbs[1], row[0])
                    query_handler(dbs[1], query, auth_obj)

    # Authenticate drive #
    gauth = auth.GoogleAuth()
    gauth.LocalWebserverAuth()
    drive = GoogleDrive(gauth)

    # Create reusable http object, preventing re-authentication per call #
    http = drive.auth.Get_Http_Object()

    # Grab the rightmost directory of the current path for upload #
    if os.name == 'nt':
        re_upload_path = re.compile(r'[^\\]{1,30}$')
    else:
        re_upload_path = re.compile(r'[^/]{1,30}$')

    # Grab only the rightmost directory of path save result in other regex
    # as anchor point for confirming recursive directories while crawling #
    re_path_edge = re.search(re_upload_path, local_path)
    # Insert path edge regex match into regex to match any path past the edge anchor point #
    if os.name == 'nt':
        re_file_path = re.compile(rf'(?<={re.escape(str(re_path_edge.group(0)))}\\).+$')
    else:
        re_file_path = re.compile(rf'(?<={re.escape(str(re_path_edge.group(0)))}/).+$')

    # List of file extension types #
    ext = ('.avi', '.doc', '.docm', '.docx', '.exe', '.gif',
           '.jpg', '.jpeg', '.m4a', '.mp3', '.mp4', '.pdf',
           '.png', '.pptx', '.rar', '.wav', '.wma', '.zip')

    print(f'\nUploading files in path:\n{25 * "*"}')

    # Iterate through folders/files recursively in upload source path,
    # encrypt data, then upload to destination path #
    for folder_path, folder_names, file_names in os.walk(local_path):
        print(f'\nUpload path: {folder_path}\n')

        # Attempt to grab the rightmost dir in path #
        upload_path_match = re.search(re_upload_path, folder_path)
        # Attempt to match path beyond folder specified at end of path #
        file_path_match = re.search(re_file_path, folder_path)

        # If match for upload path #
        if upload_path_match:
            upload_path = str(upload_path_match.group(0))
        else:
            upload_path = None

        # If match for local files #
        if file_path_match:
            file_path = str(file_path_match.group(0))
        else:
            file_path = None

        # Upload folder to Drive #
        for dirname in folder_names:
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

        # If match for local files #
        if not file_path:
            # Create folder in drive #
            folder_upload(drive, None, folder_names, http)
        else:
            # Create folder in UploadDock #
            folder_upload(drive, upload_path, folder_names, http)

        for file in file_names:
            # If OS is Windows #
            if os.name == 'nt':
                curr_file = f'{folder_path}\\{file}'
            # If OS is Linux #
            else:
                curr_file = f'{folder_path}/{file}'

            # If file is empty ignore and move to next #
            if not os.stat(curr_file).st_size > 0:
                continue

            # If the UploadDock is not being used  #
            if local_path != global_vars.DIRS[4]:
                # Read file data #
                file_data = file_handler(curr_file, 'rb', auth_obj, operation='read')

                # If in plain text, encrypt it #
                if prompt == 'plain':
                    crypt = encryptor.update(file_data)
                else:
                    crypt = file_data

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

            # If file contains extension suggesting metadata #
            if file.endswith(ext):
                # If in the base dir #
                if not file_path:
                    # If OS is Windows #
                    if os.name == 'nt':
                        curr_file = f'{folder_path}\\{file}'
                    # If OS is Linux #
                    else:
                        curr_file = f'{folder_path}/{file}'

                    # Strip all the metadata before storing #
                    strip = meta_strip(curr_file)
                # If in a recursive dir #
                else:
                    # If OS is Windows #
                    if os.name == 'nt':
                        curr_file = f'{folder_path}\\{file_path}\\{file}'
                    # If OS is Linux #
                    else:
                        curr_file = f'{folder_path}/{file_path}/{file}'

                    # Strip all the metadata before storing #
                    strip = meta_strip(curr_file)

                # If metadata strip failed, avoid uploading #
                if not strip:
                    continue

            # If in root directory #
            if not file_path:
                # Upload file to Drive #
                file_upload(drive, None, global_vars.DIRS[4], file, http, None)
            # If in recursive directory #
            else:
                # Upload file to Drive #
                file_upload(drive, upload_path, global_vars.DIRS[4], file, http, file_path)

            print(f'File: {file}')

            # If the user wants to delete data after uploading #
            if prompt2 == 'y':
                # If OS is Windows #
                if os.name == 'nt':
                    curr_file = f'{folder_path}\\{file}'
                # If OS is Linux #
                else:
                    curr_file = f'{folder_path}/{file}'

                secure_delete(curr_file)

    # Clear all data in UploadDock #
    rmtree(global_vars.DIRS[4])
    os.mkdir(global_vars.DIRS[4])

    if prompt2 == 'y':
        for folder_path, folder_names, _ in os.walk(local_path):
            [os.rmdir(f'{folder_path}\\{dirname}') if os.name == 'nt'
             else os.rmdir(f'{folder_path}/{dirname}') for dirname in folder_names]

    PARENT_ID = ''

    return print(f'\n\n[SUCCESS] Files from {local_path} have been uploaded')