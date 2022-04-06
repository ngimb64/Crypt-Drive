# Built-in Modules #
import os
import re
import time
from base64 import b64encode, b64decode
from getpass import getuser
from pathlib import Path
from shutil import rmtree

# Third-party Modules #
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidTag
from pydrive2 import auth
from pydrive2.drive import GoogleDrive
from pydrive2.files import GoogleDriveFileList

# Custom Modules #
import Modules.Globals as Globals
from Modules.Utils import FileHandler, MsgFormat, MsgSend, PrintErr, QueryHandler, SystemCmd

"""
##################
# Function Index #
########################################################################################################################
DbExtract - Export data from storage database.
DbStore - Stores data into the storage database.
Decryption - Decrypts data in decrypt doc or specified path to storage database.
FileUpload - Uploads file in upload dock or specified path to Google Drive.
FolderUpload - Uploads folder in upload dock or specified path to Google Drive.
ImportKey - Imports remote user decryption contents to decrypt shared data.
ListDrive - Lists root directory of users Google Drive.
ListStorage - Lists contents of storage database.
ShareKey - Shares decrypt components with other user protected via temporary password.
Upload - Google Drive upload function.
########################################################################################################################
"""

# Global variables #
parent_id = ''


"""
########################################################################################################################
Name:       DbExtract
Purpose:    Extracts data from local storage database in encrypted or plain text.
Parameters: The database tuple, hashed password, recursive anchor folder name, and path to extract data. 
Returns:    None
########################################################################################################################
"""
def DbExtract(dbs: tuple, password: bytes, folder: str, path: str):
    decryptor = None

    # Prompt user if data should be exported in encrypted or plain text #
    while True:
        prompt = input('\nShould the data be extracted in encrypted or plain text (encrypted or plain)? ')
        prompt2 = input('\nShould the data extracted be deleted from the data base after operation (y or n)? ')
        if prompt not in ('encrypted', 'plain') or prompt2 not in ('y', 'n'):
            PrintErr('\n* [ERROR] Improper input provided .. try again selecting inputs provided *\n', 2)
            continue

        break

    # Confirm the storage database has data to extract #
    query = Globals.DB_CONTENTS(dbs[1])
    extract_call = QueryHandler(dbs[1], query, password, fetchall=True)
    # If no data, exit the function #
    if not extract_call:
        PrintErr('\n* [ERROR] No contents in storage database to export *', 2)
        return

    if prompt == 'plain':
        # Load AESCCM decrypt components #
        key = FileHandler('.\\Keys\\aesccm.txt', 'rb', password, operation='read')
        nonce = FileHandler('.\\Keys\\nonce.txt', 'rb', password, operation='read')
        aesccm = AESCCM(key)

        # Unlock the local database key #
        crypt = FileHandler('.\\Keys\\db_crypt.txt', 'rb', password, operation='read')
        db_key = aesccm.decrypt(nonce, crypt, password)

        # Retrieve decrypt key from database #
        query = Globals.DB_RETRIEVE(dbs[0], 'upload_key')
        decrypt_call = QueryHandler(dbs[0], query, password, fetchone=True)

        # Retrieve nonce from database #
        query = Globals.DB_RETRIEVE(dbs[0], 'upload_nonce')
        nonce_call = QueryHandler(dbs[0], query, password, fetchone=True)

        # If decrypt key doesn't exist in db #
        if not decrypt_call or not nonce_call:
            PrintErr('\n* [ERROR] Database missing decrypt component ..'
                     ' exit and restart program to fix issue *', 2)
            return

        # Decrypt key & nonce #
        key = Fernet(db_key).decrypt(decrypt_call[1].encode())
        nonce = Fernet(db_key).decrypt(nonce_call[1].encode())

        # Decode retrieved key & nonce from base64 format #
        decrypt_key, decrypt_nonce = b64decode(key), b64decode(nonce)

        # Initialize ChaCha20 encryption algo #
        algo = algorithms.ChaCha20(decrypt_key, decrypt_nonce)
        cipher = Cipher(algo, mode=None)
        decryptor = cipher.decryptor()

    # Compile regex based on folder passed in #
    re_folder = re.compile(f'{folder}')
    # Compile regex for parsing out Documents from stored path #
    re_relPath = re.compile(r'(?<=\\)[a-zA-Z0-9_.\\]+')

    # Get username of currently logged-in user #
    usr = getuser()

    print(f'\nExporting stored files from {folder}:\n{(29 + len(folder)) * "*"}\n')

    for row in extract_call:
        # If regex is successful #
        if re.search(re_folder, row[1]):
            # Decode base64 contents #
            text = b64decode(row[2])

            # If encrypted .. decrypt it #
            if prompt == 'plain':
                text = decryptor.update(text)

            # If user wants to use saved path in db #
            if not path:
                # If OS is Windows #
                if os.name == 'nt':
                    file_path = f'C:\\Users\\{usr}\\{row[1]}\\{row[0]}'
                # If OS is Linux #
                else:
                    file_path = f'\\home\\{usr}\\{row[1]}\\{row[0]}'

                # Confirm all directories in file path exist #
                os.makedirs(os.path.dirname(file_path), exist_ok=True)

                # Write data to path saved in db #
                FileHandler(file_path, 'wb', password, operation='write', data=text)
            # User specified file path #
            else:
                # Use regex to strip out Documents from path #
                path_parse = re.search(re_relPath, row[1])
                # If regex fails avoid appending relative path in db #
                if not path_parse:
                    file_path = f'{path}\\{row[0]}'
                else:
                    # Append relative path to user path to recursively rebuild #
                    file_path = f'{path}\\{path_parse.group(0)}\\{row[0]}'

                # Confirm all directories in file path exist #
                os.makedirs(os.path.dirname(file_path), exist_ok=True)

                # Write data to path specified by user input #
                FileHandler(file_path, 'wb', password, operation='write', data=text)

            print(f'File: {row[0]}')

            if prompt2 == 'y':
                # Delete item from storage database #
                query = Globals.DB_DELETE(dbs[1], row[0])
                QueryHandler(dbs[1], query, password)


"""
########################################################################################################################
Name:       DbStore
Purpose:    Encrypts and inserts data into storage database.
Parameters: The database tuple, hashed password, and source path where data is being stored from.
Returns:    None
########################################################################################################################
"""
def DbStore(dbs: tuple, password: bytes, path: str):
    encryptor = None

    # Prompt user if data being stored is encrypted or not #
    while True:
        prompt = input('\nIs the data being stored encrypted already or in plain text (encrypted or plain)? ')
        prompt2 = input('\nDo you want to delete the files after stored in database (y or n)? ')
        if prompt not in ('encrypted', 'plain') or prompt2 not in ('y', 'n'):
            PrintErr('\n* [ERROR] Improper input provided .. try again selecting inputs provided *\n', 2)
            continue

        break

    if prompt == 'plain':
        # Load AESCCM decrypt components #
        key = FileHandler('.\\Keys\\aesccm.txt', 'rb', password, operation='read')
        nonce = FileHandler('.\\Keys\\nonce.txt', 'rb', password, operation='read')
        aesccm = AESCCM(key)

        # Unlock the local database key #
        crypt = FileHandler('.\\Keys\\db_crypt.txt', 'rb', password, operation='read')
        db_key = aesccm.decrypt(nonce, crypt, password)

        # Retrieve upload encryption key from database #
        query = Globals.DB_RETRIEVE(dbs[0], 'upload_key')
        decrypt_call = QueryHandler(dbs[0], query, password, fetchone=True)

        # Retrieve upload nonce from database #
        query = Globals.DB_RETRIEVE(dbs[0], 'upload_nonce')
        nonce_call = QueryHandler(dbs[0], query, password, fetchone=True)

        # If decrypt key doesn't exist in db #
        if not decrypt_call or not nonce_call:
            PrintErr('\n* [ERROR] Database missing decrypt component .. exit and restart program to fix issue *', 2)
            return

        # Decrypt key & nonce #
        key = Fernet(db_key).decrypt(decrypt_call[1].encode())
        nonce = Fernet(db_key).decrypt(nonce_call[1].encode())

        # Decode retrieved key & nonce from base64 format #
        encrypt_key, encrypt_nonce = b64decode(key), b64decode(nonce)

        # Initialize ChaCha20 encryption algo #
        algo = algorithms.ChaCha20(encrypt_key, encrypt_nonce)
        cipher = Cipher(algo, mode=None)
        encryptor = cipher.encryptor()

    # List of file extension types #
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
            rel_path = re.search(r'Documents\\[a-zA-Z0-9._\\]+$', dir_path)

            # If file contains extension with metadata #
            if file.endswith(ext):
                # Strip metadata from file #
                SystemCmd(f'{dir_path}\\{file}', None, None, 2, exif=True)

            # Read file data #
            file_data = FileHandler(f'{dir_path}\\{file}', 'rb', password, operation='read')

            # If in plain text, encrypt it #
            if prompt == 'plain':            
                crypt = encryptor.update(file_data)

                # Data is base64 encoded for storage #
                data = b64encode(crypt).decode()
            else:
                data = b64encode(file_data).decode()

            # Path is stored like "Documents\path\to\folder", file is stored as the name #
            query = Globals.DB_STORE(dbs[1], file, rel_path.group(0), data)
            QueryHandler(dbs[1], query, password)

            print(f'File: {file}')

            # If user wants to unlink stored files #
            if prompt2 == 'y':
                # Delete (unlink) from file system after storage #
                os.remove(f'{dir_path}\\{file}')

        print('')

    if prompt2 == 'y':
        # Delete leftover empty folders
        for dir_path, dir_names, _ in os.walk(path):
            [os.rmdir(f'{dir_path}\\{folder}') for folder in dir_names]

    # Ask user if they want to permanently delete data from disk #
    while True:
        print('Do you want to permanently shred deleted files in provided path from hard drive?\n')
        prompt = input('Keep in mind this operation could take more than a few minutes'
                       ' depending on the amount of file system being utilized (y or n)? ')
        if prompt not in ('y', 'n'):
            PrintErr('\n* [ERROR] Improper input provided .. try again selecting y or n *\n', 2)
            continue

        break

    if prompt == 'y':
        # Use Windows built-in cipher program to permanently delete unlinked data #
        print('Overwriting deleted data .. this process could take a while depending'
              ' on the amount of file system being utilized')
        SystemCmd(path, None, None, 2, cipher=True)

    print(f'\n[SUCCESS] Files from {path} have been encrypted & inserted into storage database')


"""
########################################################################################################################
Name:       Decryption
Purpose:    Decrypts data located on the file system.
Parameters: The database tuple, username of data to decrypt, hashed password, and local path where data is located.
Returns:    None
########################################################################################################################
"""
def Decryption(db: str, user: str, password: bytes, local_path: str):
    # If local user is specified #
    if user == '':
        user_key = 'upload_key'
        user_nonce = 'upload_nonce'
    else:
        user_key = f'{user}_decrypt'
        user_nonce = f'{user}_nonce'

    # Load AESCCM decrypt components #
    key = FileHandler('.\\Keys\\aesccm.txt', 'rb', password, operation='read')
    nonce = FileHandler('.\\Keys\\nonce.txt', 'rb', password, operation='read')
    aesccm = AESCCM(key)

    # Unlock the local database key #
    crypt = FileHandler('.\\Keys\\db_crypt.txt', 'rb', password, operation='read')
    db_key = aesccm.decrypt(nonce, crypt, password)

    # Retrieve decrypt key from database #
    query = Globals.DB_RETRIEVE(db, user_key)
    decrypt_call = QueryHandler(db, query, password, fetchone=True)

    # Retrieve nonce from database #
    query = Globals.DB_RETRIEVE(db, user_nonce)
    nonce_call = QueryHandler(db, query, password, fetchone=True)

    # If decrypt key doesn't exist in db #
    if not decrypt_call or not nonce_call:
        PrintErr('\n* [ERROR] Database missing decrypt component .. exit and restart program to fix issue *', 2)
        return

    # Decrypt key & nonce #
    key = Fernet(db_key).decrypt(decrypt_call[1].encode())
    nonce = Fernet(db_key).decrypt(nonce_call[1].encode())

    # Decode retrieved key & nonce from base64 format #
    decrypt_key, decrypt_nonce = b64decode(key), b64decode(nonce)

    # Initialize ChaCha20 encryption algo #
    algo = algorithms.ChaCha20(decrypt_key, decrypt_nonce)
    cipher = Cipher(algo, mode=None)
    decryptor = cipher.decryptor()

    print(f'\nDecrypting files in path:\n{26 * "*"}')

    # Iterate through folders/files recursively in selected path, decrypt data #
    for dir_path, _, file_names in os.walk(local_path):
        print(f'\nPath: {dir_path}\n')

        for file in file_names:
            print(f'File: {file}')
            file_data = FileHandler(f'{dir_path}\\{file}', 'rb', password, operation='read')
            plain = decryptor.update(file_data)
            os.remove(f'{dir_path}\\{file}')
            FileHandler(f'{dir_path}\\{file}', 'wb', password, operation='write', data=plain)

    print('\n[SUCCESS] Data has been decrypted')


"""
########################################################################################################################
Name:       FileUpload
Purpose:    Recursively uploads files to Drive.
Parameters: Drive session object, recursive upload path, base directory path, file to be uploaded, http session \
            object, and local directory path.
Returns:    None
########################################################################################################################
"""
def FileUpload(drive, up_path, dir_path: str, file: str, http, local_path):
    # If upload is in the root dir #
    if not up_path:
        file_obj = drive.CreateFile({'title': file})
        # Create the file object #
        file_obj.SetContentFile(f'{dir_path}\\{file}')
        # Upload file & pass http object into upload call #
        file_obj.Upload(param={'http': http})
    else:
        # Create GoogleDrive list #
        folders = GoogleDriveFileList()
        # Get List of folders in upload path #
        folders = drive.ListFile({'q': 'title=\''+up_path+'\' and mimeType='
                                 '\'application/vnd.google-apps.folder\' and trashed=false'}).GetList()
        for folder in folders:
            # If folder matches extension path, create it in folder #
            if folder['title'] == up_path:  
                file_obj = drive.CreateFile({'parents': [{'id': folder['id']}], 'title': file})          
                file_obj.SetContentFile(f'{dir_path}\\{local_path}\\{file}')
                # Upload & pass http object into upload call #
                file_obj.Upload(param={'http': http})


"""
########################################################################################################################
Name:       FolderUpload
Purpose:    Recursively uploads folders to Drive.
Parameters: Drive session object, parent directory name, directory to be created name, http session object, and count.
Returns:    None
########################################################################################################################
"""
def FolderUpload(drive, parent_dir, dirname: str, http, count: int):
    global parent_id

    # If upload is in the root dir #
    if not parent_dir:
        # Create folder object #
        folder = drive.CreateFile({'title': dirname, 'mimeType': 'application/vnd.google-apps.folder'})
        # Upload & pass http object into upload call #
        folder.Upload(param={'http': http})
    else:
        folder_list = GoogleDriveFileList()

        # If upload is past root hierarchy #
        if count > 1:
            folder_list = drive.ListFile({'q': "'{0}' in parents and trashed=false".format(parent_id)}).GetList()
        # If upload is in root directory #
        else: 
            folder_list = drive.ListFile({'q': "'root' in parents and trashed=false"}).GetList()

        for folder in folder_list:
            if folder['title'] == parent_dir:
                # Create sub-folder object & upload #
                parent = drive.CreateFile({'title': dirname, 'parents': [{'kind': 'drive#fileLink', 'id': folder['id']}],
                                           'mimeType': 'application/vnd.google-apps.folder'})

                # Upload & pass http object into upload call #
                parent.Upload(param={'http': http})

                # If parent was created #
                if count >= 1:
                    # Update global parent id variable for next iteration #
                    parent_id = parent['parents'][0]['id']


"""
########################################################################################################################
Name:       ImportKey
Purpose:    Import user's key to the encrypted local key data base.
Parameters: The database tuple, hashed password, associated username, and temporary unlock password.
Returns:    None
########################################################################################################################
"""
def ImportKey(db: str, password: bytes, user: str, user_pass: str):
    key_path = f'.\\Import\\{user}_decrypt.txt'
    key_nonce_path = f'.\\Import\\{user}_key_nonce.txt'
    aesccm_path = f'.\\Import\\{user}_aesccm.txt'
    nonce_path = f'.\\Import\\{user}_nonce.txt'

    # Confirm all critical files to operation are present #
    if not Globals.FILE_CHECK(key_path) or not Globals.FILE_CHECK(key_nonce_path) \
    or not Globals.FILE_CHECK(aesccm_path) or not Globals.FILE_CHECK(nonce_path):
        PrintErr('\n* [ERROR] A component needed for importing key is missing *\n\n'
                 'To import a key 4 files are required in the Import directory:\n'
                 '[user]_decrypt.txt, [user]_key_nonce.txt, [user]_aesccm.txt, [user]_nonce.txt', 2.5)
        return

    # Load user AESCCM decrypt components #
    key = FileHandler(aesccm_path, 'rb', password, operation='read')
    nonce = FileHandler(nonce_path, 'rb', password, operation='read')
    aesccm = AESCCM(key)

    # Read users decrypt & nonce key #
    crypt_key = FileHandler(key_path, 'rb', password, operation='read')
    crypt_nonce = FileHandler(key_nonce_path, 'rb', password, operation='read')

    # Unlock users decrypt & nonce key #
    try:
        user_key = aesccm.decrypt(nonce, crypt_key, user_pass.encode())
        key_nonce = aesccm.decrypt(nonce, crypt_nonce, user_pass.encode())
    except InvalidTag:
        PrintErr('\n* [ERROR] Incorrect unlock password entered .. try '
                 'restarting program or deleting Keys & Dbs folders *', 2)
        return

    # Load local AESCCM decrypt components #
    key = FileHandler('.\\Keys\\aesccm.txt', 'rb', password, operation='read')
    nonce = FileHandler('.\\Keys\\nonce.txt', 'rb', password, operation='read')
    aesccm = AESCCM(key)

    # Unlock the local database key #
    crypt = FileHandler('.\\Keys\\db_crypt.txt', 'rb', password, operation='read')
    db_key = aesccm.decrypt(nonce, crypt, password)

    # Encode user components #
    key, nonce = b64encode(user_key), b64encode(key_nonce)

    # Encrypt user components #
    upload_key = Fernet(db_key).encrypt(key)
    upload_nonce = Fernet(db_key).encrypt(nonce)

    # Send users decrypt key to key database #
    query = Globals.DB_INSERT(db, f'{user}_decrypt', upload_key.decode())
    QueryHandler(db, query, password)

    # Send users nonce to database #
    query = Globals.DB_INSERT(db, f'{user}_nonce', upload_nonce.decode())
    QueryHandler(db, query, password)

    # Delete file in Import dir #
    [os.remove(file) for file in (key_path, key_nonce_path, aesccm_path, nonce_path)]

    print(f'\n[SUCCESS] {user}\'s public key has been imported .. now in Keys directory & databases')


"""
########################################################################################################################
Name:       ListDrive
Purpose:    List the contents of Google Drive storage.
Parameters: None
Returns:    None
########################################################################################################################
"""
def ListDrive():
    # Authenticate drive #
    gauth = auth.GoogleAuth()
    gauth.LocalWebserverAuth()
    drive = GoogleDrive(gauth)

    # Retrieve contents of root Google Drive directory as list #
    drive_list = drive.ListFile({'q': '\'root\' in parents and trashed=false'}).GetList()

    print(f'\nDrive Contents\n{15 * "*"}\n')
    # Iterate through retrieved list and print #
    for item in drive_list:
        if item['mimeType'] == 'application/vnd.google-apps.folder':
            print(f'Folder:\t{item["title"]}')
        else:
            print(f'File:\t{item["title"]}')

    input('\nHit enter to continue ')


"""
########################################################################################################################
Name:       ListStorage
Purpose:    List the contents of the local storage database.
Parameters: The database tuple and hash password.
Returns:    None
########################################################################################################################
"""
def ListStorage(dbs: tuple, password: bytes):
    # Fetch the contents of the storage database # #
    query = Globals.DB_CONTENTS(dbs[1])
    list_call = QueryHandler(dbs[1], query, password, fetchall=True)
    # If no data .. exit the function #
    if not list_call:
        PrintErr('\n* No contents in storage database to export *', 1)
        return

    print('\nStorage Database Contents\n' + ('-' * 15) + '\n')

    for row in list_call:
        print('File name:\t{:30s} Saved path:\t{:30s}'.format(row[0], row[1]))

    input('\nHit enter to continue ')


"""
########################################################################################################################
Name:       ShareKey
Purpose:    Share decryption key protected by a password through authentication-based encryption.
Parameters: The database tuple, hashed password, senders email, encrypted email password, receivers emails & phone \
            information, and compiled password regular expression.
Returns:    None
########################################################################################################################
"""
def ShareKey(db: str, password: bytes, send_email: str, email_pass: str, receivers: str, re_pass):
    # Load AESCCM decrypt components #
    key = FileHandler('.\\Keys\\aesccm.txt', 'rb', password, operation='read')
    nonce = FileHandler('.\\Keys\\nonce.txt', 'rb', password, operation='read')

    # Unlock the local database key #
    aesccm = AESCCM(key)
    crypt = FileHandler('.\\Keys\\db_crypt.txt', 'rb', password, operation='read')
    db_key = aesccm.decrypt(nonce, crypt, password)

    # Retrieve decrypt key from database #
    query = Globals.DB_RETRIEVE(db, 'upload_key')
    decrypt_call = QueryHandler(db, query, password, fetchone=True)

    # Retrieve nonce from database #
    query = Globals.DB_RETRIEVE(db, 'upload_nonce')
    nonce_call = QueryHandler(db, query, password, fetchone=True)

    # If upload key doesn't exist in db #
    if not decrypt_call or not nonce_call:
        PrintErr('\n* Database missing decrypt component .. exit and restart program to make new keys *', 2)
        return

    # Decrypt components #
    key = Fernet(db_key).decrypt(decrypt_call[1].encode())
    nonce = Fernet(db_key).decrypt(nonce_call[1].encode())

    # Decode components #
    share_key = b64decode(key)
    share_nonce = b64decode(nonce)

    # Prompt user for password to protect key on transit #
    while True:
        key_pass = input('Enter password to encrypt key for email transmission: ')
        if not re.search(re_pass, key_pass):
            PrintErr('\n* [ERROR] Invalid password format .. numbers, letters & _+$@&( special characters allowed *', 2)
            continue

        print('\n')
        break

    # Create AESCCM password authenticated key #
    key = AESCCM.generate_key(bit_length=256)
    aesccm = AESCCM(key)
    nonce = os.urandom(13)

    # Encrypt components with temporary password-based encryption #
    key_crypt = aesccm.encrypt(nonce, share_key, key_pass.encode())
    key_nonce = aesccm.encrypt(nonce, share_nonce, key_pass.encode())

    os.chdir('.\\Keys')

    # Grab username from email with regex & format it to file names #
    user = re.search(r'[a-zA-Z0-9_]+?(?=@)', send_email)
    key_path = f'{user.group(0)}_decrypt.txt'
    key_nonce_path = f'{user.group(0)}_key_nonce.txt'
    aesccm_path = f'{user.group(0)}_aesccm.txt'
    nonce_path = f'{user.group(0)}_nonce.txt'

    FileHandler(key_path, 'wb', password, operation='write', data=key_crypt)
    FileHandler(key_nonce_path, 'wb', password, operation='write', data=key_nonce)
    FileHandler(aesccm_path, 'wb', password, operation='write', data=key)
    FileHandler(nonce_path, 'wb', password, operation='write', data=nonce)

    # Group message data to be iterated over #
    body = ('Attached below is your encrypted decryption key .. download and move to import folder',
            'Attached below is your unlock key with & nonce .. download and move to import folder',
            f'Your unlock password is => {key_pass}')

    # Group message data to be iterated over #
    files = ((key_path, nonce_path), (aesccm_path, key_nonce_path), (None, None))

    count = 0 
    # Iterate of different message destinations #
    for receiver in receivers:
        # Format and send emails/text #
        msg = MsgFormat(send_email, receiver, body[count], files[count])
        MsgSend(send_email, receiver, email_pass, msg)        
        count += 1

    # Delete sent items
    [os.remove(file) for file in (key_path, key_nonce_path, aesccm_path, nonce_path)]

    os.chdir('.\\..')
    print('\n[SUCCESS] Keys and password successfully sent')


"""
########################################################################################################################
Name:       Upload
Purpose:    Manages encrypted recursive upload to Google Drive.
Parameters: The database tuple, hashed password, local path to be uploaded, and absolute path for uploads.
Returns:    None
########################################################################################################################
"""
def Upload(dbs: tuple, password: bytes, local_path: str, abs_path: str):
    global parent_id
    encryptor = None
    folder, prompt3 = None, None

    # Prompt user if data being uploaded is in encrypted or plain text #
    while True:
        prompt = input('\nIs the data being uploaded already encrypted or in plain text (encrypted or plain)? ')
        prompt2 = input('\nAfter uploading data to cloud should it be deleted (y or n)? ')

        if prompt not in ('encrypted', 'plain') or (not local_path and prompt == 'plain') or prompt2 not in ('y', 'n'):
            PrintErr('\n* [ERROR] Improper input provided .. if Storage '
                     'selected, encrypted must also be selected *\n', 2)
            continue

        if not local_path and prompt == 'encrypted':
            folder = input('\nEnter the folder name to recursively extract from storage database and upload: ')
            prompt3 = input('\nShould the data extracted be deleted from the data base after operation (y or n)? ')

            if not re.search(r'^[a-zA-Z0-9_.]{1,30}', folder) or prompt2 not in ('y', 'n'):
                PrintErr('\n* [ERROR] Improper input provided .. try again *\n', 2)
                continue

        break

    if prompt == 'plain':
        # Load AESCCM decrypt components #
        key = FileHandler('.\\Keys\\aesccm.txt', 'rb', password, operation='read')
        nonce = FileHandler('.\\Keys\\nonce.txt', 'rb', password, operation='read')
        aesccm = AESCCM(key)

        # Unlock the local database key #
        crypt = FileHandler('.\\Keys\\db_crypt.txt', 'rb', password, operation='read')
        db_key = aesccm.decrypt(nonce, crypt, password)

        # Retrieve upload key from database #
        query = Globals.DB_RETRIEVE(dbs[0], 'upload_key')
        upload_call = QueryHandler(dbs[0], query, password, fetchone=True)

        # Retrieve nonce from database #
        query = Globals.DB_RETRIEVE(dbs[0], 'upload_nonce')
        nonce_call = QueryHandler(dbs[0], query, password, fetchone=True)

        # If upload key doesn't exist in db #
        if not upload_call or not nonce_call:
            PrintErr('\n* Database missing upload key .. exit and restart program to make new keys *', 2)
            return

        # Decrypt & decode upload components #
        plain_key = Fernet(db_key).decrypt(upload_call[1].encode())
        plain_nonce = Fernet(db_key).decrypt(nonce_call[1].encode())

        # Decode upload components #
        upload_key = b64decode(plain_key)
        upload_nonce = b64decode(plain_nonce)

        # Initialize ChaCha20 encryption algo #
        algo = algorithms.ChaCha20(upload_key, upload_nonce)
        cipher = Cipher(algo, mode=None)
        encryptor = cipher.encryptor()

    # If local_path was passed in as None
    # due to the user selecting storage #
    if not local_path:
        # Confirm the storage database has data to extract #
        query = Globals.DB_CONTENTS(dbs[1])
        extract_call = QueryHandler(dbs[1], query, password, fetchall=True)
        # If no data, exit the function #
        if not extract_call:
            PrintErr('\n* [ERROR] No contents in storage database to upload *', 2)
            return

        # Compile regex for parsing out Documents from stored path #
        re_relPath = re.compile(r'(?<=\\)[a-zA-Z0-9_.\\]+')
        # Set local_path to UploadDock #
        local_path = '.\\UploadDock'

        print(f'\nExporting stored files from folder into Upload Dock:\n{36 * "*"}\n')

        for row in extract_call:
            # If regex is successful #
            if re.search(f'{folder}', row[1]):
                # Decode base64 contents #
                text = b64decode(row[2])

                # Use regex to strip out Documents from path #
                path_parse = re.search(re_relPath, row[1])
                # If regex fails avoid appending relative path in db #
                if not path_parse:
                    file_path = f'{local_path}\\{row[0]}'
                else:
                    # Append relative path to user path to recursively rebuild #
                    file_path = f'{local_path}\\{path_parse.group(0)}\\{row[0]}'

                # Confirm all directories in file path exist #
                os.makedirs(os.path.dirname(file_path), exist_ok=True)

                # Write data to path specified by user input #
                FileHandler(file_path, 'wb', password, operation='write', data=text)

                if prompt3 == 'y':
                    # Delete item from storage database #
                    query = Globals.DB_DELETE(dbs[1], row[0])
                    QueryHandler(dbs[1], query, password)

    # Authenticate drive #
    gauth = auth.GoogleAuth()
    gauth.LocalWebserverAuth()
    drive = GoogleDrive(gauth)

    # Create reusable http object, preventing re-authentication per call #
    http = drive.auth.Get_Http_Object()

    # Grab only the rightmost directory of path save result in other regex 
    # as anchor point for confirming recursive directories while crawling #
    reg_pathEdge = re.search(r'[^\\]+$', local_path)
    # Insert path edge regex match into regex to match any path past the edge anchor point #

    # Match the first occurrence #
    reg_filePath = re.compile(r'(?<={0}\\).+$'.format(str(reg_pathEdge.group(0))))

    # Grab the rightmost directory of the current path for upload #
    reg_upPath = re.compile(r'[^\\]+$')

    # List of file extension types #
    ext = ('.avi', '.doc', '.docm', '.docx', '.exe', '.gif',
           '.jpg', '.jpeg', '.m4a', '.mp3', '.mp4', '.pdf',
           '.png', '.pptx', '.rar', '.wav', '.wma', '.zip')

    count = 0

    print(f'\nUploading files in path:\n{25 * "*"}\n')

    # Iterate through folders/files recursively in upload source path,
    # encrypt data, then upload to destination path #
    for dir_path, dir_names, file_names in os.walk(local_path):
        print(f'\nUpload path: {dir_path}\n')

        # Search file path with regex to grab recursive paths #
        filePath_match = re.search(reg_filePath, dir_path)
        upPath_match = re.search(reg_upPath, dir_path)

        # If match for upload #
        if upPath_match:
            upPath = str(upPath_match.group(0))
        else:
            upPath = None

        # If match for local files #
        if filePath_match:
            filePath = str(filePath_match.group(0))
        else:
            filePath = None

        # Upload folder to Drive #
        for dirname in dir_names:
            print(f'Directory name: {dirname}')
            if not filePath:
                try:
                    # Create dir in UploadDock #
                    os.mkdir(f'.\\UploadDock\\{dirname}')
                # Pass if dir already exists #
                except FileExistsError:
                    pass

                # Create folder in drive #
                FolderUpload(drive, None, dirname, http, count)
                count += 1
            else:
                try:
                    # Set the path for recursive directory creation #
                    create_path = Path(f'{abs_path}\\UploadDock\\{filePath}\\{dirname}')
                    # Create dir path in UploadDock #
                    create_path.mkdir(parents=True, exist_ok=True)
                # Pass if dir already exists #
                except FileExistsError:
                    pass

                # Create folder in UploadDock #
                FolderUpload(drive, upPath, dirname, http, count)
                count += 1

        print('\n')

        for file in file_names:
            print(f'File: {file}')

            # If the UploadDock is not being used  #
            if local_path != '.\\UploadDock':
                # Read file data #
                file_data = FileHandler(f'{dir_path}\\{file}', 'rb', password, operation='read')

                # If in plain text, encrypt it #
                if prompt == 'plain':
                    crypt = encryptor.update(file_data)
                else:
                    crypt = file_data

                # Re-write data in upload dock retaining file structure #
                if not filePath:
                    FileHandler(f'.\\UploadDock\\{file}', 'wb', password, operation='write', data=crypt)
                else:
                    FileHandler(f'.\\UploadDock\\{filePath}\\{file}', 'wb', password, operation='write', data=crypt)

            # If file contains extension suggesting metadata #
            if file.endswith(ext):
                if not filePath:
                    # Strip metadata from file #
                    SystemCmd(f'{abs_path}\\UploadDock\\{file}', None, None, 2, exif=True)
                else:
                    # Strip metadata from file #
                    SystemCmd(f'{abs_path}\\UploadDock\\{filePath}\\{file}', None, None, 2, exif=True)

            # Upload file to Drive #
            if not filePath:
                FileUpload(drive, None, '.\\UploadDock', file, http, None)
            else:
                FileUpload(drive, upPath, '.\\UploadDock', file, http, filePath)

            # If the user wants to delete data after uploading #
            if prompt2 == 'y':
                os.remove(f'{dir_path}\\{file}')

    # Clear all data in UploadDock #
    rmtree('.\\UploadDock')
    os.mkdir('.\\UploadDock')

    if prompt2 == 'y':
        for dir_path, dir_names, _ in os.walk(local_path):
            [os.rmdir(f'{dir_path}\\{dirname}') for dirname in dir_names]

    parent_id = ''

    print(f'\n[SUCCESS] Files from {local_path} have been uploaded')
    time.sleep(2)
