# Built-in Modules #
import os, re
from base64 import b64encode, b64decode
from getpass import getuser
from pathlib import Path
from shutil import rmtree
from time import sleep

# Third-party Modules #
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidTag
from pydrive2 import auth
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
from pydrive2.files import GoogleDriveFileList

# Custom Modules #
import Modules.Globals as Globals
from Modules.Utils import FileHandler, MsgFormat, MsgSend, PrintErr, QueryHandler, SystemCmd

# # Function Index #
# -------------------
# - DbExtract:      export data from storage database
# - DbStore:        stores data into the storage database
# - Decryption:     decrypts data in decrypt doc or specified path to storage database
# - FileUpload:     uploads file in upload dock or specified path to Google Drive
# - FolderUpload:   uploads folder in upload dock or specified path to Google Drive
# - ImportKey:      imports remote user decryption contents to decrypt shared data
# - ListDrive:      lists root directory of users Google Drive
# - ListStorage:    lists connents of storage database
# - ShareKey:       shares decrypt components with other user protected via tempory password
# - Upload:         Google Drive upload function


parent_id = ''

# Extracts data from storage database as encrypted or plaintext #
def DbExtract(dbs, cmd, password, folder, path):
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
    # If no data .. exit the function #
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
    re_relPath = re.compile(r'(?<=\\)[a-zA-Z0-9\_\.\\]+')

    # Get username of currently logged in user #
    usr = getuser()

    print('\nExporting stored files from folder:\n' + ('-' * 36) + '\n')

    for row in extract_call:
        # If regex is successful #
        if re.search(re_folder, row[1]) != None:
            # Decode base64 contents #
            text = b64decode(row[2])

            # If encrypted .. decrypt it #
            if prompt == 'plain':
                text = decryptor.update(text)

            # If user wants to use saved path in db #
            if not path:
                file_path = f'C:\\Users\\{usr}\\' + row[1] + '\\' + row[0]

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
                    file_path = path + '\\' + row[0]
                else:
                    # Append relative path to user path to recursivly rebuild #
                    file_path = path + '\\' + path_parse.group(0) + '\\' + row[0]

                # Confirm all directories in file path exist #
                os.makedirs(os.path.dirname(file_path), exist_ok=True)

                # Write data to path specified by user input #
                FileHandler(file_path, 'wb', password, operation='write', data=text)

            print(f'File: {row[0]}')

            if prompt2 == 'y':
                # Delete item from storage database #
                query = Globals.DB_DELETE(dbs[1], row[0])
                QueryHandler(dbs[1], query, password)

# Encrypts & stores data into storage database #
def DbStore(dbs, cmd, password, path):
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
            PrintErr('\n* [ERROR] Database missing decrypt component ..'
                     ' exit and restart program to fix issue *', 2)
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
    ext = ( '.avi', '.doc', '.docm', '.docx', '.exe', '.gif', 
            '.jpg', '.jpeg', '.m4a', '.mp3', '.mp4', '.pdf', 
            '.png', '.pptx', '.rar', '.wav', '.wma', '.zip' )

    print('\nStoring path in database:\n' + ('-' * 21) + '\n')

    # Iterate recursivly through path, encrypting &
    # storing data in the storage database #
    for dirpath, dirnames, filenames in os.walk(path):
        for file in filenames:
            # Cut any path higher in hierachy than Documents on the path passed in.
            # Which enables the ability to recursively rebuild with any user with keys #
            rel_path = re.search(r'Documents\\[a-zA-Z0-9\.\_\\]+$', dirpath)

            # If file contains extension with metadata #
            if file.endswith(ext):
                # Strip metadata from file #
                SystemCmd((dirpath + '\\' + file), None, None, 2, exif=True)

            # Read file data #
            file_data = FileHandler((dirpath + '\\' + file), 'rb', password, operation='read')

            # If in plain text .. encrypt it #
            if prompt == 'plain':            
                crypt = encryptor.update(file_data)

            # Data is base64 encoded for storage #
            data = b64encode(crypt).decode()

            # path is stored like "Documents\path\to\folder", file is stored as the name #
            query = Globals.DB_STORE(dbs[1], file, rel_path.group(0), data)
            store_call = QueryHandler(dbs[1], query, password)

            print(f'File: {file}')

            # If user wants to unlink stored files #
            if prompt2 == 'y':
                # Delete (unlink) from file system after storage #
                os.remove(dirpath + '\\' + file)

        print('')

    if prompt2 == 'y':
        # Delete leftover empty folders
        for dirpath, dirnames, filenames in os.walk(path):
            [ os.rmdir(dirpath + '\\' + folder) for folder in dirnames ]

    # Ask user if they want to permantly delete data from disk #
    while True:
        print('Do you want to permantly shred deleted files in provided path from hard drive?\n')
        prompt = input('Keep in mind this operation could take more than a few minutes'
                       ' depending on the amount of file system being utilized (y or n)? ')
        if prompt not in ('y', 'n'):
            PrintErr('\n* [ERROR] Improper input provided .. try again selecting y or n *\n', 2)
            continue

        break

    if prompt == 'y':
        # Use Windows built-in ciper program to permanently delete unlinked data #
        print('Overwriting deleted data .. this process could take a while depending'
              ' on the amount of file system being utilized')
        SystemCmd(path, None, None, 2, cipher=True)

    print(f'\n[SUCCESS] Files from {path} have been encrypted & inserted into storage database')

# Decrypts data onto file system or in encrypted database #
def Decryption(db, cmd, user, password, local_path): 
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

    print('\nDecrypting files in path:\n' + ('-' * 26))

    # Iterate through folders/files recurisivly in selected path, decrypt data #
    for dirpath, dirnames, filenames in os.walk(local_path):
        print(f'\nPath: {dirpath}\n')

        for file in filenames:
            print(f'File: {file}')
            file_data = FileHandler((dirpath + '\\' + file), 'rb', password, operation='read')
            plain = decryptor.update(file_data)
            os.remove(dirpath + '\\' + file)
            FileHandler((dirpath + '\\'+ file), 'wb', password, operation='write', data=plain)

    print('\n[SUCCESS] Data has been decrypted')

def FileUpload(drive, up_path, dir_path, file, http, local_path):
    # If upload is in the root dir #
    if not up_path:
        file_obj = drive.CreateFile({'title': file})
        # Create the file object #
        file_obj.SetContentFile(dir_path+'\\'+file)
        # Upload file & pass http object into upload call #
        file_obj.Upload(param={'http': http})
    else:
        # Create GoogleDrive list #
        folders = GoogleDriveFileList()
        # Get List of folders in upload path #
        folders = drive.ListFile({'q': 'title=\''+up_path+'\' and mimeType='
                                 '\'application/vnd.google-apps.folder\' and trashed=false'}).GetList()
        for folder in folders:
            # If folder matches extension path .. create it in folder #
            if folder['title'] == up_path:  
                file_obj = drive.CreateFile({'parents': [{'id': folder['id']}], 'title': file})          
                file_obj.SetContentFile(dir_path+'\\'+local_path+'\\'+file)
                # Upload & pass http object into upload call #
                file_obj.Upload(param={'http': http})       

def FolderUpload(drive, parent_dir, dirname, http, count):
    global parent_id

    # If upload is in the root dir #
    if not parent_dir:
        # Create folder object #
        folder = drive.CreateFile({'title': dirname, 'mimeType': 'application/vnd.google-apps.folder'})
        # Upload & pass http object into upload call #
        folder.Upload(param={'http': http})
    else:
        folder_list = GoogleDriveFileList()

        if count > 1:
            folder_list = drive.ListFile({'q': "'{0}' in parents and trashed=false".format(parent_id)}).GetList()
        else: 
            folder_list = drive.ListFile({'q': "'root' in parents and trashed=false"}).GetList()

        for folder in folder_list:
            if folder['title'] == parent_dir:
                # Create sub-folder object & upload #
                parent = drive.CreateFile({'title': dirname, 'parents': [{'kind': 'drive#fileLink', 'id': folder['id']}],
                                           'mimeType': 'application/vnd.google-apps.folder'})

                # Upload & pass http object into upload call #
                parent.Upload(param={'http': http})

                if count >= 1:
                    parent_id = parent['parents'][0]['id']

def ImportKey(db, password, user, user_pass):
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
    [ os.remove(file) for file in (key_path, key_nonce_path, aesccm_path, nonce_path) ]

    print(f'\n[SUCCESS] {user}\'s public key has been imported .. now in Keys directory & databases')

def ListDrive():
    # Authenticate drive #
    gauth = auth.GoogleAuth()
    gauth.LocalWebserverAuth()
    drive = GoogleDrive(gauth)

    # Retrieve contents of root Google Drive directory as list #
    drive_list = drive.ListFile({'q': '\'root\' in parents and trashed=false'}).GetList()

    print('\nDrive Contents\n' + ('-' * 15) + '\n')
    # Iterate through retrieved list and print #
    for item in drive_list:
        if item['mimeType'] == 'application/vnd.google-apps.folder':
            print('Folder:\t{}'.format(item['title']))
        else:
            print('File:\t{}'.format(item['title']))

    input('\nHit enter to continue ')

def ListStorage(dbs, password):
    # Fetch the contents of the storage database # #
    query = Globals.DB_CONTENTS(dbs[1])
    list_call = QueryHandler(dbs[1], query, password, fetchall=True)
    # If no data .. exit the function #
    if not list_call:
        PrintErr('\n* [ERROR] No contents in storage database to export *', 1)
        return

    print('\nStorage Database Contents\n' + ('-' * 15) + '\n')

    for row in list_call:
        print('File name:\t{:30s} Saved path:\t{:30s}'.format(row[0], row[1]))

    input('\nHit enter to continue ')

def ShareKey(db, password, send_email, email_pass, receivers, re_pass):
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
        PrintErr('\n* Database missing decrypt component .. exit'
                 ' and restart program to make new keys *', 2)
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
            PrintErr('\n* [ERROR] Invalid password format .. numbers,'
                     ' letters & _+$@&( special charaters allowed *', 2)
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
    user = re.search(r'[a-zA-Z0-9\_]+?(?=@)', send_email)
    key_path = f'{user.group(0)}_decrypt.txt'
    key_nonce_path = f'{user.group(0)}_key_nonce.txt'
    aesccm_path = f'{user.group(0)}_aesccm.txt'
    nonce_path = f'{user.group(0)}_nonce.txt'

    FileHandler(key_path, 'wb', password, operation='write', data=key_crypt)
    FileHandler(key_nonce_path, 'wb', password, operation='write', data=key_nonce)
    FileHandler(aesccm_path, 'wb', password, operation='write', data=key)
    FileHandler(nonce_path, 'wb', password, operation='write', data=nonce)

    # Group message data to be iterated over #
    body = ('Attached below is your encrypted decryption key .. download and move to import folder', \
            'Attached below is your unlock key with & nonce .. download and move to import folder', \
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
    [ os.remove(file) for file in (key_path, key_nonce_path, aesccm_path, nonce_path) ]

    os.chdir('.\\..')
    print('\n[SUCCESS] Keys and password successfully sent')

# Encrypt & upload to cloud storage #
def Upload(dbs, cmd, password, local_path, abs_path):
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

            if not re.search(r'^[a-zA-Z0-9\_\.]{1,30}', folder) or prompt2 not in ('y', 'n'):
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
            PrintErr('\n* Database missing upload key .. exit and restart'
                     ' program to make new keys *', 2)
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
        # If no data .. exit the function #
        if not extract_call:
            PrintErr('\n* [ERROR] No contents in storage database to upload *', 2)
            return

        # Compile regex for parsing out Documents from stored path #
        re_relPath = re.compile(r'(?<=\\)[a-zA-Z0-9\_\.\\]+')
        # Set local_path to UploadDock #
        local_path = '.\\UploadDock'

        print('\nExporting stored files from folder into Upload Dock:\n' + ('-' * 36) + '\n')

        for row in extract_call:
            # If regex is successful #
            if re.search(f'{folder}', row[1]):
                # Decode base64 contents #
                text = b64decode(row[2])

                # Use regex to strip out Documents from path #
                path_parse = re.search(re_relPath, row[1])
                # If regex fails avoid appending relative path in db #
                if not path_parse:
                    file_path = local_path + '\\' + row[0]
                else:
                    # Append relative path to user path to recursivly rebuild #
                    file_path = local_path + '\\' + path_parse.group(0) + '\\' + row[0]

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

    # Create reuseable http object, preventing reauthentication per call #
    http = drive.auth.Get_Http_Object()

    # Grab only the rightmost directory of path save result in other regex 
    # as anchor point for confirming rescursive directories while crawling #
    reg_pathEdge = re.search(r'[^\\]+$', local_path)
    # Insert path edge regex match into regex to match any path past the edge anchor point #

    # Match the first occurance
    reg_filePath = re.compile(r'(?<={0}\\).+$'.format(str(reg_pathEdge.group(0))))

    # Grab the rightmost directory of the current path for upload #
    reg_upPath = re.compile(r'[^\\]+$')

    # List of file extension types #
    ext = ( '.avi', '.doc', '.docm', '.docx', '.exe', '.gif', 
            '.jpg', '.jpeg', '.m4a', '.mp3', '.mp4', '.pdf', 
            '.png', '.pptx', '.rar', '.wav', '.wma', '.zip' )

    count = 0

    print('\nUploading files in path:\n' + ('-' * 25))

    # Iterate through folders/files recursively in upload source path,
    # encrypt data, then upload to destination path #
    for dirpath, dirnames, filenames in os.walk(local_path):
        print(f'\nUpload path: {dirpath}\n')

        # Search file path with regex to grab recursive paths #
        filePath_match = re.search(reg_filePath, dirpath)
        upPath_match = re.search(reg_upPath, dirpath)

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
        for dirname in dirnames:
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
                    create_path = Path(abs_path+'\\UploadDock\\'+filePath+'\\'+dirname)
                    # Create dirpath in UploadDock #
                    create_path.mkdir(parents=True, exist_ok=True)
                # Pass if dir already exists #
                except FileExistsError as err:
                    print('Error making parent dir: {err}')
                    pass

                # Create folder in UploadDock #
                FolderUpload(drive, upPath, dirname, http, count)
                count += 1

        print('\n')

        for file in filenames:
            print(f'File: {file}')

            # If the UploadDock is not being used  #
            if local_path != '.\\UploadDock':
                # Read file data #
                file_data = FileHandler((dirpath+'\\'+file), 'rb', password, operation='read')

                # If in plain text .. encrypt it #
                if prompt == 'plain':
                    crypt = encryptor.update(file_data)
                else:
                    crypt = file_data

                # Re-write data in upload dock retaining file structure #
                if not filePath:
                    FileHandler(('.\\UploadDock\\'+file), 'wb', password, operation='write', data=crypt)
                else:
                    FileHandler(('.\\UploadDock\\'+filePath+'\\'+file), 'wb', password, operation='write', data=crypt)

            # If file contains extension suggesting metadata #
            if file.endswith(ext):
                if not filePath:
                    # Strip metadata from file #
                    SystemCmd((abs_path+'\\UploadDock\\'+file), None, None, 2, exif=True)
                else:
                    # Strip metadata from file #
                    SystemCmd((abs_path+'\\UploadDock\\'+filePath+'\\'+file), None, None, 2, exif=True)

            # Upload file to Drive #
            if not filePath:
                FileUpload(drive, None, '.\\UploadDock', file, http, None)
            else:
                FileUpload(drive, upPath, '.\\UploadDock', file, http, filePath)

            # If the user wants to delete data after uploading #
            if prompt2 == 'y':
                os.remove(dirpath + '\\' + file)

    # Clear all data in UploadDock #
    rmtree('.\\UploadDock')
    os.mkdir('.\\UploadDock')

    if prompt2 == 'y':
        for dirpath, dirnames, _ in os.walk(local_path):
            [ os.rmdir(dirpath + '\\' + dirname) for dirname in dirnames ]

    print(f'\n[SUCCESS] Files from {local_path} have been uploaded')
    sleep(2)