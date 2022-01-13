# Built-in Modules #
from base64 import b64encode, b64decode
from time import sleep
import os, re

# Third-party Modules #
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidTag
from pydrive2 import auth
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive

# Custom Modules #
import Modules.Globals as Globals
from Modules.Utils import FileHandler, MsgFormat, MsgSend, PrintErr, QueryHandler, SystemCmd

# # Function Index #
# -------------------
# - Decryption:     decrypts data in decrypt doc to storage database or specified path
# - FileUpload:     uploads file in upload dock or specified path to Google Drive
# - FolderUpload:   uploads folder in upload dock or specified path to Google Drive
# - ImportKey:     imports remote user decryption contents to decrypt shared data
# - ListDrive:     lists root directory of users Google Drive
# - ShareKey:      shares decrypt components with other user protected via tempory password
# - Upload:         Google Drive upload function

def Decryption(db, cmd, user, password): 
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
    query = Globals.db_retrieve(db, user_key)
    decrypt_call = QueryHandler(db, query, password, fetchone=True)

    # Retrieve nonce from database #
    query = Globals.db_retrieve(db, user_nonce)
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

    # Iterate through folders/files recurisivly in DecryptDock, decrypt data #
    for dirpath, dirnames, filenames in os.walk('.\\DecryptDock'):
        SystemCmd(cmd, None, None, 2)
        print(f'Decrypt path: {dirpath}\n')

        for file in filenames:
            print(f'Decrypting file: {file}')
            file_data = FileHandler((dirpath + '\\' + file), 'rb', password, operation='read')
            plain = decryptor.update(file_data)
            os.remove(dirpath + '\\' + file)
            FileHandler((dirpath + '\\'+ file), 'wb', password, operation='write', data=plain)

    print('\n[SUCCESS] Data has been decrypted')

def FileUpload(drive, up_path, dir_path, file, http):
    # Create file object for upload #
    if up_path == None:
        file_obj = drive.CreateFile({'title': file})
        file_obj.SetContentFile(dir_path + '\\' + file)
        # Upload & pass http object into upload call #
        file_obj.Upload(param={'http': http})
    else:
        # Get List of folders in upload path #
        folders = drive.ListFile({'q': 'title=\'' + up_path + '\' and ' \
                        'mimeType=\'application/vnd.google-apps.folder\' and trashed=false'}).GetList()
        for folder in folders:
            # If file is in folder .. create it #
            if folder['title'] == up_path:  
                file_obj = drive.CreateFile({'parents': [{'id': folder['id']}], 'title': file})          
                file_obj.SetContentFile(dir_path + '\\' + file)
                # Upload & pass http object into upload call #
                file_obj.Upload(param={'http': http})       

def FolderUpload(drive, up_path, dirname, http):
    if up_path == None:
        # Create folder object & upload #
        folder = drive.CreateFile({'title': dirname, 'mimeType': 'application/vnd.google-apps.folder'})
        # Upload & pass http object into upload call #
        folder.Upload(param={'http': http})
    else:
        folder = drive.CreateFile({'title': dirname, 'parents': [{'kind': 'drive#fileLink', 'id': up_path}], \
                                   'mimeType': 'application/vnd.google-apps.folder'})
        folder.Upload(param={'http': http})

def ImportKey(db, password, user, user_pass):
    key_path = f'.\\Import\\{user}_decrypt.txt'
    key_nonce_path = f'.\\Import\\{user}_key_nonce.txt'
    aesccm_path = f'.\\Import\\{user}_aesccm.txt'
    nonce_path = f'.\\Import\\{user}_nonce.txt'

    # Confirm all critical files to operation are present #
    if Globals.file_check(key_path) == False or Globals.file_check(key_nonce_path) == False \
    or Globals.file_check(aesccm_path) == False or Globals.file_check(nonce_path) == False:
        PrintErr('* [ERROR] A component needed for importing key is missing *\n'
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
        PrintErr('* [ERROR] Incorrect unlock password entered *', 2)
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
    query = Globals.db_insert(db, f'{user}_decrypt', upload_key.decode())
    QueryHandler(db, query, password)

    # Send users nonce to database #
    query = Globals.db_insert(db, f'{user}_nonce', upload_nonce.decode())
    QueryHandler(db, query, password)

    # Delete file in Import dir #
    [ os.remove(file) for file in (key_path, key_nonce_path, aesccm_path, nonce_path) ]

    print('\n[SUCCESS] {}\'s public key has been imported .. now in Keys directory & databases'.format(user))

def ListDrive():
    # Authenticate drive #
    gauth = auth.GoogleAuth()
    gauth.LocalWebserverAuth()
    drive = GoogleDrive(gauth)

    # Retrieve contents of root Google Drive directory as list #
    drive_list = drive.ListFile({'q': '\'root\' in parents and trashed=false'}).GetList()

    print('\nDrive Contents\n--------------\n')
    # Iterate through retrieved list and print #
    for item in drive_list:
        if item['mimeType'] == 'application/vnd.google-apps.folder':
            print('Folder: {}'.format(item['title']))
        else:
            print('File: {}'.format(item['title']))

    sleep(2.5)

def ShareKey(db, password, send_email, email_pass, receivers, re_pass):
    # Load AESCCM decrypt components #
    key = FileHandler('.\\Keys\\aesccm.txt', 'rb', password, operation='read')
    nonce = FileHandler('.\\Keys\\nonce.txt', 'rb', password, operation='read')

    # Unlock the local database key #
    aesccm = AESCCM(key)
    crypt = FileHandler('.\\Keys\\db_crypt.txt', 'rb', password, operation='read')
    db_key = aesccm.decrypt(nonce, crypt, password)

    # Retrieve decrypt key from database #
    query = Globals.db_retrieve(db, 'upload_key')
    decrypt_call = QueryHandler(db, query, password, fetchone=True)

    # Retrieve nonce from database #
    query = Globals.db_retrieve(db, 'upload_nonce')
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
        if re.search(re_pass, key_pass) == False:
            PrintErr('\n* [ERROR] Invalid password format .. numbers, letters & _+$@&( special charaters allowed *', 2)
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
def Upload(db, cmd, password, local_path):
    # Load AESCCM decrypt components #
    key = FileHandler('.\\Keys\\aesccm.txt', 'rb', password, operation='read')
    nonce = FileHandler('.\\Keys\\nonce.txt', 'rb', password, operation='read')
    aesccm = AESCCM(key)

    # Unlock the local database key #
    crypt = FileHandler('.\\Keys\\db_crypt.txt', 'rb', password, operation='read')
    db_key = aesccm.decrypt(nonce, crypt, password)

    # Retrieve upload key from database #
    query = Globals.db_retrieve(db, 'upload_key')
    upload_call = QueryHandler(db, query, password, fetchone=True)

    # Retrieve nonce from database #
    query = Globals.db_retrieve(db, 'upload_nonce')
    nonce_call = QueryHandler(db, query, password, fetchone=True)

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

    # Authenticate drive #
    gauth = auth.GoogleAuth()
    gauth.LocalWebserverAuth()
    drive = GoogleDrive(gauth)

    # Create reuseable http object, preventing reauthentication per call #
    http = drive.auth.Get_Http_Object()

    # Grab only the rightmost directory of path save result in other regex 
    # as anchor point for confirming rescursive directories while crawling #
    reg_pathEdge = re.search(r'[a-zA-Z0-9_\"\' \.\,\-]+$', local_path)
    reg_extPath = re.compile(fr'(?<={str(reg_pathEdge.group(0))}\\).+')

    # Iterate through folders/files recursively in upload source path, 
    # encrypt data, then upload to destination path #
    for dirpath, dirnames, filenames in os.walk(local_path):
        SystemCmd(cmd, None, None, 2)
        
        print(f'\nUpload path: {dirpath}\n')
        extPath = re.search(reg_extPath, dirpath)

        # Upload folder to Drive #
        for dirname in dirnames:
            print(f'Directory name: {dirname}')
            if extPath ==   None:
                FolderUpload(drive, None, dirname, http)
            else:
                FolderUpload(drive, str(extPath.group(0)), dirname, http)

        print('\n')

        for file in filenames:
            print(f'File: {file}')
            # Read data, encrypt, & write to UploadDock #
            file_data = FileHandler((dirpath + '\\' + file), 'rb', password, operation='read')
            crypt = encryptor.update(file_data)
            FileHandler(('.\\UploadDock\\'+ file), 'wb', password, operation='write', data=crypt)

            # Upload file to Drive #
            if extPath ==  None:
                FileUpload(drive, None, '.\\UploadDock', file, http)
            else:
                FileUpload(drive, str(extPath.group(0)), '.\\UploadDock', file, http)

            os.remove('.\\UploadDock\\' + file)

    print(f'\n[SUCCESS] Files from {local_path} have been uploaded')