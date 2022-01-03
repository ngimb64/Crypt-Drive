from Modules.Utils import file_handler, msg_format, msg_send, print_err, query_handler, system_cmd
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidTag
from base64 import b64decode
from time import sleep
from pydrive2 import auth
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
import os, re
import Modules.Globals as Globals

# # Function Index #
# -------------------
# - decryption:     decrypts data in decrypt doc to storage database or specified path
# - file_upload:    uploads file in upload dock or specified path to Google Drive
# - folder_upload:  uploads folder in upload dock or specified path to Google Drive
# - import_key:     imports remote user decryption contents to decrypt shared data
# - list_drive:     lists root directory of users Google Drive
# - share_key:      shares decrypt components with other user protected via tempory password
# - upload:         Google Drive upload function

def decryption(db, cmd, user, password): 
    # If local user is specified #
    if user == '':
        user_key = 'upload_key'
        user_nonce = 'upload_nonce'
    else:
        user_key = f'{user}_decrypt'
        user_nonce = f'{user}_nonce'

    # Load AESCCM decrypt components #
    key = file_handler('.\\Keys\\aesccm.txt', 'rb', password, operation='read')
    nonce = file_handler('.\\Keys\\nonce.txt', 'rb', password, operation='read')
    aesccm = AESCCM(key)

    # Unlock the local database key #
    crypt = file_handler('.\\Keys\\db_crypt.txt', 'rb', password, operation='read')
    db_key = aesccm.decrypt(nonce, crypt, password)

    # Decrypt the key database #
    db_crypt = file_handler('.\\Dbs\\keys.db', 'rb', password, operation='read')
    plain = Fernet(db_key).decrypt(db_crypt)
    file_handler('.\\Dbs\\keys.db', 'wb', password, operation='write', data=plain)

    # Retrieve decrypt key from database #
    query = Globals.db_retrieve(db, user_key)
    decrypt_call = query_handler(db, query, password, fetchone=True)
    # If decrypt key doesn't exist in db #
    if decrypt_call == None:
        print_err('\n* Database missing decrypt key .. exit and restart program to make new keys *', 2)
        return

    # Retrieve nonce from database #
    query = Globals.db_retrieve(db, user_nonce)
    nonce_call = query_handler(db, query, password, fetchone=True)
    # If upload key doesn't exist in db #
    if nonce_call == None:
        print_err('\n* Database missing nonce .. exit and restart program to make new keys *', 2)
        return

    # Decode retrieved key & nonce from base64 format #
    decrypt_key, decrypt_nonce = b64decode(decrypt_call[1]), b64decode(nonce_call[1])

    # Re-encrypt the key database #
    plain = file_handler('.\\Dbs\\keys.db', 'rb', password, operation='read')
    db_crypt = Fernet(db_key).encrypt(plain)
    file_handler('.\\Dbs\\keys.db', 'wb', password, operation='write', data=db_crypt)

    # Initialize ChaCha20 encryption algo #
    algo = algorithms.ChaCha20(decrypt_key, decrypt_nonce)
    cipher = Cipher(algo, mode=None)
    decryptor = cipher.decryptor()

    # Iterate through folders/files recurisivly in DecryptDock, decrypt data #
    for dirpath, dirnames, filenames in os.walk('.\\DecryptDock'):
        system_cmd(cmd, None, None, 2)
        print(f'Decrypt path: {dirpath}\n')
        for file in filenames:
            print(f'Decrypting file: {file}')
            file_data = file_handler((dirpath + '\\' + file), 'rb', password, operation='read')
            plain = decryptor.update(file_data)
            os.remove(dirpath + '\\' + file)
            file_handler((dirpath + '\\'+ file), 'wb', password, operation='write', data=plain)

    print('\n[SUCCESS] Data has been decrypted')

def file_upload(drive, up_path, dir_path, file, http):
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

def folder_upload(drive, up_path, dirname, http):
    if up_path == None:
        # Create folder object & upload #
        folder = drive.CreateFile({'title': dirname, 'mimeType': 'application/vnd.google-apps.folder'})
        # Upload & pass http object into upload call #
        folder.Upload(param={'http': http})
    else:
        folder = drive.CreateFile({'title': dirname, 'parents': [{'kind': 'drive#fileLink', 'id': up_path}], \
                                   'mimeType': 'application/vnd.google-apps.folder'})
        folder.Upload(param={'http': http})

def import_key(db, password, user, user_pass):
    key_path = f'.\\Import\\{user}_decrypt.txt'
    key_nonce_path = f'.\\Import\\{user}_key_nonce.txt'
    aesccm_path = f'.\\Import\\{user}_aesccm.txt'
    nonce_path = f'.\\Import\\{user}_nonce.txt'

    # Confirm all critical files to operation are present #
    if Globals.file_check(key_path) == False or Globals.file_check(key_nonce_path) == False \
    or Globals.file_check(aesccm_path) == False or Globals.file_check(nonce_path) == False:
        print_err('* [ERROR] A component needed for importing key is missing *\n'
                  'To import a key 4 files are required in the Import directory:\n'
                  '[user]_decrypt.txt, [user]_key_nonce.txt, [user]_aesccm.txt, [user]_nonce.txt', 2.5)
        return

    # Load user AESCCM decrypt components #
    key = file_handler(aesccm_path, 'rb', password, operation='read')
    nonce = file_handler(nonce_path, 'rb', password, operation='read')
    aesccm = AESCCM(key)

    # Unlock users decrypt & nonce key #
    crypt = file_handler(key_path, 'rb', password, operation='read')
    try:
        user_key = aesccm.decrypt(nonce, crypt, user_pass.encode())
    except InvalidTag:
        print_err('* [ERROR] Incorrect unlock password entered *', 2)
        return

    crypt = file_handler(key_nonce_path, 'rb', password, operation='read')
    key_nonce = aesccm.decrypt(nonce, crypt, user_pass.encode())

    # Load local AESCCM decrypt components #
    key = file_handler('.\\Keys\\aesccm.txt', 'rb', password, operation='read')
    nonce = file_handler('.\\Keys\\nonce.txt', 'rb', password, operation='read')
    aesccm = AESCCM(key)

    # Unlock the local database key #
    crypt = file_handler('.\\Keys\\db_crypt.txt', 'rb', password, operation='read')
    db_key = aesccm.decrypt(nonce, crypt, password)

    # Decrypt the key database #
    db_crypt = file_handler('.\\Dbs\\keys.db', 'rb', password, operation='read')
    plain = Fernet(db_key).decrypt(db_crypt)
    file_handler('.\\Dbs\\keys.db', 'wb', password, operation='write', data=plain)

    # Send users decrypt key to key database #
    query = Globals.db_insert(db, f'{user}_decrypt', user_key.decode())
    query_handler(db, query, password)

    # Send users nonce to database #
    query = Globals.db_insert(db, f'{user}_nonce', key_nonce.decode())
    query_handler(db, query, password)

    # Re-encrypt the key database #
    plain = file_handler('.\\Dbs\\keys.db', 'rb', password, operation='read')
    db_crypt = Fernet(db_key).encrypt(plain)
    file_handler('.\\Dbs\\keys.db', 'wb', password, operation='write', data=db_crypt)

    # Delete file in Import dir #
    [ os.remove(file) for file in (key_path, key_nonce_path, aesccm_path, nonce_path) ]

    print('\n[SUCCESS] {}\'s public key has been imported .. now in Keys directory & databases'.format(user))

def list_drive():
    # Authenticate drive #
    gauth = auth.GoogleAuth()
    gauth.LocalWebserverAuth()
    drive = GoogleDrive(gauth)

    print('\nDrive Contents\n--------------\n')

    # Iterate through retrieved list and print #
    drive_list = drive.ListFile({'q': '\'root\' in parents and trashed=false'}).GetList()
    for item in drive_list:
        if item['mimeType'] == 'application/vnd.google-apps.folder':
            print('Folder: {}'.format(item['title']))
        else:
            print('File: {}'.format(item['title']))

    sleep(2.5)

def share_key(db, password, send_email, email_pass, receivers, re_pass):
    # Load AESCCM decrypt components #
    key = file_handler('.\\Keys\\aesccm.txt', 'rb', password, operation='read')
    nonce = file_handler('.\\Keys\\nonce.txt', 'rb', password, operation='read')

    # Unlock the local database key #
    aesccm = AESCCM(key)
    crypt = file_handler('.\\Keys\\db_crypt.txt', 'rb', password, operation='read')
    db_key = aesccm.decrypt(nonce, crypt, password)

    # Decrypt the key database #
    db_crypt = file_handler('.\\Dbs\\keys.db', 'rb', password, operation='read')
    plain = Fernet(db_key).decrypt(db_crypt)
    file_handler('.\\Dbs\\keys.db', 'wb', password, operation='write', data=plain)

    # Retrieve decrypt key from database #
    query = Globals.db_retrieve(db, 'upload_key')
    decrypt_call = query_handler(db, query, password, fetchone=True)
    # If upload key doesn't exist in db #
    if decrypt_call == None:
        print_err('\n* Database missing decrypt key .. exit and restart program to make new keys *', 2)
        return

    # Retrieve nonce from database #
    query = Globals.db_retrieve(db, 'upload_nonce')
    nonce_call = query_handler(db, query, password, fetchone=True)
    # If upload key doesn't exist in db #
    if nonce_call == None:
        print_err('\n* Database missing nonce .. exit and restart program to make new keys *', 2)
        return

    # Re-encrypt the key database #
    plain = file_handler('.\\Dbs\\keys.db', 'rb', password, operation='read')
    db_crypt = Fernet(db_key).encrypt(plain)
    file_handler('.\\Dbs\\keys.db', 'wb', password, operation='write', data=db_crypt)

    # Prompt user for password to protect key on transit #
    while True:
        key_pass = input('Enter password to encrypt key for email transmission: ')
        if re.search(re_pass, key_pass) == False:
            print_err('\n* [ERROR] Invalid password format .. numbers, letters & _+$@&( special charaters allowed *', 2)
            continue

        print('\n')
        break

    # Create AESCCM password authenticated key #
    key = AESCCM.generate_key(bit_length=256)
    aesccm = AESCCM(key)
    nonce = os.urandom(13)
    key_crypt = aesccm.encrypt(nonce, decrypt_call[1].encode(), key_pass.encode())
    key_nonce = aesccm.encrypt(nonce, nonce_call[1].encode(), key_pass.encode())

    os.chdir('.\\Keys')

    # Grab username from email with regex & format it to file names #
    user = re.search(r'[a-zA-Z0-9_]+?(?=@)', send_email)
    key_path = f'{user.group(0)}_decrypt.txt'
    key_nonce_path = f'{user.group(0)}_key_nonce.txt'
    aesccm_path = f'{user.group(0)}_aesccm.txt'
    nonce_path = f'{user.group(0)}_nonce.txt'

    file_handler(key_path, 'wb', password, operation='write', data=key_crypt)
    file_handler(key_nonce_path, 'wb', password, operation='write', data=key_nonce)
    file_handler(aesccm_path, 'wb', password, operation='write', data=key)
    file_handler(nonce_path, 'wb', password, operation='write', data=nonce)

    # Group message data to be iterated over #
    body = ('Attached below is your encrypted decryption key .. download and move to import folder', \
            'Attached below is your unlock key with & nonce .. download and move to import folder', \
            f'Your unlock password is => {key_pass}')

    # Group message data to be iterated over #
    files = ((key_path, nonce_path), (aesccm_path, key_nonce_path), (None, None))

    count = 0 
    for receiver in receivers:
        msg = msg_format(send_email, receiver, body[count], files[count])
        msg_send(send_email, receiver, email_pass, msg)        
        count += 1

    [ os.remove(file) for file in (key_path, key_nonce_path, aesccm_path, nonce_path) ]

    os.chdir('.\\..')
    print('\n[SUCCESS] Keys and password successfully sent')

# Encrypt & upload to cloud storage #
def upload(db, cmd, password, local_path):
    # Load AESCCM decrypt components #
    key = file_handler('.\\Keys\\aesccm.txt', 'rb', password, operation='read')
    nonce = file_handler('.\\Keys\\nonce.txt', 'rb', password, operation='read')
    aesccm = AESCCM(key)

    # Unlock the local database key #
    crypt = file_handler('.\\Keys\\db_crypt.txt', 'rb', password, operation='read')
    db_key = aesccm.decrypt(nonce, crypt, password)

    # Decrypt the key database #
    db_crypt = file_handler('.\\Dbs\\keys.db', 'rb', password, operation='read')
    plain = Fernet(db_key).decrypt(db_crypt)
    file_handler('.\\Dbs\\keys.db', 'wb', password, operation='write', data=plain)

    # Retrieve upload key from database #
    query = Globals.db_retrieve(db, 'upload_key')
    upload_call = query_handler(db, query, password, fetchone=True)
    # If upload key doesn't exist in db #
    if upload_call == None:
        print_err('\n* Database missing upload key .. exit and restart program to make new keys *', 2)
        return

    # Retrieve nonce from database #
    query = Globals.db_retrieve(db, 'upload_nonce')
    nonce_call = query_handler(db, query, password, fetchone=True)
    # If upload key doesn't exist in db #
    if nonce_call == None:
        print_err('\n* Database missing upload nonce .. exit and restart program to make new keys *', 2)
        return

    # Decode retrieved key & nonce from base64 format #
    upload_key, upload_nonce = b64decode(upload_call[1]), b64decode(nonce_call[1])

    # Re-encrypt the key database #
    plain = file_handler('.\\Dbs\\keys.db', 'rb', password, operation='read')
    crypt = Fernet(db_key).encrypt(plain)
    file_handler('.\\Dbs\\keys.db', 'wb', password, operation='write', data=crypt)

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
    reg_pathEdge = re.search(r'[a-zA-Z0-9_\"\' \.,\-]+$', local_path)
    reg_extPath = re.compile(fr'(?<={str(reg_pathEdge.group(0))}\\).+')

    # Iterate through folders/files recursively in upload source path, 
    # encrypt data, then upload to destination path #
    for dirpath, dirnames, filenames in os.walk(local_path):
        system_cmd(cmd, None, None, 2)
        print(f'\nUpload path: {dirpath}\n')
        extPath = re.search(reg_extPath, dirpath)
        for dirname in dirnames:
            print(f'Directory name: {dirname}')
            if extPath == None:
                folder_upload(drive, None, dirname, http)
            else:
                folder_upload(drive, str(extPath.group(0)), dirname, http)

        print('\n')

        for file in filenames:
            print(f'File: {file}')
            # Read data, encrypt, & write to UploadDock #
            file_data = file_handler((dirpath + '\\' + file), 'rb', password, operation='read')
            crypt = encryptor.update(file_data)
            file_handler(('.\\UploadDock\\'+ file), 'wb', password, operation='write', data=crypt)

            if extPath ==  None:
                file_upload(drive, None, '.\\UploadDock', file, http)
            else:
                file_upload(drive, str(extPath.group(0)), '.\\UploadDock', file, http)

            os.remove('.\\UploadDock\\' + file)

    print(f'\n[SUCCESS] Files from {local_path} have been uploaded')