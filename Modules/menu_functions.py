# pylint: disable=W0106
""" Built-in modules """
import os
import re
from base64 import b64encode, b64decode
from getpass import getuser
from shutil import rmtree
# External Modules #
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.exceptions import InvalidTag
from pydrive2 import auth
from pydrive2.drive import GoogleDrive
# Custom Modules #
import Modules.db_handlers as global_vars
from Modules.menu_utils import upload_dir_handler, decrypt_input, extract_input, extract_parse, \
                               import_input, meta_handler, share_input, store_input, \
                               upload_extract, upload_input, upload_stage
from Modules.utils import decrypt_db_data, cha_init, cha_decrypt, encrypt_db_data, \
                          fetch_upload_comps, file_handler, get_database_comp, meta_strip, \
                          msg_format, msg_send, print_err, query_handler, secure_delete


def db_extract(dbs: tuple, auth_obj: object, re_path, re_dir):
    """
    Extracts data from local storage database in encrypted or plain text.

    :param dbs:  The database name tuple.
    :param auth_obj:  The authentication instance.
    :param re_path:  Compiled regex to match input path.
    :param re_dir:  Compiled regex to match input directory to recursively extract from storage db.
    :return:  Prints successful operation or error message.
    """
    decryptor = None
    # Prompt user for needed inputs to perform extraction #
    folder, path, is_crypt, is_deleted = extract_input(re_dir, re_path)

    # Confirm the storage database has data to extract #
    query = global_vars.db_contents(dbs[1])
    extract_call = query_handler(dbs[1], query, auth_obj, operation='fetchall')

    # If no data, exit the function #
    if not extract_call:
        return print_err('No contents in storage database to export', 2)

    # If data is to be extracted in plain text #
    if is_crypt == 'plain':
        # Retrieve nonce from Keys db, then decode and decrypt #
        key, nonce = cha_decrypt(auth_obj, dbs[0])
        # Initialize the ChaCha20 algo object #
        algo = cha_init(key, nonce)
        # Set the algo object as decryptor #
        decryptor = algo.decryptor()

    # Compile regex based on folder passed in #
    re_folder = re.compile(f'{re.escape(folder)}')
    # Compile regex for parsing out Documents from stored path #
    re_rel_winpath = re.compile(r'(?<=\\)[a-zA-Z\d_.\\\-\'\"]{1,240}')
    re_rel_linpath = re.compile(r'(?<=/)[a-zA-Z\d_./\-\'\"]{1,240}')

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
            if is_crypt == 'plain':
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
                # Validate and format extraction file path #
                file_path = extract_parse(re_rel_winpath, re_rel_linpath, row, path)

                # Confirm all directories in file path exist #
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                # Write data to path specified by user input #
                file_handler(file_path, 'wb', auth_obj, operation='write', data=text)

            print(f'File: {row[0]}')

            if is_deleted == 'y':
                # Delete item from storage database #
                query = global_vars.db_delete(dbs[1], row[0])
                query_handler(dbs[1], query, auth_obj)

    return print(f'\n\n[SUCCESS] Files from {folder} have been extracted')


def db_store(dbs: tuple, auth_obj: object, re_path):
    """
    Encrypts and inserts data into storage database.

    :param dbs: The database name tuple.
    :param auth_obj:  The authentication instance.
    :param re_path:  Compiled regex to match input path.
    :return:  Nothing
    """
    encryptor = None

    # Prompt user for needed inputs to perform extraction #
    path, is_crypt, is_deleted = store_input(re_path)

    # If the data to be stored is in plain text #
    if is_crypt == 'plain':
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
                rel_path = re.search(r'Documents\\[a-zA-Z\d._\\\-\'\"]{1,240}$', dir_path)
                curr_file = f'{dir_path}\\{file}'
            # If OS is Linux #
            else:
                rel_path = re.search(r'Documents/[a-zA-Z\d._/\-\'\"]{1,240}$', dir_path)
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
            if is_crypt == 'plain':
                # Encrypt the plain text data #
                crypt = encryptor.update(file_data)
                # Encrypted data is base64 encoded for storage #
                data = b64encode(crypt).decode()
            else:
                # Cipher data is base64 encoded for storage #
                data = b64encode(file_data).decode()

            # If the relative path regex matches #
            if rel_path:
                relative_path = rel_path.group(0)
            else:
                relative_path = None

            # Path is stored like "Documents\path\to\folder", file is stored as the name #
            query = global_vars.db_store(dbs[1], file, relative_path, data)
            query_handler(dbs[1], query, auth_obj)

            print(f'File: {file}')

            # If user wants to delete stored files #
            if is_deleted == 'y':
                # Delete (unlink) from file system after storage #
                secure_delete(curr_file)

    if is_deleted == 'y':
        # Recursively delete leftover empty folders
        for dir_path, dir_names, _ in os.walk(path):
            [rmtree(f'{dir_path}\\{folder}') if os.name == 'nt'
             else rmtree(f'{dir_path}/{folder}') for folder in dir_names]

    print(f'\n\n[SUCCESS] Files from {path} have been encrypted & inserted into storage database')


def decryption(db_name: str, auth_obj: object, re_user, re_path):
    """
    Decrypts data located on the file system.

    :param db_name:  The key's database name syntax.
    :param auth_obj:  The authentication instance.
    :param re_user:  Compiled regex to match input username.
    :param re_path:  Compiled regex to match input path.
    :return:  Prints successful operation or error message.
    """
    # Prompt user for needed inputs to perform decryption #
    user, local_path = decrypt_input(re_user, re_path)

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
    decrypt_call, nonce_call = fetch_upload_comps(db_name, user_key, user_nonce, auth_obj)

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
        file_obj.Upload(param={'http': http})
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
                file_obj.Upload(param={'http': http})
                break


def folder_upload(drive: object, parent_dir, dir_list: list, http: object, parent_id: str):
    """
    Recursively uploads folders to Drive.

    :param drive:  Google Drive authenticated instance.
    :param parent_dir:  Parent directory name.
    :param dir_list:  List of subdirectories to be created.
    :param http:  Http session instance.
    :param parent_id:  The current id of parent folder
    :return:  The update id of parent folder.
    """
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
                folder.Upload(param={'http': http})

                print(f'Directory: {directory}')
            else:
                # Get list of folders based on parent id #
                folder_list = drive.ListFile({'q': f'\"{parent_id}\" in parents and trashed=false'}
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
                        parent.Upload(param={'http': http})

                        print(f'Directory: {directory}')

                        # Update parent id for next iteration #
                        add_id = parent['parents'][0]['id']

                        break

        if not parent_id:
            # Set root as parent folder for next iteration #
            return 'root'

        # Set added sub-folder id #
        return add_id

    return None


def import_key(db_names: str, auth_obj: object, re_user, re_pass):
    """
    Import user's key to the encrypted local key database.

    :param db_names:  Database name tuple.
    :param auth_obj:  The authentication instance.
    :param re_user:  Compiled regex to match input username.
    :param re_pass:  Compiled regex to match input user password.
    :return:  Prints successful operation or error message.
    """
    # Prompt user for needed inputs to perform key import #
    user, user_pass = import_input(re_user, re_pass)

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
    :return:  Waits for user input to exit or prints error message.
    """
    # Fetch the contents of the storage database # #
    query = global_vars.db_contents(db_name)
    list_call = query_handler(db_name, query, auth_obj, operation='fetchall')

    # If no data, exit the function #
    if not list_call:
        return print_err('No contents in storage database to export', 1)

    print(f'\nStorage Database Contents\n{(26 * "*")}\n')
    # Print the results of the retrieved database #
    [print(f'File name:  {row[0]:30s}  Saved path:  {row[1]:30s}') for row in list_call]

    return input('\nHit enter to continue ')


def key_share(db_name: str, auth_obj: object, re_email, re_pass, re_phone):
    """
    Share decryption key protected by a password through authentication-based encryption.

    :param db_name:  Keys database name.
    :param auth_obj:  The authentication instance.
    :param re_email:  Compiled regex for email address matching.
    :param re_pass:  Compiled regex for password matching.
    :param re_phone:  Compiled regex for phone number matching.
    :return:  Nothing
    """
    # If OS is Windows #
    if os.name == 'nt':
        app_secret = f'{global_vars.CWD}\\AppSecret.txt'
    # If OS is Linux #
    else:
        app_secret = f'{global_vars.CWD}/AppSecret.txt'

    # If AppSecret for Gmail login is missing #
    if not global_vars.file_check(app_secret):
        return print_err('Missing application password (AppSecret.txt) to login Gmail API, '
                         'generate password on Google account and save in AppSecret.txt in'
                         ' main dir', 2)

    # Load app password from file #
    email_pass = file_handler(app_secret, 'r', auth_obj, 'read')
    # Prompt user for needed inputs to perform key sharing #
    send_email, recv_email, recv_email2, \
    recv_phone, provider, key_pass = share_input(re_email, re_phone, re_pass)

    receivers = (recv_email, recv_email2, f'{recv_phone}@{provider}')

    # Retrieve and decrypt ChaCha20 components #
    share_key, share_nonce = cha_decrypt(auth_obj, db_name)

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

    return print('\n\n[SUCCESS] Keys and password successfully sent')


def upload(dbs: tuple, auth_obj: object, re_path):
    """
    Manages encrypted recursive upload to Google Drive.

    :param dbs:  Database name tuple.
    :param auth_obj:  The authentication instance.
    :param re_path:  Compiled regex to match input path.
    :return:  Prints successful operation or error message.
    """
    encryptor = None
    # Prompt user for needed inputs to perform cloud drive upload #
    local_path, prompt, prompt2, folder, prompt3 = upload_input(re_path)

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
        # Extract contents from storage database for upload #
        upload_extract(dbs, auth_obj, folder, prompt3)

    # Authenticate drive #
    gauth = auth.GoogleAuth()
    gauth.LocalWebserverAuth()
    drive = GoogleDrive(gauth)

    # Create reusable http object, preventing re-authentication per call #
    http = drive.auth.Get_Http_Object()

    # If OS is Windows #
    if os.name == 'nt':
        # Grab the rightmost directory of the current path for upload #
        re_upload_path = re.compile(r'[^\\]{1,60}$')
    # If OS is Linux #:
    else:
        # Grab the rightmost directory of the current path for upload #
        re_upload_path = re.compile(r'[^/]{1,60}$')

    # Grab only the rightmost directory of path save result in other regex
    # as anchor point for confirming recursive directories while crawling #
    re_path_edge = re.search(re_upload_path, local_path)

    # If OS is Windows #
    if os.name == 'nt':
        # Insert path edge regex match into regex to match any path past the edge anchor point #
        re_file_path = re.compile(rf'(?<={re.escape(str(re_path_edge.group(0)))}\\).+$')
    # If OS is Linux #
    else:
        # Insert path edge regex match into regex to match any path past the edge anchor point #
        re_file_path = re.compile(rf'(?<={re.escape(str(re_path_edge.group(0)))}/).+$')

    # List of file extension types #
    ext = ('.avi', '.doc', '.docm', '.docx', '.exe', '.gif',
           '.jpg', '.jpeg', '.m4a', '.mp3', '.mp4', '.pdf',
           '.png', '.pptx', '.rar', '.wav', '.wma', '.zip')
    parent_id = ''

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
        # If in the base directory #
        else:
            upload_path = None

        # If match for local files #
        if file_path_match:
            file_path = str(file_path_match.group(0))
        # If in the base directory #
        else:
            file_path = None

        # If there are folders to be uploaded #
        if folder_names:
            # Iterate through folders to upload #
            for dirname in folder_names:
                # Ensure all the directory's exist #
                upload_dir_handler(file_path, dirname)

            # If match for local files #
            if not file_path:
                # Create folder in drive #
                parent_id = folder_upload(drive, None, folder_names, http, parent_id)
            else:
                # Create folder in UploadDock #
                parent_id = folder_upload(drive, upload_path, folder_names, http, parent_id)

        # If there are files to be uploaded in current path #
        if file_names:
            # Iterate through files to upload #
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

                    # Copy write encrypted data to fresh file in UploadDock #
                    upload_stage(file_path, file, auth_obj, crypt)

                # If file contains extension suggesting metadata #
                if file.endswith(ext):
                    # Format path and scrub metadata #
                    strip = meta_handler(file_path, folder_path, file)
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

    return print(f'\n\n[SUCCESS] Files from {local_path} have been uploaded')
