# Built-in modules #
import os
from io import StringIO

# Global variables #
global CWD, LOG_STREAM, FILES, DBS, DIRS, HAS_KEYS, MISSING


"""
########################################################################################################################
Name:       Initialize
Purpose:    Initializes variables for global access.
Parameters: The base path of the initially executed script.
Returns:    None
########################################################################################################################
"""
def Initialize(path: str):
    # Global variables #
    global CWD, LOG_STREAM, FILES, DBS, DIRS, HAS_KEYS, MISSING

    # Absolute path to program #
    CWD = path
    # Create string IO object for logging #
    LOG_STREAM = StringIO()

    FILES = (f'{path}\\CryptKeys\\aesccm.txt', f'{path}\\CryptKeys\\nonce.txt',
             f'{path}\\CryptKeys\\db_crypt.txt', f'{path}\\CryptKeys\\secret_key.txt')
    DBS = (f'{path}\\CryptDbs\\crypt_keys.db', f'{path}\\CryptDbs\\crypt_storage.db')
    DIRS = (f'{path}\\CryptDbs', f'{path}\\CryptImport', f'{path}\\CryptKeys',
            f'{path}\\DecryptDock', f'{path}\\UploadDock')

    # Check if text files exist #
    key_check = FILE_CHECK(FILES[0])
    nonce_check = FILE_CHECK(FILES[1])
    dbkey_check = FILE_CHECK(FILES[2])
    secretkey_check = FILE_CHECK(FILES[3])

    # Check if database files exist #
    db_check = FILE_CHECK(DBS[0])
    storage_check = FILE_CHECK(DBS[1])

    # Check if directories exist #
    db_dir_check = DIR_CHECK(DIRS[0])
    decrypt_dir_check = DIR_CHECK(DIRS[1])
    import_dir_check = DIR_CHECK(DIRS[2])
    keys_dir_check = DIR_CHECK(DIRS[3])
    upload_dir_check = DIR_CHECK(DIRS[4])

    MISSING = []

    count = 0
    # If directories are missing, add them to the missing list #
    for item in (db_dir_check, decrypt_dir_check, import_dir_check, keys_dir_check, upload_dir_check):
        if not item:
            MISSING.append(DIRS[count])
            count += 1

    count = 0
    # If DBs are missing, add them to missing list #
    for item in (db_check, storage_check):
        if not item:
            MISSING.append(DBS[count])
            count += 1

    count = 0
    # If text files are missing, add them to the missing list #
    for item in (key_check, nonce_check, dbkey_check, secretkey_check):
        if not item:
            MISSING.append(FILES[count])
            count += 1

    # If any components are missing #
    if MISSING:
        HAS_KEYS = False
        return

    HAS_KEYS = True


""" File/Dir handlers """

# Check if directory exists #
def DIR_CHECK(path: str) -> bool:
    return os.path.isdir(path)

# Check if file exists #
def FILE_CHECK(path: str) -> bool:
    return os.path.isfile(path)


""" MySQL database queries """

# Create keys database #
def DB_KEYS(db: str) -> str:
    return f'CREATE TABLE {db}(name VARCHAR(20) PRIMARY KEY NOT NULL, data TINYTEXT NOT NULL);'

# Create storage database #
def DB_STORAGE(db: str) -> str:
    return f'CREATE TABLE {db}(name VARCHAR(20) PRIMARY KEY NOT NULL, path TINYTEXT NOT NULL, data LONGTEXT NOT NULL);'

# Insert item into keys database #
def DB_INSERT(db: str, name_val: str, data_val: str) -> str:
    return f'INSERT INTO {db} (name, data) VALUES (\"{name_val}\",\"{data_val}\");'

# Store data in storage database #
def DB_STORE(db: str, name_val: str, path_val: str, data_val: str) -> str:
    return f'INSERT INTO {db} (name, path, data) VALUES (\"{name_val}\", \"{path_val}\", \"{data_val}\");'

# Retrieve item from database #
def DB_RETRIEVE(db: str, name: str) -> str:
    return f'SELECT name,data FROM {db} WHERE name=\"{name}\";'

# Enumerate contents of database #
def DB_CONTENTS(db: str) -> str:
    return f'SELECT * FROM {db}'

# Delete item from database #
def DB_DELETE(db: str, item: str) -> str:
    return f'DELETE FROM {db} WHERE name=\"{item}\"'
