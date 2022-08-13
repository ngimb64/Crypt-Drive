# pylint: disable=W0601,W0604
""" Built-in modules """
import os
from io import StringIO


# Global variables #
global CWD, LOG_STREAM, FILES, DBS, DIRS, HAS_KEYS, MISSING


def initialize(path: str):
    """
    Initializes variables for global access.

    :param path:  The base path of the initially executed script.
    :return:  Nothing
    """
    # Global variables #
    global CWD, LOG_STREAM, FILES, DBS, DIRS, HAS_KEYS, MISSING

    # Absolute path to program #
    CWD = path
    # Create string IO object for logging #
    LOG_STREAM = StringIO()

    # IF the OS is Windows #
    if os.name == 'nt':
        FILES = (f'{path}\\CryptKeys\\aesccm.txt', f'{path}\\CryptKeys\\nonce.txt',
                 f'{path}\\CryptKeys\\db_crypt.txt', f'{path}\\CryptKeys\\secret_key.txt')
        DBS = (f'{path}\\CryptDbs\\crypt_keys.db', f'{path}\\CryptDbs\\crypt_storage.db')
        DIRS = (f'{path}\\CryptDbs', f'{path}\\CryptImport', f'{path}\\CryptKeys',
                f'{path}\\DecryptDock', f'{path}\\UploadDock')
    # If the OS is Linux #
    else:
        FILES = (f'{path}/CryptKeys/aesccm.txt', f'{path}/CryptKeys/nonce.txt',
                 f'{path}/CryptKeys/db_crypt.txt', f'{path}/CryptKeys/secret_key.txt')
        DBS = (f'{path}/CryptDbs/crypt_keys.db', f'{path}/CryptDbs/crypt_storage.db')
        DIRS = (f'{path}/CryptDbs', f'{path}/CryptImport', f'{path}/CryptKeys',
                f'{path}/DecryptDock', f'{path}/UploadDock')

    # Check if text files exist #
    key_check = file_check(FILES[0])
    nonce_check = file_check(FILES[1])
    dbkey_check = file_check(FILES[2])
    secretkey_check = file_check(FILES[3])

    # Check if database files exist #
    db_check = file_check(DBS[0])
    storage_check = file_check(DBS[1])

    # Check if directories exist #
    db_dir_check = dir_check(DIRS[0])
    decrypt_dir_check = dir_check(DIRS[1])
    import_dir_check = dir_check(DIRS[2])
    keys_dir_check = dir_check(DIRS[3])
    upload_dir_check = dir_check(DIRS[4])

    MISSING = []

    count = 0
    # If directories are missing, add them to the missing list #
    for item in (db_dir_check, decrypt_dir_check, import_dir_check,
                 keys_dir_check, upload_dir_check):
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


def dir_check(path: str) -> bool:
    """
    Check if directory exists.

    :param path:  The path to the directory to be checked.
    :return:  Boolean True/False whether directory exists/non-exists.
    """
    return os.path.isdir(path)


def file_check(path: str) -> bool:
    """
    Check if file exists.

    :param path:  The path to the file to be checked.
    :return:  Boolean True/False whether directory exists/non-exists.
    """
    return os.path.isfile(path)


def db_keys(db_name: str) -> str:
    """
    Format MySQL query for Keys database table creation.

    :param db_name:  The name of the database where the table is created.
    :return:  Formatted MySQL query.
    """
    return f'CREATE TABLE {db_name}(name VARCHAR(20) PRIMARY KEY NOT NULL, data TINYTEXT NOT NULL);'


def db_storage(db_name: str) -> str:
    """
    Format MySQL query for Storage database table creation.

    :param db_name:  The name of the database where the table is created.
    :return:  Formatted MySQL query.
    """
    return f'CREATE TABLE {db_name}(name VARCHAR(20) PRIMARY KEY NOT NULL, path TINYTEXT NOT NULL' \
           'data LONGTEXT NOT NULL);'


def db_insert(db_name: str, name_val: str, data_val: str) -> str:
    """
    Format MySQL query to insert keys in the keys database.

    :param db_name:  The name of the database where the table is created.
    :param name_val:  The name of the value that is stored.
    :param data_val:  The content of the value that is stored.
    :return:  Formatted MySQL query.
    """
    return f'INSERT INTO {db_name} (name, data) VALUES (\"{name_val}\",\"{data_val}\");'


def db_store(db_name: str, name_val: str, path_val: str, data_val: str) -> str:
    """
    Format MySQL query to insert data into the storage database.

    :param db_name:  The name of the database where the table is created.
    :param name_val:  The name of the file to be stored.
    :param path_val:  The path where the file is stored.
    :param data_val:  The data contained within the file.
    :return:  Formatted MySQL query.
    """
    return f'INSERT INTO {db_name} (name, path, data) VALUES (\"{name_val}\", \"{path_val}\",' \
           f' \"{data_val}\");'


def db_retrieve(db_name: str, name: str) -> str:
    """
    Format MySQL query to retrieve item from database.

    :param db_name:  The database name where the item will be retrieved.
    :param name:  The name of the item to be retrieved.
    :return:  Formatted MySQL query.
    """
    return f'SELECT name,data FROM {db_name} WHERE name=\"{name}\";'


def db_contents(db_name: str) -> str:
    """
    Format MYySQL query to retrieve the contents of a database.

    :param db_name:  The database whose contents will be retrieved.
    :return:  Formatted MySQL query.
    """
    return f'SELECT * FROM {db_name}'


# Delete item from database #
def db_delete(db_name: str, item: str) -> str:
    """
    Format MySQL query to delete an item from a database.

    :param db_name:  The database where the item will be deleted.
    :param item:  The item to be deleted from the database.
    :return:  Formatted MySQL query.
    """
    return f'DELETE FROM {db_name} WHERE name=\"{item}\"'
