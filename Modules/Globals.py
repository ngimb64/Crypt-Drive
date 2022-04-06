# Built-in modules #
import os
from io import StringIO

# Global declarations #
global LOG, LOG_STREAM


"""
########################################################################################################################
Name:       Initialize
Purpose:    Initializes variables for global access.
Parameters: None
Returns:    None
########################################################################################################################
"""
def Initialize():
    global LOG, LOG_STREAM

    # Logging boolean on/off switch #
    LOG = False
    # Set logging as string IO object #
    LOG_STREAM = StringIO()


# Check if directory exists #
def DIR_CHECK(path: str) -> bool:
    return os.path.isdir(path)

# Check if file exists #
def FILE_CHECK(path: str) -> bool:
    return os.path.isfile(path)


''' MySQL database queries '''

# Create keys database #
def DB_KEYS(db: str) -> str:
    return f'CREATE TABLE {db}(name VARCHAR(20) PRIMARY KEY NOT NULL, item TINYTEXT NOT NULL);'

# Create storage database #
def DB_STORAGE(db: str) -> str:
    return f'CREATE TABLE {db}(name VARCHAR(20) PRIMARY KEY NOT NULL, path TINYTEXT NOT NULL, item LONGTEXT NOT NULL);'

# Insert item into keys database #
def DB_INSERT(db: str, name_val: str, item_val: str) -> str:
    return f'INSERT INTO {db} (name, item) VALUES (\"{name_val}\",\"{item_val}\");'

# Store data in storage database #
def DB_STORE(db: str, name_val: str, path_val: str, item_val: str) -> str:
    return f'INSERT INTO {db} (name, path, item) VALUES (\"{name_val}\", \"{path_val}\", \"{item_val}\");'

# Retrieve item from database #
def DB_RETRIEVE(db: str, name: str) -> str:
    return f'SELECT name,item FROM {db} WHERE name=\"{name}\";'

# Enumerate contents of database #
def DB_CONTENTS(db: str) -> str:
    return f'SELECT * FROM {db}'

# Delete item from database #
def DB_DELETE(db: str, item: str) -> str:
    return f'DELETE FROM {db} WHERE name=\"{item}\"'
