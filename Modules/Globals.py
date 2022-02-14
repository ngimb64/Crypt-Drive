from io import StringIO
import os

def Initialize():
    global DIR_CHECK, FILE_CHECK, DB_KEYS, DB_STORAGE, DB_INSERT, DB_STORE, \
           DB_RETRIEVE, DB_CONTENTS, DB_DELETE, LOG, LOG_STREAM

    # Portable lambda functions #
    DIR_CHECK = lambda path: os.path.isdir(path)
    FILE_CHECK = lambda path: os.path.isfile(path)
    DB_KEYS = lambda db: f'CREATE TABLE {db}(name VARCHAR(20) PRIMARY KEY NOT NULL, item TINYTEXT NOT NULL);'
    DB_STORAGE = lambda db: f'CREATE TABLE {db}(name VARCHAR(20) PRIMARY KEY NOT NULL, path TINYTEXT NOT NULL, item LONGTEXT NOT NULL);'
    DB_INSERT = lambda db, name_val, item_val: f'INSERT INTO {db} (name, item) VALUES (\"{name_val}\",\"{item_val}\");'
    DB_STORE = lambda db, name_val, path_val, item_val: f'INSERT INTO {db} (name, path, item) VALUES (\"{name_val}\", \"{path_val}\", \"{item_val}\");'
    DB_RETRIEVE = lambda db, name: f'SELECT name,item FROM {db} WHERE name=\"{name}\";'
    DB_CONTENTS = lambda db: f'SELECT * FROM {db}'
    DB_DELETE = lambda db, item: f'DELETE FROM {db} WHERE name=\"{item}\"'

    # Logging boolean toggle switch #
    LOG = False

    # Set logging as string IO object #
    LOG_STREAM = StringIO() 