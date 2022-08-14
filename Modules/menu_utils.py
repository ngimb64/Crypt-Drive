""" Built-in modules """
import os
import re
# Custom modules #
from Modules.utils import print_err

def extract_input(re_dir, re_path) -> tuple:
    """
    Gathers users input for database data extraction function.

    :param re_path:  Compiled regex to match input file path.
    :param re_dir:  Compiled regex to match input directory name.
    :return:  tuple of validated user input.
    """
    while True:
        dir_name = input('Enter folder name to be recursively exported from the database: ')
        exp_path = input('\nEnter [A-Z]:\\Windows\\path or /Linux/path to export to'
                     ' or hit enter export in Documents:\n')
        crypt_check = input('\nShould the data be extracted in encrypted or plain text'
                       ' (encrypted or plain)? ')
        delete_check = input('\nShould the data extracted be deleted from the data base after'
                        ' operation (y or n)? ')

        # If path regex fails and enter was not input or folder regex fails #
        if not re.search(re_dir, dir_name) or (not re.search(re_path, exp_path) and exp_path != '')\
        or crypt_check not in ('encrypted', 'plain') or delete_check not in ('y', 'n'):
            print_err('Improper format .. try again following directions', 2)
            continue

        break

    if exp_path == '':
        exp_path = None

    return dir_name, exp_path, crypt_check, delete_check


def extract_parse(re_rel_winpath, re_rel_linpath, row: list, path: str) -> str:
    """
    Attempts to match regex of recursive path on stored file path in extracted database row. If \
    match fails, document is extracted to base directory entered in non-recursive fashion. If \
    stored filepath is formatted as opposing OS, reformat it to current OS.

    :param re_rel_winpath:  Compiled regex to match Windows path.
    :param re_rel_linpath:  Compiled regex to match Linux path.
    :param row:  The extracted row from the storage database.
    :param path:  Base path user entered.
    :return:
    """
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

    return file_path
