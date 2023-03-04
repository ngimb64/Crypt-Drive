""" Built-in modules """
import sqlite3
import sys
# Custom modules #
import Modules.utils as utils


def db_create(db_tuple: tuple) -> str:
    """
    Create the program database with keys and data storage tables.

    :param db_tuple:  Database table name tuple.
    :return:  The parsed database creation query.
    """
    return f'''
            CREATE TABLE IF NOT EXISTS {db_tuple[0]} (
                name VARCHAR(20) PRIMARY KEY NOT NULL,
                data TINYTEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS {db_tuple[1]} (
                name VARCHAR(40) PRIMARY KEY NOT NULL,
                path TINYTEXT NOT NULL,
                data LONGTEXT NOT NULL
            );
    '''


def key_insert(db_name: str) -> str:
    """
    Format MySQL query to insert keys in the keys database.

    :param db_name:  The name of the database where the table is created.
    :return:  Formatted MySQL query.
    """
    return f'INSERT INTO {db_name} (name, data) VALUES (?,?);'


def data_insert(db_name: str) -> str:
    """
    Format MySQL query to insert data into the storage database.

    :param db_name:  The name of the database where the table is created.
    :return:  Formatted MySQL query.
    """
    return f'INSERT INTO {db_name} (name, path, data) VALUES (?, ?, ?);'


def db_retrieve(db_name: str) -> str:
    """
    Format MySQL query to retrieve item from database.

    :param db_name:  The database name where the item will be retrieved.
    :return:  Formatted MySQL query.
    """
    return f'SELECT name,data FROM {db_name} WHERE name=?;'


def db_contents(db_name: str) -> str:
    """
    Format MYySQL query to retrieve the contents of a database.

    :param db_name:  The database whose contents will be retrieved.
    :return:  Formatted MySQL query.
    """
    return f'SELECT * FROM {db_name};'


# Delete item from database #
def db_delete(db_name: str) -> str:
    """
    Format MySQL query to delete an item from a database.

    :param db_name:  The database where the item will be deleted.
    :return:  Formatted MySQL query.
    """
    return f'DELETE FROM {db_name} WHERE name=?;'


class DbConnectionHandler:
    """ Acts as custom context manager for easy integrated management of database connections. """
    def __init__(self, db_name):
        """
        Database connection initializer.

        :param db_name:  The string name of the database to be connected to.
        """
        self.connection = sqlite3.connect(db_name)

    def __enter__(self):
        """
        Method for managing what is returned into the context manager as proxy variable(connection).

        :return:  Context instance to be returned to connection variable in context manager.
        """
        # Return the context to the context manager #
        return self.connection

    def __exit__(self, exc_type, exc_val, traceback):
        """
        Method for handling the events that occurs when exiting context manager.

        :param exc_type:  The exception type.
        :param exc_val:  The exception value.
        :param traceback:  Exception traceback occurrence in stack.
        """
        # Close db connection on context manager exit #
        self.connection.close()


def query_handler(conf: object, query, *args, exec_script=None, fetch=None):
    """
    Database handler to handler various db calls with session locking and error handling.

    :param conf:  The program configuration instance.
    :param query:  The query to be executed in the accessed database.
    :param args:  Takes variable length arguments to pass as database parameters.
    :param exec_script:  If set to True, runs executescript instead of execute.
    :param fetch:  If set to one, fetchone is returned. If set to all, fetchall is returned.
    :return:  If fetching data, the fetched data is returned. Otherwise, None.
    """
    # If the passed in MySQL query was not a complete statement #
    if not sqlite3.complete_statement(query):
        # Print error, log, and exit #
        utils.print_err(f'Passed in query is not a complete MySQL statement: {query}', None)
        utils.logger(conf, f'Passed in query is not a complete MySQL statement: {query}',
                     operation='write', handler='error')
        sys.exit(3)

    try:
        # Connection context manager auto-handles commits/rollbacks #
        with conf.db_conn:
            # If query is one-liner #
            if not exec_script:
                # If no args to be parsed into query #
                if not args:
                    # Execute SQL query #
                    db_call = conf.db_conn.execute(query)
                # If args are to be parsed into query #
                else:
                    # Execute SQL query #
                    db_call = conf.db_conn.execute(query, args)

            # If query is multi-liner script #
            else:
                # Execute SQL script #
                db_call = conf.db_conn.executescript(query)

            # If the fetch flag is at default "None" #
            if not fetch:
                return None

            # If the fetch flag is set to "one" #
            if fetch == 'one':
                # Return fetched row #
                return db_call.fetchone()

            # If the fetch flag is set to "all" #
            if fetch == 'all':
                # Return all fetched rows #
                return db_call.fetchall()

            # If the fetch flag has been set to unknown value #
            utils.print_err(f'Fetch flag is set to unexpected value: {fetch}', None)
            utils.logger(conf, f'Fetch flag is set to unexpected value: {fetch}',
                         operation='write', handler='error')
            sys.exit(4)

    # If error occurs during database operation #
    except sqlite3.Error as db_err:
        # Lookup precise database error #
        db_error_query(conf, db_err)


def db_error_query(conf_obj: object, db_error: object):
    """
    Looks up the exact error raised by database error catch-all handler, prints and logs.

    :param conf_obj: The program configuration instance.
    :param db_error:  The database error that occurred to be looked-up.
    :return:  Nothing
    """
    # If query is not a string or multiple queries are passed to execute() #
    if db_error == sqlite3.Warning:
        utils.print_err(f'Db sqlite warning: {db_error}', None)
        utils.logger(conf_obj, f'Db sqlite3 warning: {db_error}',
                     operation='write', handler='error')

    # If error occurs during fetch across rollback or is unable to bind parameters #
    elif db_error == sqlite3.InterfaceError:
        utils.print_err(f'Db interface error: {db_error}', None)
        utils.logger(conf_obj, f'Db interface error: {db_error}',
                     operation='write', handler='error')

    # If data-related error occurs, such as number out of range and overflowed strings #
    elif db_error == sqlite3.DataError:
        utils.print_err(f'Db data-related error: {db_error}', None)
        utils.logger(conf_obj, f'Db data-related error: {db_error}',
                     operation='write', handler='error')

    # If database operation error occurs, such as a database path not being found or the failed
    # processing of a transaction #
    elif db_error == sqlite3.OperationalError:
        utils.print_err(f'Db operational error: {db_error}', None)
        utils.logger(conf_obj, f'Db operational error: {db_error}',
                     operation='write', handler='error')

    # If database relational integrity is affected #
    elif db_error == sqlite3.IntegrityError:
        utils.print_err(f'Db relational integrity error: {db_error}', None)
        utils.logger(conf_obj, f'Db relational integrity error: {db_error}',
                     operation='write', handler='error')

    # If sqlite3 internal error occurs, suggesting a potential runtime library issue #
    elif db_error == sqlite3.InternalError:
        utils.print_err(f'Db sqlite3 internal runtime error: {db_error}', None)
        utils.logger(conf_obj, f'Db sqlite3 internal runtime error: {db_error}',
                     operation='write', handler='error')

    # If sqlite3 API error occurs, such as trying to operate on a closed connection #
    elif db_error == sqlite3.ProgrammingError:
        utils.print_err(f'Db sqlite3 API operational error: {db_error}', None)
        utils.logger(conf_obj, f'Db sqlite3 APi operational error: {db_error}',
                     operation='write', handler='error')

    # If a called API method is not supported by the underlying SQLite3 runtime library #
    elif db_error == sqlite3.NotSupportedError:
        utils.print_err(f'Db API not supported by sqlite3 runtime library: {db_error}', None)
        utils.logger(conf_obj, f'Db API not supported by sqlite3 runtime library: {db_error}',
                     operation='write', handler='error')

    # If unexpected error occurs (shouldn't happen, just in case) #
    else:
        utils.print_err(f'Unexpected database exception: {db_error}', None)
        utils.logger(conf_obj, f'Unexpected database exception: {db_error}',
                     operation='write', handler='error')
