# pylint: disable=W0106
""" Built-in modules """
import argparse
import os
import sys
import venv
from pathlib import Path
from subprocess import Popen, PIPE, TimeoutExpired
from threading import Thread
from urllib.parse import urlparse
from urllib.request import urlretrieve


# Global variables #
# If the OS is Windows #
if os.name == 'nt':
    PACKAGE_FILENAME = 'windows_packages.txt'
# If the OS is Linux #
else:
    PACKAGE_FILENAME = 'linux_packages.txt'


def system_cmd(cmd: list, exec_time):
    """
    Executes system shell command and returns the output. If improper data type is in command syntax
    list or error occurs during command execution, the error is displayed via stderr and logged,
    and False is returned to indicated failed operation.

    :param cmd:  The command to be executed.
    :param exec_time:  The execution timeout to prevent process hangs.
    :return:  Nothing
    """
    try:
        # Set up child process in context manager, piping output & errors to return variables #
        with Popen(cmd, stdout=sys.stdout, stderr=sys.stderr, shell=True) as command:
            # Execute process for passed in timeout (None=blocking) #
            command.communicate(timeout=exec_time)

    # If the process times out #
    except TimeoutExpired:
        # Print error and log #
        print_err(f'Process for {cmd} timed out before finishing execution')

    # If the input command has data other than string #
    except TypeError:
        # Print error and log #
        print_err(f'Input in {cmd} contains data type other than string')


class ExtendedEnvBuilder(venv.EnvBuilder):
    """
    This builder installs setuptools and pip so that you can pip or easy_install other packages
    into the created virtual environment.

    :param nodist:  If true, setuptools and pip are not installed into the created virtual
                    environment.
    :param nopip:  If true, pip is not installed into the created virtual environment.
    :param progress:  If setuptools or pip are installed, the progress of the installation can be
                      monitored by passing a progress callable. If specified, it is called with
                      two arguments: a string indicating some progress, and a context indicating
                      where the string is coming from. The context argument can have one of three
                      values: 'main', indicating that it is called from virtualize() itself, and
                      'stdout' and 'stderr', which are obtained by reading lines from the output
                      streams of a subprocess which is used to install the app. If a callable is
                      not specified, default progress information is output to sys.stderr.
    """
    def __init__(self, *args, **kwargs):
        self.nodist = kwargs.pop('nodist', False)
        self.nopip = kwargs.pop('nopip', False)
        self.progress = kwargs.pop('progress', None)
        self.verbose = kwargs.pop('verbose', False)
        super().__init__(*args, **kwargs)

    def install_setuptools(self, context):
        """
        Install setuptools in the virtual environment.

        :param context: The information for the virtual environment creation request.
        """
        url = 'https://github.com/abadger/setuptools/blob/master/ez_setup.py'
        self.install_script(context, 'setuptools', url)

        # Clear up the setuptools archive which gets downloaded #
        pred = lambda o: o.startswith('setuptools-') and o.endswith('.tar.gz')
        files = filter(pred, os.listdir(context.bin_path))

        # Iterate through files in bin path and delete #
        for file in files:
            file = os.path.join(context.bin_path, file)
            os.unlink(file)

    def install_pip(self, context):
        """
        Install pip in the virtual environment.

        :param context: The information for the virtual environment creation request.
        """
        url = 'https://bootstrap.pypa.io/get-pip.py'
        self.install_script(context, 'pip', url)

    def post_setup(self, context):
        """
        Set up any packages which need to be pre-installed into the virtual environment being
        created.

        :param context:  The information for the virtual environment creation request.
        :return:  Nothing
        """
        os.environ['VIRTUAL_ENV'] = context.env_dir

        # If no setup tools #
        if not self.nodist:
            # Install setup tools #
            self.install_setuptools(context)

        # If no pip and setuptools #
        if not self.nopip and not self.nodist:
            # Install them #
            self.install_pip(context)

        # Get the current working dir #
        path = Path.cwd()
        venv_path = Path(context.env_dir)
        # Format the package path #
        package_path = path / PACKAGE_FILENAME

        # If the OS is Windows #
        if os.name == 'nt':
            # Format path for pip installation in venv #
            pip_path = venv_path / 'Scripts' / 'pip.exe'
        # If the OS is Linux #
        else:
            # Format path for pip installation in venv #
            pip_path = venv_path / 'bin' / 'pip'

        # Execute the pip upgrade command as child process #
        command = [str(pip_path), 'install', '--upgrade', 'pip']
        system_cmd(command, 60)

        # If the package list file exists #
        if package_path.exists():
            # Execute pip -r into venv based on package list #
            command = [str(pip_path), 'install', '-r', str(package_path)]
            system_cmd(command, 300)

    def reader(self, stream, context):
        """
        Read lines from a subprocess' output stream and either pass to a progress callable
        (if specified) or write progress information to sys.stderr.

        :param stream:  Subprocess output stream.
        :param context:  The information for the virtual environment creation request.
        :return: Nothing
        """
        progress = self.progress

        while True:
            # Read line from subprocess stream #
            proc_stream = stream.readline()

            # If there is no more data to read #
            if not proc_stream:
                break

            # If progress has no data #
            if progress is not None:
                progress(proc_stream, context)
            # If progress is present #
            else:
                # If not set to verbose #
                if not self.verbose:
                    sys.stderr.write('.')
                # If verbosity set #
                else:
                    sys.stderr.write(proc_stream.decode('utf-8'))

                sys.stderr.flush()

        stream.close()

    def install_script(self, context, name, url):
        """
        Retrieve content from passed in url and install into the virtual env.

        :param context:  The information for the virtual environment creation request.
        :param name:  Utility name to be installed into environment.
        :param url:  The url where the utility can be retrieved from the internet.
        :return:  Nothing
        """
        _, _, path, _, _, _ = urlparse(url)
        file_name = os.path.split(path)[-1]
        binpath = context.bin_path
        distpath = os.path.join(binpath, file_name)

        # If the URL starts with http #
        if url.lower().startswith('http'):
            # Download script into the virtual environment's binaries folder #
            urlretrieve(url, distpath)
        # Unusual URL detected #
        else:
            print_err('Improper URL format attempted to be passed into urlretrieve')
            sys.exit(2)

        progress = self.progress

        if self.verbose:
            term = '\n'
        else:
            term = ''

        # If progress is set #
        if progress is not None:
            progress(f'Installing {name} .. {term}', 'main')
        # If progress is not set #
        else:
            sys.stderr.write(f'Installing {name} .. {term}')
            sys.stderr.flush()

        args = [context.env_exe, file_name]

        # Install in the virtual environment #
        with Popen(args, stdout=PIPE, stderr=PIPE, cwd=binpath) as proc:
            thread_1 = Thread(target=self.reader, args=(proc.stdout, 'stdout'))
            thread_1.start()
            thread_2 = Thread(target=self.reader, args=(proc.stderr, 'stderr'))
            thread_2.start()

            proc.wait()
            thread_1.join()
            thread_2.join()

        if progress is not None:
            progress('done.', 'main')
        else:
            sys.stderr.write('done.\n')

        # Clean up - no longer needed
        os.unlink(distpath)


def print_err(msg: str):
    """
    Prints error message via stderr.

    :param msg:  The error message to be displayed via stderr.
    :return:  Nothing
    """
    print(f'\n* [ERROR] {msg} *\n', file=sys.stderr)


def main(args=None):
    """
    Runs through various arg checks and sets up program.

    :param args:  None by default, but numerous options available.
    :return:  Nothing
    """
    if sys.version_info < (3, 3) or not hasattr(sys, 'base_prefix'):
        raise ValueError('This script is only for use with Python 3.3 or later')

    parser = argparse.ArgumentParser(prog=__name__,
                                     description='Creates virtual Python environments in one'
                                                 ' or more target directories.')
    parser.add_argument('dirs', metavar='ENV_DIR', nargs='+',
                        help='A directory in which to create the virtual environment.')
    parser.add_argument('--no-setuptools', default=False, action='store_true', dest='nodist',
                        help='Don\'t install setuptools or pip in the virtual environment.')
    parser.add_argument('--no-pip', default=False, action='store_true', dest='nopip',
                        help='Don\'t install pip in the virtual environment.')
    parser.add_argument('--system-site-packages', default=False, action='store_true',
                        dest='system_site', help='Give the virtual environment access to the '
                             'system site-packages dir.')

    if os.name == 'nt':
        use_symlinks = False
    else:
        use_symlinks = True

    parser.add_argument('--symlinks', default=use_symlinks, action='store_true',
                        dest='symlinks', help='Try to use symlinks rather than copies, when '
                                              'symlinks are not the default for the platform.')
    parser.add_argument('--clear', default=False, action='store_true', dest='clear',
                        help='Delete the contents of the virtual environment directory if it '
                             'already exists, before virtual environment creation.')
    parser.add_argument('--upgrade', default=False, action='store_true', dest='upgrade',
                        help='Upgrade the virtual environment directory to use this version of '
                        'Python, assuming Python has been upgraded in-place.')
    parser.add_argument('--verbose', default=False, action='store_true', dest='verbose',
                        help='Display the output from the scripts which install setuptools and '
                             'pip.')
    options = parser.parse_args(args)

    if options.upgrade and options.clear:
        raise ValueError('you cannot supply --upgrade and --clear together.')

    builder = ExtendedEnvBuilder(system_site_packages=options.system_site, clear=options.clear,
                                 symlinks=options.symlinks, upgrade=options.upgrade,
                                 nodist=options.nodist, nopip=options.nopip,
                                 verbose=options.verbose)

    [builder.create(d) for d in options.dirs]


if __name__ == '__main__':
    RET = 0
    try:
        main()

    except Exception as err:
        print_err(f'Unexpected error occurred: {err}')
        RET = 1

    sys.exit(RET)
