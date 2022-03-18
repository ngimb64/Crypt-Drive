# Script for installing modules not included
# with Python 3 default installation #

import os, re
from time import sleep
from subprocess import Popen, SubprocessError, TimeoutExpired, CalledProcessError 

def install(package, stdout, stderr, exec_time):
    try:
        command = Popen(['pip', 'install', '--user', package], stdout=stdout, stderr=stderr, shell=False)
        outs, errs = command.communicate(exec_time)
    except (SubprocessError, TimeoutExpired, CalledProcessError, OSError, ValueError):
        command.kill()
        outs, errs = command.communicate()

def main():
    re_mod = re.compile(r'^[a-zA-Z0-9\=\-\.]{2,20}')
    filename = 'packages.txt'

    # Open file & iterate line by line #
    if os.path.isfile(filename) and os.access(filename, os.R_OK):
        try:
            with open(filename, 'r') as file:
                for line in file:
                    # If regex matches package name .. install #
                    if re.search(re_mod, line):
                        install(line, None, None, 2)
        # File error handling #
        except (IOError, FileNotFoundError,Exception) as err:
            print(f'\n* Error Occured: {err} *\n\n')
            input('Hit enter to end ..\n')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
