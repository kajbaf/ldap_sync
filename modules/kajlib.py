'''
@changelist:
2.1: added internal file objects along with functionalities to handle and check open/close state of file.
2.2: support for tty files.
'''
from __future__ import print_function, division
import sys
from os.path import isfile, isdir, exists, join
from os import makedirs, rmdir, unlink


__author__ = 'Mohammad Kajbaf'
__version__ = '2.2'


def automain(func):
    """decorator to declare the _main_ function which will be default to run
    use as:
    @automain
    def default_func():
    ...pass"""
    import inspect
    parent = inspect.stack()[1][0]
    name = parent.f_locals.get('__name__', None)
    if name == '__main__':
        func()


def info(*objs):
    """function to write information messages to stdout"""
    print('INFO ', *objs, file=sys.stdout)


def warning(*objs):
    """function to write warning messages to stderr"""
    print('WARNING ', *objs, file=sys.stderr)


def error(*objs):
    """function to write error messages to stderr"""
    print('ERROR ', *objs, file=sys.stderr)


def getint(message):
    """function to get integer from input"""
    try:
        i = int(raw_input(message))
    except ValueError, e:
        warning(e)
        raise e
    return i


def getfloat(message):
    """function to get float from input"""
    try:
        f = float(raw_input(message))
    except ValueError, e:
        warning(e)
        raise e
    return f


def getstr(message):
    """function to get string from input"""
    try:
        str = raw_input(message)
    except ValueError, e:
        warning(e)
        raise e
    return str


def isdebug():
    """function to check Kaj Debug mode"""
    return 'DEBUG' in globals() and bool(DEBUG)

def set_debug():
    """function to set Kaj Debug mode"""
    globals()['DEBUG'] = 1

def clear_debug():
    """function to reset Kaj Debug mode"""
    globals()['DEBUG'] = 0


class path(object):
    r"""
    Instances of this class represent a file path, and facilitate
    several operations on files and directories.
    Its most surprising feature is that it overloads the division
    operator, so that the result of placing a / operator between two
    paths (or between a path and a string) results in a longer path,
    representing the two operands joined by the system's path
    separator character.
    Now, it handles openning and closing of files like a charm!
    """
    def __init__(self, target):
        if isinstance(target, path):
            self.target = target.target
            self.f = target.f
        elif isinstance(target, file):
            self.f = file
            self.target = file.name
        else:
            self.target = target
            self.f = None

    def exists(self):
        return exists(self.target)

    def isfile(self):
        return isfile(self.target)

    def isdir(self):
        return isdir(self.target)

    def isopen(self):
        return True if self.f and not self.f.closed else False

    def isatty(self):
        return self.f.isatty()

    def mkdir(self, mode = 493):
        makedirs(self.target, mode)

    def rmdir(self):
        if self.isdir():
            rmdir(self.target)
        else:
            raise ValueError('Path does not represent a directory')

    def delete(self):
        if self.isopen():
            self.close()
        if self.isfile():
            unlink(self.target)
        else:
            raise ValueError('Path does not represent a file')

    def open(self, mode = "r"):
        if self.isopen():
            if self._mode == mode or self.isatty():
                return self.f
            else:
                self.close()
        self._mode = mode
        self.f = file(self.target, mode)
        return self.f

    def close(self):
        if self.isopen() and not self.isatty():
            self.f.close()

    @staticmethod
    def join(path, fname):
        return join(path, fname)

    def __div__(self, other):
        if isinstance(other, path):
            return path(join(self.target, other.target))
        return path(join(self.target, other))

    def __repr__(self):
        return '<path %s>' % self.target

    def __str__(self):
        return str(self.__unicode__())

    def __unicode__(self):
        return u'%s' % self.target
