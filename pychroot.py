# Copyright (c) 2018, Ian Daniher <@itdaniher>
# Copyright (c) 2014-2017, pychroot developers
# BSD 3-Clause License

import os
import errno
import logging
import operator
from functools import reduce
from tinyoil import touch, mount, MS_BIND, MS_REC, MS_REMOUNT, MS_RDONLY, SplitExec, simple_unshare

ChrootError = ChrootMountError = Exception


def dictbool(dct, key):
    '''Check if a key exists and is True in a dictionary.

    :param dct: The dictionary to check.
    :type dct: dict
    :param key: The key to check
    :type key: any
    '''
    return key in dct and isinstance(dct[key], bool) and dct[key]


def getlogger(log, name):
    '''Gets a logger given a logger and a package.

    Will return the given logger if the name is not generated from
    the current package, otherwise generate a logger based on __name__.

    :param log: Logger to start with.
    :type log: logging.Logger
    :param name: The __name__ of the caller.
    :type name: str
    '''
    return log if isinstance(log, logging.Logger) and not log.name.startswith(name.partition('.')[0]) else logging.getLogger(name)


def bind(src, dest, chroot, create=False, log=None, readonly=False, recursive=False, **_kwargs):
    '''Set up a bind mount.

    :param src: The source location to mount.
    :type src: str
    :param dest: The destination to mount on.
    :type dest: str
    :param chroot: The chroot base path.
    :type chroot: str
    :param create: Whether to create the destination.
    :type create: bool
    :param log: A logger to use for logging.
    :type log: logging.Logger
    :param readonly: Whether to remount read-only.
    :type readonly: bool
    :param recursive: Whether to use a recursive bind mount.
    :type recursive: bool
    '''
    log = getlogger(log, __name__)
    fstypes = 'proc', 'sysfs', 'tmpfs'
    mount_flags = []
    mount_options = []
    if src not in fstypes:
        src = os.path.normpath(src)
    if os.path.islink(dest):
        dest = os.path.join(chroot, os.path.realpath(dest).lstrip('/'))
        if not os.path.exists(dest):
            create = True
    else:
        dest = os.path.normpath(dest)
    if create:
        try:
            if not os.path.isdir(src) and src not in fstypes:
                os.makedirs(os.path.dirname(dest))
            else:
                os.makedirs(dest)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
        if not os.path.isdir(src) and src not in fstypes:
            try:
                touch(dest)
            except OSError as e:
                raise ChrootMountError("cannot bind mount to '{}'".format(
                    dest), getattr(e, 'errno', None))
    if not os.path.exists(src) and src not in fstypes:
        raise ChrootMountError(
            "cannot bind mount from '{}'".format(src), errno.ENOENT)
    elif not os.path.exists(dest):
        raise ChrootMountError(
            "cannot bind mount to '{}'".format(dest), errno.ENOENT)
    if src in fstypes:
        fstype = src
        log.debug("  mounting '{}' filesystem on '{}'".format(src, dest))
    else:
        fstype = None
        mount_flags.append(MS_BIND)
        if recursive:
            mount_flags.append(MS_REC)
        log.debug("  bind mounting '{}' on '{}'".format(src, dest))
    try:
        mount(source=src, target=dest, fstype=fstype, flags=reduce(
            operator.or_, mount_flags, 0), data=','.join(mount_options))
        if readonly:
            mount_flags.extend([MS_REMOUNT, MS_RDONLY])
            mount(source=src, target=dest, fstype=fstype, flags=reduce(
                operator.or_, mount_flags, 0), data=','.join(mount_options))
    except OSError as e:
        raise ChrootMountError(
            'Failed mounting: mount -t {} {} {}'.format(fstype, src, dest), e.errno)


class Chroot(SplitExec):
    '''Context manager that provides chroot support.

    This is done by forking, doing some magic on the stack so the contents are
    not executed in the parent, and executing the context in the forked child.
    Exceptions are pickled and passed through to the parent.

    :param path: The path to the image to chroot into.
    :type path: str
    :param log: A log object to use for logging.
    :type log: logging.Logger
    :param mountpoints: A dictionary defining the mountpoints to use. These can
        override any of the defaults or add extra mountpoints
    :type mountpoints: dict
    :param hostname: The hostname for the chroot, defaults to the system hostname.
    :type hostname: str
    '''
    default_mounts = {'/dev': {'recursive': True}, 'proc:/proc': {},
                      'sysfs:/sys': {}, 'tmpfs:/dev/shm': {}, '/etc/resolv.conf': {}}

    def __init__(self, path, log=None, mountpoints=None, hostname=None, skip_chdir=False):
        super(Chroot, self).__init__()
        self.log = getlogger(log, __name__)
        self.path = os.path.abspath(path)
        self.hostname = hostname
        self.skip_chdir = skip_chdir
        self.mountpoints = self.default_mounts.copy()
        self.mountpoints.update(mountpoints if mountpoints else {})
        if not os.path.isdir(self.path):
            raise ChrootError(
                "cannot change root directory to '{}'".format(path), errno.ENOTDIR)
        for k, source, chrmount, opts in self.mounts:
            src = source
            if source.startswith('$'):
                src = os.getenv(source[1:], source)
                if src == source:
                    if 'optional' in opts:
                        self.log.debug(
                            'Skipping optional and nonexistent mountpoint due to undefined host environment variable: %s', source)
                        del self.mountpoints[k]
                        continue
                    else:
                        raise ChrootMountError(
                            'cannot mount undefined environment variable: {}'.format(source))
                self.log.debug(
                    'Expanding mountpoint "%s" to "%s"', source, src)
                self.mountpoints[src] = opts
                del self.mountpoints[k]
                if '$' in chrmount:
                    chrmount = os.path.join(self.path, src.lstrip('/'))
            if 'optional' not in opts and not os.path.exists(chrmount):
                self.mountpoints[k]['create'] = True

    @property
    def mounts(self):
        for k, options in list(self.mountpoints.items()):
            source, _, dest = k.partition(':')
            if not dest:
                dest = source
            dest = os.path.join(self.path, dest.lstrip('/'))
            yield k, source, dest, options

    def _child_setup(self):
        kwargs = {}
        if os.getuid() != 0:
            kwargs.update({'user': True, 'net': True})
        simple_unshare(pid=True, hostname=self.hostname, **kwargs)
        self._mount()
        os.chroot(self.path)
        if not self.skip_chdir:
            os.chdir('/')

    def _cleanup(self):
        for _, _, chrmount, opts in self.mounts:
            if 'create' not in opts:
                continue
            self.log.debug(
                'Removing dynamically created mountpoint: %s', chrmount)
            try:
                if not os.path.isdir(chrmount):
                    os.remove(chrmount)
                    chrmount = os.path.dirname(chrmount)
                os.removedirs(chrmount)
            except OSError:
                pass
            except Exception as e:
                raise ChrootMountError("failed to remove chroot mount point '{}'".format(
                    chrmount), getattr(e, 'errno', None))

    def _mount(self):
        '''Do the bind mounts for this chroot object.

        This _must_ be run after creating a new mount namespace.
        '''
        for _, source, chrmount, opts in self.mounts:
            if dictbool(opts, 'optional') and not os.path.exists(source):
                self.log.debug(
                    'Skipping optional and nonexistent mountpoint: %s', source)
                continue
            bind(src=source, dest=chrmount,
                 chroot=self.path, log=self.log, **opts)
