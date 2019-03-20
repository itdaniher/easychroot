# SplitExec implementation from https://pypi.python.org/pypi/withhacks
# Copyright 2010 Ryan Kelly under the MIT License
#
# other code from https://github.com/pkgcore/snakeoil and https://github.com/pkgcore/pychroot
# Copyright 2018 Ian Daniher <itdaniher@gmail.com> under the BSD-3 Clause License
# Copyright 2015-2017 Tim Harder <radhermit@gmail.com> under the BSD-3 Clause License

import os
import sys
import errno
import pickle
import signal
import ctypes
import inspect
import functools
import threading
import traceback
import subprocess

from multiprocessing.connection import Pipe
from importlib import import_module
from typing import Optional, Union

CLONE_FS = 512
CLONE_FILES = 1024
CLONE_NEWNS = 131072
CLONE_NEWUTS = 67108864
CLONE_NEWIPC = 134217728
CLONE_NEWUSER = 268435456
CLONE_NEWPID = 536870912
CLONE_NEWNET = 1073741824
MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_SYNCHRONOUS = 16
MS_REMOUNT = 32
MS_MANDLOCK = 64
MS_DIRSYNC = 128
MS_NOATIME = 1024
MS_NODIRATIME = 2048
MS_BIND = 4096
MS_MOVE = 8192
MS_REC = 16384
MS_SILENT = 32768
MS_POSIXACL = 1 << 16
MS_UNBINDABLE = 1 << 17
MS_PRIVATE = 1 << 18
MS_SLAVE = 1 << 19
MS_SHARED = 1 << 20
MS_RELATIME = 1 << 21
MS_KERNMOUNT = 1 << 22
MS_I_VERSION = 1 << 23
MS_STRICTATIME = 1 << 24
MS_ACTIVE = 1 << 30
MS_NOUSER = 1 << 31
MNT_FORCE = 1
MNT_DETACH = 2
MNT_EXPIRE = 4
UMOUNT_NOFOLLOW = 8


def touch(fname, mode=420, **kwargs):
    """touch(1) equivalent
    :param fname: file path
    :type fname: str
    :param mode: file mode
    :type mode: octal
    See os.utime for other supported arguments.
    """
    flags = os.O_CREAT | os.O_APPEND
    dir_fd = kwargs.get("dir_fd", None)
    os_open = functools.partial(os.open, dir_fd=dir_fd)
    with os.fdopen(os_open(fname, flags, mode)) as f:
        os.utime(f.fileno() if os.utime in os.supports_fd else fname, dir_fd=None if os.supports_fd else dir_fd, **kwargs)


class SplitExec(object):
    """Context manager separating code execution across parent/child processes.

    This is done by forking and doing some magic on the stack so the contents
    of the context are executed only on the forked child. Exceptions are
    pickled and passed back to the parent.
    """

    def __init__(self) -> None:
        self.__trace_lock = threading.Lock()
        self.__orig_sys_trace = None
        self.__orig_trace_funcs = {}
        self.__injected_trace_funcs = {}
        self.__pipe = None
        self.childpid = None
        self.exit_status = -1
        self.locals = {}

    def _parent_handler(self, signum, frame):
        """Signal handler for the parent process.

        By default this runs the parent cleanup and then resends the original
        signal to the parent process.
        """
        self._cleanup()
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    def _parent_setup(self) -> None:
        "Initialization for parent process."
        try:
            signal.signal(signal.SIGINT, self._parent_handler)
            signal.signal(signal.SIGTERM, self._parent_handler)
        except ValueError:
            pass

    def _child_setup(self):
        "Initialization for child process."

    def _cleanup(self):
        "Parent process clean up on termination of the child."

    def _exception_cleanup(self):
        "Parent process clean up after the child throws an exception."
        self._cleanup()

    def _child_exit(self, exc):
        frame = self.__get_context_frame()
        local_vars = {}
        for k, v in frame.f_locals.items():
            if k not in self.__child_orig_locals or v != self.__child_orig_locals[k]:
                try:
                    pickle.dumps(v)
                    local_vars[k] = v
                except (AttributeError, TypeError, pickle.PicklingError):
                    continue
        exc._locals = local_vars
        try:
            self.__pipe.send(exc)
        except (BrokenPipeError if sys.hexversion >= 50528256 else OSError, IOError) as e:
            if e.errno in (errno.EPIPE, errno.ESHUTDOWN):
                pass
            else:
                raise
        os._exit(0)

    def __enter__(self):
        parent_pipe, child_pipe = Pipe()
        childpid = os.fork()
        if childpid != 0:
            self._parent_setup()
            self.childpid = childpid
            self.__pipe = parent_pipe
            frame = self.__get_context_frame()
            self.__inject_trace_func(frame, self.__exit_context)
            return self
        else:
            frame = self.__get_context_frame()
            self.__child_orig_locals = dict(frame.f_locals)
            self.__pipe = child_pipe
            try:
                self._child_setup()
            except Exception as exc:
                exc.__traceback_list__ = traceback.format_exc()
                self._child_exit(exc)
            return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if self.childpid is not None:
            self.__revert_tracing(inspect.currentframe())
            if exc_type is not self.ParentException:
                raise exc_value
            try:
                exc = self.__pipe.recv()
                self.locals = exc._locals
            except EOFError as e:
                exc = SystemExit(e)
            if not isinstance(exc, SystemExit):
                os.waitpid(self.childpid, 0)
                self._exception_cleanup()
                sys.excepthook = self.__excepthook
                raise exc
        else:
            if exc_value is not None:
                exc = exc_value
                exc.__traceback_list__ = traceback.format_exc()
            else:
                exc = SystemExit()
            self._child_exit(exc)
        _pid, exit_status = os.waitpid(self.childpid, 0)
        self.exit_status = exit_status >> 8
        self._cleanup()
        return True

    @staticmethod
    def __excepthook(_exc_type, exc_value, exc_traceback):
        "Output the proper traceback information from the chroot context."
        if hasattr(exc_value, "__traceback_list__"):
            sys.stderr.write(exc_value.__traceback_list__)
        else:
            traceback.print_tb(exc_traceback)

    @staticmethod
    def __dummy_sys_trace(frame, event, arg):
        "Dummy trace function used to enable tracing."

    class ParentException(Exception):
        "Exception used to detect when the child terminates."

    def __enable_tracing(self):
        "Enable system-wide tracing via a dummy method."
        self.__orig_sys_trace = sys.gettrace()
        sys.settrace(self.__dummy_sys_trace)

    def __revert_tracing(self, frame=None):
        "Revert to previous system trace setting."
        sys.settrace(self.__orig_sys_trace)
        if frame is not None:
            frame.f_trace = self.__orig_sys_trace

    def __exit_context(self, frame, event, arg):
        "Simple function to throw a ParentException."
        raise self.ParentException()

    def __inject_trace_func(self, frame, func):
        """Inject a trace function for a frame.

        The given trace function will be executed immediately when the frame's
        execution resumes.
        """
        with self.__trace_lock:
            if frame.f_trace is not self.__invoke_trace_funcs:
                self.__orig_trace_funcs[frame] = frame.f_trace
                frame.f_trace = self.__invoke_trace_funcs
                self.__injected_trace_funcs[frame] = []
                if len(self.__orig_trace_funcs) == 1:
                    self.__enable_tracing()
        self.__injected_trace_funcs[frame].append(func)

    def __invoke_trace_funcs(self, frame, event, arg):
        """Invoke all trace funcs that have been injected.

        Once the injected functions have been executed all trace hooks are
        removed in order to minimize overhead.
        """
        try:
            for func in self.__injected_trace_funcs[frame]:
                func(frame, event, arg)
        finally:
            del self.__injected_trace_funcs[frame]
            with self.__trace_lock:
                if len(self.__orig_trace_funcs) == 1:
                    self.__revert_tracing()
                frame.f_trace = self.__orig_trace_funcs.pop(frame)

    def __get_context_frame(self):
        """Get the frame object for the with-statement context.

        This is designed to work from within superclass method call. It finds
        the first frame where the local variable "self" doesn\'t exist.
        """
        try:
            return self.__frame
        except AttributeError:
            frame = inspect.stack(0)[2][0]
            while frame.f_locals.get("self") is self:
                frame = frame.f_back
            self.__frame = frame
            return frame


def exit_as_status(status: int) -> None:
    """Exit the same way as |status|.
    If the status field says it was killed by a signal, then we'll do that to
    ourselves.  Otherwise we'll exit with the exit code.
    See http://www.cons.org/cracauer/sigint.html for more details.
    Args:
        status: A status as returned by os.wait type funcs.
    """
    exit_status = os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        sig_status = os.WTERMSIG(status)
        pid = os.getpid()
        os.kill(pid, sig_status)
        time.sleep(0.1)
        try:
            signal.signal(sig_status, signal.SIG_DFL)
        except RuntimeError as e:
            if e.args[0] != errno.EINVAL:
                raise
        os.kill(pid, sig_status)
        time.sleep(0.1)
        exit_status = 127
    sys.exit(exit_status)


def unshare(flags: int) -> None:
    """Binding to the Linux unshare system call. See unshare(2) for details.

    Args:
        flags: Namespaces to unshare; bitwise OR of CLONE_* flags.

    Raises:
        OSError: if unshare failed.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(ctypes.c_int(flags)) != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))


def _reap_children(pid: int) -> int:
    """Reap all children that get reparented to us until we see |pid| exit.

    Args:
        pid: The main child to watch for.

    Returns:
        The wait status of the |pid| child.
    """
    pid_status = 0
    while True:
        try:
            wpid, status = os.wait()
            if pid == wpid:
                pid_status = status
        except OSError as e:
            if e.errno == errno.ECHILD:
                break
            elif e.errno != errno.EINTR:
                raise
    return pid_status


def _safe_tcsetpgrp(fd: int, pgrp: int) -> None:
    "Set |pgrp| as the controller of the tty |fd|."
    try:
        curr_pgrp = os.tcgetpgrp(fd)
    except OSError as e:
        if e.errno == errno.ENOTTY:
            return
        raise
    if curr_pgrp == os.getpgrp():
        os.tcsetpgrp(fd, pgrp)


def create_pidns() -> Optional[int]:
    """Start a new pid namespace

    This will launch all the right manager processes.  The child that returns
    will be isolated in a new pid namespace.

    If functionality is not available, then it will return w/out doing anything.

    Returns:
        The last pid outside of the namespace.
    """
    first_pid = os.getpid()
    try:
        unshare(CLONE_NEWPID)
    except OSError as e:
        if e.errno == errno.EINVAL:
            return first_pid
        else:
            raise
    pid = os.fork()
    if pid:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        _safe_tcsetpgrp(sys.stdin.fileno(), pid)
        exit_as_status(_reap_children(pid))
    else:
        try:
            mount(None, "/proc", "proc", MS_PRIVATE | MS_REC)
        except OSError as e:
            if e.errno != errno.EINVAL:
                raise
        mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME)
        pid = os.fork()
        if pid:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            os.setpgrp()
            _safe_tcsetpgrp(sys.stdin.fileno(), pid)
            exit_as_status(_reap_children(pid))
    os.setpgrp()
    return first_pid


def create_utsns(hostname: Optional[str] = None) -> None:
    """Start a new UTS namespace

    If functionality is not available, then it will return w/out doing anything.
    """
    try:
        unshare(CLONE_NEWUTS)
    except OSError as e:
        if e.errno != errno.EINVAL:
            return
        else:
            raise
    if hostname is not None:
        socket.sethostname(hostname)


def simple_unshare(_mount: bool = True, uts: bool = True, ipc: bool = True, pid: bool = True, hostname: Optional[str] = None) -> None:
    """Simpler helper for setting up namespaces quickly.

    If support for any namespace type is not available, we'll silently skip it.

    Args:
        mount: Create a mount namespace.
        uts: Create a UTS namespace.
        ipc: Create an IPC namespace.
        pid: Create a pid namespace.
        hostname: hostname to use for the UTS namespace
    """
    if _mount:
        unshare(CLONE_NEWNS)
        try:
            mount(None, "/", None, MS_REC | MS_SLAVE)
        except OSError as e:
            if e.errno != errno.EINVAL:
                raise
    if uts:
        create_utsns(hostname)
    if ipc:
        try:
            unshare(CLONE_NEWIPC)
        except OSError as e:
            if e.errno != errno.EINVAL:
                pass
    if pid:
        create_pidns()


def mount(source: Optional[str], target: str, fstype: Optional[str], flags: int, data: None = None) -> None:
    "Call mount(2); see the man page for details."
    libc = ctypes.CDLL(None, use_errno=True)
    source = source.encode() if isinstance(source, str) else source
    target = target.encode() if isinstance(target, str) else target
    fstype = fstype.encode() if isinstance(fstype, str) else fstype
    if libc.mount(source, target, fstype, ctypes.c_ulong(flags), data) != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
