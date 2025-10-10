# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
from typing import TypeVar
from collections.abc import Iterator
import socket
import ctypes
import errno
import os
import contextlib

from mkosi.log import die
from mkosi.sandbox import oserror
from pathlib import Path

from mkosi.util import startswith

T = TypeVar("T")

SECCOMP_USER_NOTIF_FLAG_CONTINUE = 1
PIDFD_THREAD = os.O_EXCL

class iovec(ctypes.Structure):
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_len", ctypes.c_size_t),
    ]


class seccomp_data(ctypes.Structure):
    _fields_ = [
        ("nr", ctypes.c_int),
        ("arch", ctypes.c_uint32),
        ("instruction_pointer", ctypes.c_uint64),
        ("args", ctypes.c_uint64 * 6),
    ]


class seccomp_notif(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("data", seccomp_data),
    ]


class seccomp_notif_resp(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint64),
        ("val", ctypes.c_int64),
        ("error", ctypes.c_int32),
        ("flags", ctypes.c_uint32),
    ]


libc = ctypes.CDLL(None, use_errno=True)

libc.process_vm_readv.argtypes = (
    ctypes.c_uint32,
    ctypes.POINTER(iovec),
    ctypes.c_ulong,
    ctypes.POINTER(iovec),
    ctypes.c_ulong,
    ctypes.c_ulong,
)
libc.process_vm_readv.restype = ctypes.c_ssize_t
libc.process_vm_writev.argtypes = (
    ctypes.c_uint32,
    ctypes.POINTER(iovec),
    ctypes.c_ulong,
    ctypes.POINTER(iovec),
    ctypes.c_ulong,
    ctypes.c_ulong,
)
libc.process_vm_writev.restype = ctypes.c_ssize_t

libc.setxattr.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int)
libc.setxattr.restype = ctypes.c_int

libc.lsetxattr.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int)
libc.lsetxattr.restype = ctypes.c_int

libc.fsetxattr.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int)
libc.fsetxattr.restype = ctypes.c_int

libc.pidfd_getfd.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_uint)


def read_pointer_arguments(
    pid: ctypes.c_uint32,
    path_addr: int = 0,
    name_addr: int = 0,
    value_addr: int = 0,
    value_size: int = 0,
) -> tuple[bytes, bytes, bytes]:
    if path_addr == 0 and name_addr == 0 and value_addr == 0:
        return (b"", b"", b"")

    liovs = (iovec * 3)()
    riovs = (iovec * 3)()
    path_buf = name_buf = value_buf = None

    if path_addr != 0:
        path_buf = ctypes.create_string_buffer(4096)

        liovs[0].iov_base = ctypes.addressof(path_buf)
        liovs[0].iov_len = len(path_buf)

        riovs[0].iov_base = path_addr
        riovs[0].iov_len = len(path_buf)

    if name_addr != 0:
        name_buf = ctypes.create_string_buffer(256)

        liovs[1].iov_base = ctypes.addressof(name_buf)
        liovs[1].iov_len = len(name_buf)

        riovs[1].iov_base = name_addr
        riovs[1].iov_len = len(name_buf)

    if value_addr != 0:
        value_buf = ctypes.create_string_buffer(int(value_size))

        liovs[2].iov_base = ctypes.addressof(value_buf)
        liovs[2].iov_len = value_size

        riovs[2].iov_base = value_addr
        riovs[2].iov_len = len(value_buf)

    # Read all data in a single process_vm_readv call
    if libc.process_vm_readv(pid, liovs, 3, riovs, 3, 0) < 0:
        oserror("process_vm_readv")

    return (
        path_buf.value if path_buf else b"",
        name_buf.value if name_buf else b"",
        value_buf.raw if value_buf else b"",
    )


def find_tgid(pid: int) -> int:
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if tgid := startswith(line, "Tgid: "):
            return int(tgid.strip())

    die(f"Could not figure thread group leader for thread id {pid}")


@contextlib.contextmanager
def change_mount_namespace(pid: int) -> Iterator[None]:
    srcrootfd = os.open(f"/proc/self/root", os.O_PATH | os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    srccwdfd = os.open(f"/proc/self/cwd", os.O_PATH | os.O_RDONLY | os.O_CLOEXEC)
    srcpidfd = os.pidfd_open(os.getpid())

    tgtrootfd = os.open(f"/proc/{pid}/root", os.O_PATH | os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    tgtcwdfd = os.open(f"/proc/{pid}/cwd", os.O_PATH | os.O_RDONLY | os.O_CLOEXEC)

    try:
        tgtpidfd = os.pidfd_open(pid, PIDFD_THREAD)
    except OSError as e:
        if e.errno != errno.EINVAL:
            raise

        tgtpidfd = os.pidfd_open(find_tgid(pid))

    os.setns(tgtpidfd, os.CLONE_NEWNS)
    os.close(tgtpidfd)
    os.fchdir(tgtcwdfd)
    os.close(tgtcwdfd)
    resolved = os.readlink("", dir_fd=tgtrootfd)
    os.close(tgtrootfd)
    os.chroot(resolved)

    try:
        yield
    finally:
        os.setns(srcpidfd, os.CLONE_NEWNS)
        os.close(srcpidfd)
        os.fchdir(srccwdfd)
        os.close(srccwdfd)
        resolved = os.readlink("", dir_fd=srcrootfd)
        os.close(srcrootfd)
        os.chroot(resolved)


@contextlib.contextmanager
def copyfd(pid: int, fd: int) -> Iterator[int]:
    try:
        pidfd = os.pidfd_open(pid, PIDFD_THREAD)
    except OSError as e:
        if e.errno != errno.EINVAL:
            raise

        pidfd = os.pidfd_open(find_tgid(pid))

    fd = libc.pidfd_getfd(pidfd, fd, 0)
    os.close(pidfd)
    if fd < 0:
        oserror("pidfd_getfd")

    try:
        yield fd
    finally:
        os.close(fd)


def handle_setxattr(syscall: bytes, request: seccomp_notif, response: seccomp_notif_resp) -> None:
    size = request.data.args[3]
    flags = request.data.args[4]

    path, name, value = read_pointer_arguments(
        pid=request.pid,
        path_addr=request.data.args[0] if syscall != b"fsetxattr" else 0,
        name_addr=request.data.args[1],
        value_addr=request.data.args[2],
        value_size=request.data.args[3],
    )

    if not name.startswith(b"security."):
        response.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE
        return

    name = b"user." + name

    if syscall == b"setxattr":
        r = libc.setxattr(path, name, value, size, flags)
    elif syscall == b"fsetxattr":
        fd = request.data.args[0]

        with copyfd(request.pid, fd) as fd:
            r = libc.fsetxattr(fd, name, value, size, flags)
    else:
        assert syscall == b"lsetxattr"
        r = libc.lsetxattr(path, name, value, size, flags)

    if r < 0:
        response.error = -ctypes.get_errno()


def handle_getxattr(syscall: bytes, request: seccomp_notif, response: seccomp_notif_resp) -> None:
    size = request.data.args[3]

    path, name, _ = read_pointer_arguments(
        pid=request.pid,
        path_addr=request.data.args[0] if syscall != b"fgetxattr" else 0,
        name_addr=request.data.args[1],
    )

    if not name.startswith(b"security."):
        response.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE
        return

    name = b"user." + name
    value_buf = ctypes.create_string_buffer(size)

    if syscall == b"getxattr":
        r = libc.getxattr(path, name, value_buf, size)
    elif syscall == b"fgetxattr":
        fd = request.data.args[0]

        with copyfd(request.pid, fd) as fd:
            r = libc.fgetxattr(fd, name, value_buf, size)
    else:
        assert syscall == b"lgetxattr"
        r = libc.lgetxattr(path, name, value_buf, size)

    if r < 0:
        response.error = -ctypes.get_errno()
        return

    response.val = r

    if size == 0:
        return

    liovs = (iovec * 1)()
    liovs[0].iov_base = ctypes.addressof(value_buf)
    liovs[0].iov_len = size

    riovs = (iovec * 1)()
    riovs[0].iov_base = request.data.args[2]
    riovs[0].iov_len = size

    if libc.process_vm_writev(request.pid, liovs, 1, riovs, 1, 0) < 0:
        oserror("process_vm_writev")


def handle_listxattr(syscall: bytes, request: seccomp_notif, response: seccomp_notif_resp) -> None:
    size = request.data.args[2]

    path, _, _ = read_pointer_arguments(
        pid=request.pid,
        path_addr=request.data.args[0] if syscall != b"flistxattr" else 0,
    )

    list_buf = ctypes.create_string_buffer(size)

    if syscall == b"listxattr":
        r = libc.listxattr(path, list_buf, size)
    elif syscall == b"flistxattr":
        fd = request.data.args[0]

        with copyfd(request.pid, fd) as fd:
            r = libc.flistxattr(fd, list_buf, size)
    else:
        assert syscall == b"llistxattr"
        r = libc.llistxattr(path, list_buf, size)

    if r < 0:
        response.error = -ctypes.get_errno()
        return

    if size == 0:
        response.val = r
        return

    l = b"\0".join(
        xattr.replace(b"user.security.", b"security.")
        for xattr in list_buf.raw.split(b"\0")
        if not xattr.startswith(b"security.")
    )

    response.val = len(l)

    list_buf = ctypes.create_string_buffer(l, size=len(l))

    liovs = (iovec * 1)()
    liovs[0].iov_base = ctypes.addressof(list_buf)
    liovs[0].iov_len = len(list_buf)

    riovs = (iovec * 1)()
    riovs[0].iov_base = request.data.args[1]
    riovs[0].iov_len = len(list_buf)

    if libc.process_vm_writev(request.pid, liovs, 1, riovs, 1, 0) < 0:
        oserror("process_vm_writev")


def handle_removexattr(syscall: bytes, request: seccomp_notif, response: seccomp_notif_resp) -> None:
    path, name, _ = read_pointer_arguments(
        pid=request.pid,
        path_addr=request.data.args[0] if syscall != b"fremovexattr" else 0,
        name_addr=request.data.args[1],
    )

    if not name.startswith(b"security."):
        response.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE
        return

    name = b"user." + name

    if syscall == b"removexattr":
        r = libc.removexattr(path, name)
    elif syscall == b"fremovexattr":
        fd = request.data.args[0]

        with copyfd(request.pid, fd) as fd:
            r = libc.fremovexattr(fd, name)
    else:
        assert syscall == b"lremovexattr"
        r = libc.lremovexattr(path, name)

    if r < 0:
        response.error = -ctypes.get_errno()


def xattr_notify_handler(*, transport: socket.socket) -> None:
    libseccomp = ctypes.CDLL("libseccomp.so.2")
    if libseccomp is None:
        raise FileNotFoundError("libseccomp.so.2")

    libseccomp.seccomp_notify_alloc.argtypes = (
        ctypes.POINTER(ctypes.POINTER(seccomp_notif)),
        ctypes.POINTER(ctypes.POINTER(seccomp_notif_resp)),
    )
    libseccomp.seccomp_notify_receive.argtypes = (
        ctypes.c_int,
        ctypes.POINTER(seccomp_notif),
    )
    libseccomp.seccomp_syscall_resolve_num_arch.argtypes = (
        ctypes.c_uint32,
        ctypes.c_int,
    )
    libseccomp.seccomp_syscall_resolve_num_arch.restype = ctypes.c_char_p
    libseccomp.seccomp_notify_respond.argtypes = (
        ctypes.c_int,
        ctypes.POINTER(seccomp_notif_resp),
    )
    libseccomp.seccomp_notify_free.argtypes = (
        ctypes.POINTER(seccomp_notif),
        ctypes.POINTER(seccomp_notif_resp),
    )

    handlers = {
        b"setxattr": handle_setxattr,
        b"lsetxattr": handle_setxattr,
        b"fsetxattr": handle_setxattr,
        b"getxattr": handle_getxattr,
        b"lgetxattr": handle_getxattr,
        b"fgetxattr": handle_getxattr,
        b"listxattr": handle_listxattr,
        b"llistxattr": handle_listxattr,
        b"flistxattr": handle_listxattr,
        b"removexattr": handle_removexattr,
        b"lremovexattr": handle_removexattr,
        b"fremovexattr": handle_removexattr,
    }

    request = ctypes.POINTER(seccomp_notif)()
    response = ctypes.POINTER(seccomp_notif_resp)()

    r = libseccomp.seccomp_notify_alloc(request, response)
    if r < 0:
        oserror("seccomp_notify_alloc", errno=r)

    try:
        with transport:
            _, [seccomp_notify_fd], _, _ = socket.recv_fds(transport, bufsize=0, maxfds=1, flags=0)

        while True:
            ctypes.memset(request, 0, ctypes.sizeof(request.contents))
            r = libseccomp.seccomp_notify_receive(seccomp_notify_fd, request)
            if r == -errno.ECANCELED:
                break
            if r < 0:
                oserror("seccomp_notify_receive", errno=r)

            syscall = libseccomp.seccomp_syscall_resolve_num_arch(
                request.contents.data.arch, request.contents.data.nr
            )
            if not syscall:
                oserror("seccomp_syscall_resolve_num_arch", errno=errno.ENOENT)

            response.contents.id = request.contents.id
            response.contents.error = 0
            response.contents.val = 0
            response.contents.flags = 0

            with change_mount_namespace(request.contents.pid):
                handlers[syscall](syscall, request.contents, response.contents)

            r = libseccomp.seccomp_notify_respond(seccomp_notify_fd, response)
            if r < 0:
                oserror("seccomp_notify_respond", errno=r)
    except KeyboardInterrupt:
        pass
    finally:
        libseccomp.seccomp_notify_free(request, response)
