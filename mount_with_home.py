#!/usr/bin/python3

__doc__ = f"""{__file__}:

Usage:
  {__file__} CHROOT_PATH [options] [ADDITIONAL_VOLUMES...]
  {__file__} --help
  {__file__} --version

Options:
  --help        Show this screen.
  --version     Show version.
  --root        Don't drop privs to executing user, maintain root permissions in chroot.
  --no_ro       Don't bind-mount readonly files necessary for consistent environment usage, like /etc/password or /etc/hosts. (implies --root)
  --use_home=x  Use the specified directory as the chroot user's home directory.
  --share_home  Use the executing user's home directory as the chroot user's home directory.

"""
from docopt import docopt

import os
import sys
from pychroot import Chroot

arguments = docopt(__doc__, version="easychroot v0.1")
user_name = os.environ.get("SUDO_USER") or os.environ["USER"]
user_shell = os.environ["SHELL"]

if arguments.get("--root"):
    user_home = "/root"
else:
    user_home = os.environ["HOME"]

chroot_path = arguments.get("CHROOT_PATH")

passwd_entry = [user_line for user_line in open("/etc/passwd", "r").read().split("\n") if user_name == user_line.split(":", maxsplit=1)[0]][0]

user_name, _, uid, gid, *_, login_home, login_shell = passwd_entry.split(":")

init_user = os.getuid()
mounts = {"/tmp": {}}
bind_user_confs = False
if not arguments.get("--no_ro"):
    readonlys = "/etc/shadow /etc/shadow- /etc/sudoers /etc/passwd /etc/group /etc/group- /etc/hosts /etc/fstab".split()
    bind_user_confs = True
else:
    readonlys = []
    user_name = "root"
    user_home = "/root"


if arguments.get("--share_home"):
    mounts[user_home] = {"recursive": True}
    bind_user_confs = False
elif arguments.get("--use_home"):
    temp_home = arguments.get("--use_home")
    mounts[f"{temp_home}:{user_home}"] = {}
else:
    temp_home = f"/tmp{user_home}"
    if not os.path.exists(temp_home):
        os.makedirs(temp_home)
    mounts[f"{temp_home}:{user_home}"] = {}
    uid_, gid_ = int(uid), int(gid)
    os.chown(temp_home, uid_, gid_)
    for root, dirs, files in os.walk(temp_home):
        for name in dirs + files:
            os.chown(os.path.join(root, name), uid_, gid_)

if bind_user_confs and (login_shell == "/bin/zsh"):
    mounts[f"{user_home}/.zshrc"] = {"readonly": True, "optional": True, "create": True}
    mounts[f"{user_home}/.zfunctions"] = {"readonly": True, "optional": True, "create": True}

for ro in readonlys:
    mounts[ro] = {"readonly": True}

for volume in arguments.get("ADDITIONAL_VOLUMES"):
    mounts[volume] = {}

env = dict(
    LD_LIBRARY_PATH="/lib:/usr/lib:/usr/local/lib",
    PYTHONDONTWRITEBYTECODE="1",
    LC_ALL="C.UTF-8",
    LANG="C.UTF-8",
    TERM="xterm-256color",
    HOME=user_home,
    PATH="/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin",
)

with Chroot(chroot_path, mountpoints=mounts):
    env["CHROOT"] = "_" + os.path.basename(chroot_path.strip("/"))
    os.environ = env
    os.chdir(user_home)
    user_shell = {True: user_shell, False: "/bin/sh"}[os.path.exists(user_shell)]
    if init_user != 1000 and os.path.exists(login_shell) and not arguments.get("--root"):
        print("have privilege and valid login_shell, no --root flag - su'ing to original user")
        os.execve("/bin/su", ("/bin/su", user_name), os.environ)
    else:
        print("dropping to root shell: execve'ing %s" % user_shell)
        os.execve(user_shell, (user_shell,), os.environ)
