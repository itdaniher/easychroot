import os
import sys
from pychroot import Chroot

user_name = os.environ.get('SUDO_USER') or os.environ['USER']
user_shell = os.environ['SHELL']
if '--root' in sys.argv:
    user_home = '/root'
else:
    user_home = os.environ['HOME']
chroot_path = sys.argv[1]

env = dict(LD_LIBRARY_PATH="/lib:/usr/lib:/usr/local/lib", PYTHONDONTWRITEBYTECODE="1", LC_ALL="C.UTF-8",
           LANG="C.UTF-8", TERM="xterm-256color", HOME=user_home, PATH="/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin")

if '--no_ro' not in sys.argv:
    readonlys = '/etc/shadow /etc/shadow- /etc/sudoers /etc/passwd /etc/group /etc/group- /etc/hosts /etc/fstab'.split()
else:
    readonlys = []
if '--no_home' not in sys.argv:
    mounts = {user_home: {'recursive': True}, '/tmp': {}}
else:
    mounts = {'/tmp': {}}

for ro in readonlys:
    mounts[ro] = {'readonly': True}

if len(sys.argv) > 1:
    for arg in sys.argv[2::]:
        if arg[0] != '-':
            mounts[arg] = {}

passwd_entry = [user_line for user_line in open('/etc/passwd', 'r').read().split('\n')
                if user_name == user_line.split(':', maxsplit=1)[0]][0]

user_name, *_, login_home, login_shell = passwd_entry.split(':')

init_user = os.getuid()

with Chroot(chroot_path, mountpoints=mounts):
    env["CHROOT"] = "_" + os.path.basename(chroot_path.strip('/'))
    os.environ = env
    os.chdir(user_home)
    user_shell = {True: user_shell,
                  False: '/bin/sh'}[os.path.exists(user_shell)]
    if init_user != 1000 and os.path.exists(login_shell) and '--root' not in sys.argv:
        print("have privilege and valid login_shell, no --root flag - su'ing to original user")
        os.execve('/bin/su', ('/bin/su', user_name), os.environ)
    else:
        print("dropping to root shell: execve'ing %s" % user_shell)
        os.execve(user_shell, (user_shell,), os.environ)
