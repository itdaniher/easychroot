import os
import sys
from pychroot import Chroot

user_name = os.environ.get('SUDO_USER') or os.environ['USER']
user_shell = os.environ['SHELL']
user_home = os.environ['HOME']
chroot_path = sys.argv[1]

env = dict(LD_LIBRARY_PATH="/lib:/usr/lib:/usr/local/lib", PYTHONDONTWRITEBYTECODE="1", LC_ALL="en_US.UTF-8", TERM="xterm-256color", HOME=user_home, PATH="/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin", CHROOT="32b")

readonlys = '/etc/shadow /etc/shadow- /etc/sudoers /etc/passwd /etc/group /etc/group-'.split()
mounts = {user_home: {'recursive':True}}
for ro in readonlys:
    mounts[ro] = {'readonly': True}

user_name, *_, login_home, login_shell  = [user_line for user_line in open('/etc/passwd','r').read().split('\n') if user_name == user_line.split(':', maxsplit=1)[0]][0].split(':')


init_user = os.getuid()
with Chroot(chroot_path, mountpoints=mounts):
    os.environ = env
    os.chdir(user_home)
    user_shell = {True: user_shell, False: '/bin/bash'}[os.path.exists(user_shell)]
    if init_user != 1000 and os.path.exists(login_shell):
        print("have privilege and valid login_shell, su'ing to original user")
        os.execve('/bin/su', ('/bin/su', user_name), os.environ)
    else:
        print("dropping to root shell: execve'ing %s" % user_shell)
        os.execve(user_shell, (user_shell,), os.environ)
