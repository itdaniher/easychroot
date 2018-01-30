import os
import sys
from pychroot import Chroot

user_name = os.environ.get('SUDO_USER') or os.environ['USER']
user_shell = os.environ['SHELL']
user_home = os.environ['HOME']
chroot_path = sys.argv[1]

env = dict(LD_LIBRARY_PATH="/lib:/usr/lib:/usr/local/lib", PYTHONDONTWRITEBYTECODE="1", LC_ALL="en_US.UTF-8", TERM="xterm-256color", HOME=user_home, PATH="/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin", CHROOT="32b")

readonlys = '/etc/shadow /etc/shadow- /etc/sudoers /etc/passwd /etc/group /etc/group-'.split()
mounts ={user_home: {'recursive':True}}
for ro in readonlys:
    mounts[ro] = {'readonly': True}

init_user = os.getuid()
with Chroot(chroot_path, mountpoints=mounts):
    os.environ = env
    os.chdir(user_home)
    if init_user != 1000:
        os.execve('/bin/su', ('/bin/su', user_name), os.environ)
    else:
        os.execve(user_shell, (user_shell,), os.environ)
