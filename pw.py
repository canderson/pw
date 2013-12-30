#! /usr/bin/python

import os
import re
import sys
from random import SystemRandom
import subprocess
from pwd import getpwnam
import stat

## CONFIGURE
PATH = os.path.join(os.environ['HOME'], '.passwords/')
SYSTEM_USER = "alice"
IDENTITIES = ["alice@example.org"] # For GPG
##

secure_random = SystemRandom()

def generate_pw(length=20):
    out = []
    for i in range(0,length):
        out.append(chr(secure_random.choice(range(48,96) + range(97,127))))
    return ''.join(out)

def pw_directory_entries(path, extension):
    directory_contents = os.listdir(path)
    found = []
    for name in directory_contents:
        match = re.search("^(.*)%s$" % extension, name)
        if match == None: continue
        found.append(match.group(1))
    return found

def choose_given_existing(user_input, existing_list, allow_unknown=True):
    if user_input in existing_list and user_input != "":
        return user_input
    else:
        # Match to existing entries by inclusion
        matching = filter(lambda site: re.search(user_input, site), existing_list)
        if len(matching) == 1 and user_input != "":
            return user_input
        elif len(matching) == 0 and allow_unknown:
            return user_input

        # Multiple matches or no matches. Give the user another (prompted) opportunity
        print "Please select:"
        if len(matching) != 0:
            options = sorted(matching)
        elif not allow_unknown:
            options = sorted(existing_list)
            if len(options) == 0: return user_input
        if matching: print '\n'.join(options)
        return raw_input("Selected name: ")

def check_permissions(path):
    user_data = getpwnam('christian')
    uid = user_data.pw_uid
    gid = user_data.pw_gid
    directory_data = os.stat(path)
    if directory_data.st_uid != uid: return False
    if directory_data.st_gid != gid: return False
    # Others rwx should be 000
    if directory_data.st_mode & stat.S_IRWXO: return False
    return True

def configure_annex(path):
    if os.path.exists(os.path.join(path, ".git")): return
    os.system("git init %s" % path)
    os.system("git annex init %s" % path)
    return

def parse_input():
    try:
        command = sys.argv[1]
    except IndexError:
        exit("pw command [site [uname]]")
    command = command.lower()

    if command == "s": command = "set"
    elif command == "g": command = "get"

    if command not in ("get","set"):
        exit("valid commands are set and get")

    try:
        user_input_site = sys.argv[2]
    except IndexError:
        user_input_site = ''
        user_input_uname = ''
    else:
        try: user_input_uname = sys.argv[3]
        except IndexError: user_input_uname = ''
    if ' ' in user_input_uname or ' ' in user_input_site:
        exit("no spaces in input please")
    return [command, user_input_site, user_input_uname]

def main():
    command, user_input_site, user_input_uname = parse_input()
    try:
        os.chdir(PATH)
    except OSError:
        exit("Could not find data directory: %s" % PATH)
    if not check_permissions(PATH):
        exit("Bad permissions on data directory: %s." % PATH)
    configure_annex(PATH)

    allow_unknown = (command == "set")
    existing_sites = pw_directory_entries(".", "_pws")
    site = choose_given_existing(user_input_site, existing_sites, allow_unknown)
    print "Using site: %s" % site

    # Do not create site directory yet, because we still might exit
    site_dir = site + "_pws"
    site_dir_exists = False
    if site not in existing_sites:
        if command == "get":
            exit("tried to get password for unknown site")
        existing_unames = []
    else:
        site_dir_exists = True
        os.chdir(site_dir)
        existing_unames = pw_directory_entries(".", ".pw")

    uname = choose_given_existing(user_input_uname, existing_unames, allow_unknown)
    print "Using uname: %s" % uname

    if uname not in existing_unames and command == "get":
        exit("tried to get password for unknown uname")

    uname_file = uname + '.pw'

    if command == "get":
        os.system('gpg --decrypt %s | xclip -i' % uname_file)
        print
    elif command == "set":
        if uname in existing_unames:
            sure = raw_input("Are you sure you want to change the pw [y/N]: ")
            if sure.lower() not in ("y","yes"):
                exit()
            os.system("git annex unlock %s" % uname_file)
            verb = "Updating"
        else:
            verb = "Creating"
        # We do not expect to exit after this.
        # It is safe to start making writes to the filesystem.
        if not site_dir_exists:
            site_dir = site + "_pws"
            os.mkdir(site_dir)
            os.chdir(site_dir)
        pw = raw_input("Enter new password (leave blank for auto): ")
        if not pw: pw = generate_pw()
        subprocess.Popen(
            ["xclip", "-i"],
            stdin=subprocess.PIPE).communicate(input=pw)
        print pw
        output_file = open(uname_file, "w")
        gpg_invocation = ["gpg", "--encrypt"]
        for recipient in IDENTITIES:
            gpg_invocation.extend(["--recipient", recipient])
        gpg_process = subprocess.Popen(
            gpg_invocation,
            stdin=subprocess.PIPE,
            stdout=output_file)
        gpg_process.communicate(input=pw)
        os.system("git annex add %s" % uname_file)
        commit_description = '"' + verb + " " + "password for " + site + ":" + uname + '"'
        os.system("git commit -m %s" % commit_description)
    else:
        # Unknown command
        assert(False)

if __name__ == "__main__":
    main()
