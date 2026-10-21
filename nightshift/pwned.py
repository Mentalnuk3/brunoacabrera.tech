"""
PWNED? - finds out if a password has ever shown up in a data breach.

The trick: we NEVER send the password over the internet.
We send 5 characters of a mathematical fingerprint of it.
That's called k-anonymity. Read step 3 and it clicks.
"""

import hashlib
import urllib.request
from getpass import getpass


def check(password):
    # STEP 1 - turn the password into a SHA-1 hash.
    # A hash is a blender: text goes in, a 40-character code comes out.
    # It's one-way - nobody gets the password back from the code.
    # Change one letter of the password and the whole code changes.
    full_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

    # STEP 2 - split the hash in two.
    prefix = full_hash[:5]    # first 5 chars - THIS is what we send
    suffix = full_hash[5:]    # the other 35 - THIS stays on your machine
    print(f"\n  SHA-1 hash : {full_hash}")
    print(f"  sent       : {prefix}{'*' * 35}")

    # STEP 3 - ask the server for EVERY breached hash starting with that prefix.
    # About 800 come back. The server has no idea which one is ours.
    # It knows we asked something. It doesn't know what we asked.
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    request = urllib.request.Request(url, headers={"User-Agent": "cyber-lab"})
    with urllib.request.urlopen(request, timeout=10) as response:
        body = response.read().decode("utf-8")

    lines = body.splitlines()
    print(f"  received   : {len(lines)} candidate hashes\n")

    # STEP 4 - the comparison happens RIGHT HERE, on our machine.
    for line in lines:
        candidate, count = line.split(":")
        if candidate == suffix:
            return int(count)
    return 0


def main():
    print("=" * 52)
    print("  PWNED?  -  breached password checker")
    print("=" * 52)
    print("\nType a password (it won't show on screen, it won't leave this PC).")
    print("Press Enter on an empty line to quit.\n")

    while True:
        password = getpass("password > ")
        if not password:
            print("\nlater.")
            break

        times = check(password)

        if times:
            print(f"  >>> BREACHED {times:,} times <<<")
            print("  This password is on lists attackers actually use. Change it.")
        else:
            print("  >>> not found in any known breach <<<")
            print("  That doesn't mean it's strong. It means it hasn't leaked yet.")
        print()


if __name__ == "__main__":
    main()
