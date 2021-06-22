import requests
import hashlib
import sys

# By requesting the data based on just a sample, the actual search is then being done locally, without sending your hash away. 'Key anonymity'.
# Requesting data based on the first five characters of the SHA1 has of the input password.
# API provided by the course instructor.
def request_api_data(firstFive):
    url = 'https://api.pwnedpasswords.com/range/' + firstFive
    response1 = requests.get(url)
    if response1.status_code != 200:
        raise RuntimeError(f'Error fetching: {response1.status_code}, check the api and try again')
    return response1

# Adjusting the response for looping, foolipg the response for matching SHA1 hashes.
def get_password_breach_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

# Hashing, splitting the password and calling foredefined fucntions.
def breached_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5char, tail = sha1password[:5], sha1password[5:]
    response2 = request_api_data(first5char)
    return get_password_breach_count(response2, tail)

# Main function, passing in any number of passwords via terminal, hence sys
def main(args):
    for password in args:
        count = breached_api_check(password)
        if count:
            print(f'Password {password} was found {count} times.')
        else:
            print(f'Password {password} was NOT found.')
    return 'Done.'

# Passing in the sys.argvs.
if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))

