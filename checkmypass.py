import requests
import hashlib
import sys

# Task: Take passwords form a text file..


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    respose = requests.get(url)
    if respose.status_code != 200:
        raise RuntimeError(f'Error Fetching: {respose.status_code}')
    return respose


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # head = first five chars of sha1_password
    # tail = contains remaining chars of sha1_password
    head, tail = sha1_password[:5], sha1_password[5:]
    try:
        res = request_api_data(head)
        return get_password_leaks_count(res, tail)
    except:
        print('No Internet Connection!')


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times!')
        else:
            print(f'{password} was not found. Carry on!')
    return 'Done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
