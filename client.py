try:
    import os, sys, json, argparse, urllib, urllib2, boto3, requests
    from math import ceil
    from threading import Thread
    from time import time, sleep
    from datetime import datetime
    from hashlib import sha1
    from subprocess import check_output
except Exception as e:
    print '\t', e
    exit()

# Extensions to look at - Note these are executables or may contain executable code that Windows treat as executable
extensions = ('.dll', '.exe', '.pif', '.application', '.gadget', '.msi', '.com', '.scr', '.hta', '.cpl', '.msc', '.jar', '.py')

endpoint = '<>'

def get_digest(path):
    digest = sha1()
    with open(path, 'rb') as f:
        while True:
            data_32 = f.read(32768) # 32KB segment reads (for large files)
            if not data_32: break
            digest.update(data_32)
    return digest.hexdigest().upper()

def get_digests(path, email):
    '''Limits to first 2000 Hashes for now.'''
    global extensions
    digests = {}
    count = 0
    for root, dirs, files in os.walk(path):
        for f in files:
            if f.lower().endswith(extensions):
                digest = get_digest(os.path.join(root, f))
                if digest not in digests:
                    digests[digest] = []
                    digests[digest].append(os.path.join(root, f))
                else: digests[get_digest(os.path.join(root, f))].append(os.path.join(root, f))
            count += 1
            if count >= 2000: break
        if count >= 2000: break
    requests.post(endpoint, data=json.dumps({'data': digests, 'email': email}))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--email", help="Your email address to receive SNS notification", required=True)
    parser.add_argument("-p", "--path", help="Path to scan", required=True)
    args = parser.parse_args()
    get_digests(args.path, args.email)

if __name__ == '__main__':
    main()
