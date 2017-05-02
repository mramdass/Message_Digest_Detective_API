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

def get_digests(path, sns):
    '''Limits to first 2000 Hashes for now.'''
    global extensions, endpoint
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
    if digests == {}:
        print 'No files found during scan'
        return
    requests.post(endpoint, data=json.dumps({'data': digests, 'contact': '+1' + sns}))

def query_es(query_string):
    hits = []
    for i in requests.post(endpoint, data=json.dumps({"query":{"query_string":{"query":query_string}},"size":5})).json()['hits']['hits']:
        hits.append(i['_source'])
    return hits

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--sns", help="Your phone number to receive SNS notification: 1112223333", required=False)
    parser.add_argument("-p", "--path", help="Path to scan", required=False)

    parser.add_argument("-a", "--sha1", help="SHA-1 Hash", required=False)
    parser.add_argument("-b", "--prodcode", help="Product Code", required=False)
    parser.add_argument("-c", "--opsystemcode", help="Operating System Code", required=False)
    parser.add_argument("-d", "--specialcode", help="Special Code", required=False)
    parser.add_argument("-e", "--filename", help="File Name", required=False)
    parser.add_argument("-f", "--filesize", help="File Size", required=False)
    parser.add_argument("-g", "--crc32", help="CRC32", required=False)
    parser.add_argument("-i", "--md5", help="MD5 Hash", required=False)

    args = parser.parse_args()
    if args.sns and args.path: get_digests(args.path, args.sns)

    query_array = []
    query_string = '('
    if args.sha1: query_array.append('SHA-1:' + args.sha1)
    if args.prodcode: query_array.append('ProductCode:' + args.prodcode)
    if args.opsystemcode: query_array.append('OpSystemCode:' + args.opsystemcode)
    if args.specialcode: query_array.append('SpecialCode:' + args.specialcode)
    if args.filename: query_array.append('FileName:' + args.filename)
    if args.filesize: query_array.append('FileSize:' + args.filesize)
    if args.crc32: query_array.append('CRC32:' + args.crc32)
    if args.md5: query_array.append('MD5:' + args.md5)
    length = len(query_array)
    for i in range(0, length):
        if i + 1 == length: query_string += query_array[i]
        else: query_string += query_array[i] + ' AND '
    query_string += ')'

    if args.sha1 or args.prodcode or args.opsystemcode or args.specialcode or args.filename or args.filesize or args.crc32 or args.md5:
        print json.dumps(query_es(query_string), indent=4, sort_keys=True)



if __name__ == '__main__':
    main()
