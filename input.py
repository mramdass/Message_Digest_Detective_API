try:
    import os, sys, json, argparse, urllib, urllib2, requests, certifi
    from csv import reader
    from zipfile import ZipFile
    from json import dumps, loads, load, dump
    from elasticsearch import Elasticsearch, RequestsHttpConnection, serializer, compat, exceptions
    from elasticsearch.helpers import bulk
    from requests_aws4auth import AWS4Auth
except Exception as e: print e

zip_name = 'NSRLFile.txt.zip'
rds_name = 'NSRLFile.txt'
mfg_name = 'NSRLMfg.txt'
os_name = 'NSRLOS.txt'
prod_name = 'NSRLProd.txt'

# AWS ElasticSearch Credentials
AWSAccessKeyId = ""
AWSSecretKey = ""

aws_es_endpoint = ''
aws_es_port = 443

auth = AWS4Auth(AWSAccessKeyId, AWSSecretKey, 'us-east-1', 'es')

# 1st Attribution: http://stackoverflow.com/questions/38209061/django-elasticsearch-aws-httplib-unicodedecodeerror/38371830
# 2nd Attribution: https://docs.python.org/2/library/json.html#basic-usage
class JSONSerializerPython2(serializer.JSONSerializer):
    def dumps(self, data):
        if isinstance(data, compat.string_types): return data
        try: return dumps(data, default=self.default, ensure_ascii=True)
        except (ValueError, TypeError) as e: raise exceptions.SerializationError(data, e)

es = Elasticsearch(
    hosts=[{'host': aws_es_endpoint, 'port': aws_es_port}],
    use_ssl=True,
    http_auth=auth,
    verify_certs=True,
    connection_class=RequestsHttpConnection,
    serializer=JSONSerializerPython2()
)

mapping = {
    "SHA-1": {"type": "string"},
    "MD5": {"type": "string"},
    "CRC32": {"type": "string"},
    "FileName": {"type": "string"},
    "FileSize": {"type": "integer"},
    "ProductCode": {"type": "integer"},
    "OpSystemCode": {"type": "integer"},
    "SpecialCode": {"type": "string"}
}

mapping_prod = {
    "ProductCode": {"type": "integer"},
    "ProductName": {"type": "string"},
    "ProductVersion": {"type": "string"},
    "OpSystemCode": {"type": "string"},
    "MfgCode": {"type": "string"},
    "Language": {"type": "string"},
    "ApplicationType": {"type": "string"}
}

mapping_os = {
    "OpSystemCode": {"type": "string"},  # NSRL RDS has this as an integer
    "OpSystemName": {"type": "string"},
    "OpSystemVersion": {"type": "string"},
    "MfgCode": {"type": "string"}
}

mapping_mfg = {
    "MfgCode": {"type": "string"},
    "MfgName": {"type": "string"}
}

es.indices.create(index='rds', body=mapping, ignore=400)
es.indices.create(index='prod', body=mapping_prod, ignore=400)
es.indices.create(index='os', body=mapping_os, ignore=400)
es.indices.create(index='mfg', body=mapping_mfg, ignore=400)

def upload_details(directory):
    global prod_name, os_name, mfg_name, es
    with open(directory + '/' + prod_name, 'r') as p:
        count = 1
        next(p)
        for line in reader(p):
            try:
                data = {
                    "ProductCode": int(line[0]),
                    "ProductName": line[1],
                    "ProductVersion": line[2],
                    "OpSystemCode": line[3],
                    "MfgCode": line[4],
                    "Language": line[5],
                    "ApplicationType": line[6].rstrip()
                }
                es.index(index="prod", doc_type='rds', id=count, body=data)
                count += 1
            except Exception as e:
                print e
                print line
    with open(directory + '/' + os_name, 'r') as o:
        count = 1
        next(o)
        for line in reader(o):
            try:
                data = {
                    "OpSystemCode": line[0],
                    "OpSystemName": line[1],
                    "OpSystemVersion": line[2],
                    "MfgCode": line[3].rstrip()
                }
                es.index(index="os", doc_type='rds', id=count, body=data)
                count += 1
            except Exception as e:
                print e
                print line
    with open(directory + '/' + mfg_name, 'r') as m:
        count = 1
        next(m)
        for line in reader(m):
            try:
                data = {
                    "MfgCode": line[0],
                    "MfgName": line[1].rstrip()
                }
                es.index(index="mfg", doc_type='rds', id=count, body=data)
                count += 1
            except Exception as e:
                print e
                print line

def update_rds(update, md5, productcode, opsystemcode, specialcode, filename, allocation, crc32):
    global es
    try:
        doc = {
            "SHA-1": update,
            "MD5": md5,
            "CRC32": crc32,
            "FileName": filename,
            "FileSize": allocation,
            "ProductCode": int(productcode),
            "OpSystemCode": int(opsystemcode),
            "SpecialCode": specialcode
        }
        es.index(index="rds", doc_type='rds', id=str(doc), body=doc)
    except Exception as e:
        print e

def delete_rds():
    global id, es
    id.value = 0
    es.indices.delete(index='rds', ignore=[400, 404])
    es.indices.delete(index='prod', ignore=[400, 404])
    es.indices.delete(index='os', ignore=[400, 404])
    es.indices.delete(index='mfg', ignore=[400, 404])

def set_data(input_file, index_name="rds", doc_type_name="rds"):
    with ZipFile(input_file + '/' + zip_name) as zf:
        with zf.open(rds_name, mode='r') as f:
            next(f)
            for line in reader(f):
                doc = {}
                try:
                    doc["SHA-1"] = line[0].strip('"')
                    doc["MD5"] = line[1].strip('"')
                    doc["CRC32"] = line[2].strip('"')
                    doc["FileName"] = line[3].strip('"').decode('unicode_escape').encode('ascii','ignore')
                    doc["FileSize"] = int(line[4])
                    doc["ProductCode"] = int(line[5])
                    doc["OpSystemCode"] = line[6].strip('"')
                    doc["SpecialCode"] = line[7].rstrip().strip('"')
                    yield {
                        "_index": index_name,
                        "_type": doc_type_name,
                        "_source": doc
                    }
                except Exception as e:
                    print e
                    print line
                    doc["SHA-1"] = line[0].strip('"')
                    doc["MD5"] = line[1].strip('"')
                    doc["CRC32"] = ''
                    doc["FileName"] = ''
                    doc["FileSize"] = -1
                    doc["ProductCode"] = -1
                    doc["OpSystemCode"] = ''
                    doc["SpecialCode"] = ''
                    yield {
                        "_index": index_name,
                        "_type": doc_type_name,
                        "_source": doc
                    }

# Attribution: https://github.com/elastic/elasticsearch-py/issues/508
def upload(es, input_file, index_name="rds", doc_type_name="rds"):
    print 'Now Uploading RDS'
    success, _ = bulk(es, set_data(input_file, index_name, doc_type_name))
    print 'Finished Uploading RDS'
    print 'Now Uploading Details'
    upload_details(input_file)
    print 'Finished Uploading Details'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--delete", help="Deletes the RDS and Detail files from server", required=False)
    parser.add_argument("-r", "--rds", help="Path to the directory of the Zipped RDS", required=False)
    parser.add_argument("-u", "--update", help="Enter the SHA-1 Hash to add", required=False)
    parser.add_argument("-m", "--md5", help="Indicate the MD5 Hash", required=False)
    parser.add_argument("-p", "--productcode", help="Indicate the Product Code", required=False)
    parser.add_argument("-o", "--opsystemcode", help="Indicate the Operating System Code", required=False)
    parser.add_argument("-s", "--specialcode", help='Indicate the special code, if none, enter ""', required=False)
    parser.add_argument("-f", "--filename", help="Indicate the file name", required=False)
    parser.add_argument("-a", "--allocation", help="Indicate the file size", required=False)
    parser.add_argument("-c", "--crc32", help="Indicate the CRC32", required=False)
    args = parser.parse_args()

    if args.rds: upload(es, args.rds)
    elif args.rds == None and args.delete == None and (args.update and args.md5 and args.productcode and args.opsystemcode and args.specialcode and args.filename and args.allocation and args.crc32):
        update_rds(args.update, args.md5, args.productcode, args.opsystemcode, args.specialcode, args.filename, args.allocation, args.crc32)
    elif args.delete:
        if args.delete == 'e39d647ca60c6ad7b06aaf460c729c02e7507047': delete_rds()
    else:
        print 'Usage: python input.py -r <path to directory that contains zipped RDS and detail files>\
        \npython input.py -u <sha-1> -m <md5> -p <product code> -o <operation system code> -s <special code> -f <file name> -a <file size> -c <CRC32>'

if __name__ == '__main__':
    main()
