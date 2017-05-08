#!/usr/bin/env python2.7
try:
    import json, argparse, urllib, urllib2, boto3, requests, ast, certifi, sys
    from json import dumps, loads, dump, load
    from elasticsearch import Elasticsearch, RequestsHttpConnection, serializer, compat, exceptions
    from requests_aws4auth import AWS4Auth
    from csv import reader
except Exception as e:
    print '\t', e
    exit()

elastic_cloud_endpoint = '<>'
elastic_cloud_username = '<>'
elastic_cloud_password = '<>'

# 1st Attribution: http://stackoverflow.com/questions/38209061/django-elasticsearch-aws-httplib-unicodedecodeerror/38371830
# 2nd Attribution: https://docs.python.org/2/library/json.html#basic-usage
class JSONSerializerPython2(serializer.JSONSerializer):
    def dumps(self, data):
        if isinstance(data, compat.string_types): return data
        try: return dumps(data, default=self.default, ensure_ascii=True)
        except (ValueError, TypeError) as e: raise exceptions.SerializationError(data, e)

es = Elasticsearch(
    [elastic_cloud_endpoint],
    port=9243,
    http_auth=elastic_cloud_username + ":" + elastic_cloud_password,
    serializer=JSONSerializerPython2(),
    ca_certs=certifi.where()
)


# Running function
def read(stream):
    for line in stream:
        doc = {}
        try:
            line = list(reader([line]))
            doc["SHA-1"] = line[0][0].strip('"')
            doc["MD5"] = line[0][1].strip('"')
            doc["CRC32"] = line[0][2].strip('"')
            doc["FileName"] = line[0][3].strip('"')
            doc["FileSize"] = int(line[0][4])
            doc["ProductCode"] = int(line[0][5])
            doc["OpSystemCode"] = line[0][6].strip('"')
            doc["SpecialCode"] = line[0][7].rstrip().strip('"')
            es.index(index="rds", doc_type='rds', id=hash(frozenset(doc.items())), body=doc)
        except Exception as e:
            print e
            print line

def main(): read(sys.stdin)

if __name__ == "__main__":
    main()
