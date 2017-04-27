try:
    import os, sys, json, argparse, urllib, urllib2, requests, certifi, multiprocessing
    from multiprocessing import Pool, Value, Lock
    from csv import reader
    from math import ceil
    from time import time, sleep
    from zipfile import ZipFile
    from hashlib import sha1
    from subprocess import check_output
    from json import dumps, loads, load, dump
    from itertools import islice, chain
    from datetime import datetime
    from elasticsearch import Elasticsearch, RequestsHttpConnection, serializer, compat, exceptions
except Exception as e: print e

rds_path = 'C:\\Users\\mramd\\Documents\\CS-GY 9223 - Cloud Computing\\Project\\Materials\\NSRLFile.txt.zip'
rds_name = 'NSRLFile.txt'
mfg_path = 'C:\\Users\\mramd\\Documents\\CS-GY 9223 - Cloud Computing\\Project\\Materials\\NSRLMfg.txt'
os_path = 'C:\\Users\\mramd\\Documents\\CS-GY 9223 - Cloud Computing\\Project\\Materials\\NSRLOS.txt'
prod_path = 'C:\\Users\\mramd\\Documents\\CS-GY 9223 - Cloud Computing\\Project\\Materials\\NSRLProd.txt'

# Elastic Cloud Credentials
elastic_cloud_endpoint = 'https://2d0242d7f9f24454edb6f8e2e0f6e10c.us-east-1.aws.found.io'
elastic_cloud_username = 'elastic'
elastic_cloud_password = 'op9044rR4zh9seNFBj2E8630'

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

#es.indices.delete(index='rds', ignore=[400, 404])
#es.indices.delete(index='prod', ignore=[400, 404])
#es.indices.delete(index='os', ignore=[400, 404])
#es.indices.delete(index='mfg', ignore=[400, 404])

es.indices.create(index='rds', body=mapping, ignore=400)
es.indices.create(index='prod', body=mapping_prod, ignore=400)
es.indices.create(index='os', body=mapping_os, ignore=400)
es.indices.create(index='mfg', body=mapping_mfg, ignore=400)

id = Value('i', 1)
lock = Lock()

def initializer(*args):
    global id, lock
    id, lock = args

def process(line):
    global id, lock, es
    with lock:
        id.value += 1
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
        es.index(index="rds", doc_type='rds', id=id.value - 1, body=doc)
    except Exception as e:
        print e
        print line

def upload_details():
    global prod_path, os_path, mfg_path, es
    with open(prod_path, 'r') as p:
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
    with open(os_path, 'r') as o:
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
    with open(mfg_path, 'r') as m:
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

if __name__ == '__main__':
    #upload_details()
    #exit(0)
    with ZipFile(rds_path) as zf:
        with zf.open(rds_name, mode='r') as f:
            next(f)
            while True:
                try:
                    lines = islice(f, 5000000)
                    if id.value == 104318303: break
                    pool = Pool(8, initializer, (id, lock))
                    pool.map(process, lines)
                    print 'ID:', id.value
                except Exception as e:
                    print e

'''
specifics = {"query": {"match": {"SHA-1":"00BDDBD88ED400EA7EA1C165EB5E7343A9119A29"}}}
es.search(index="rds", body=specifics)

{
  "took": 6,
  "timed_out": false,
  "_shards": {
    "total": 9,
    "successful": 9,
    "failed": 0
  },
  "hits": {
    "total": 2,
    "max_score": 10.459803,
    "hits": [
      {
        "_index": "rds",
        "_type": "rds",
        "_id": "289",
        "_score": 10.459803,
        "_source": {
          "ProductCode": 10791,
          "SHA-1": "00BDDBD88ED400EA7EA1C165EB5E7343A9119A29",
          "OpSystemCode": "358",
          "SpecialCode": "",
          "FileName": "idct_mmi.c",
          "FileSize": 10793,
          "CRC32": "6692D1E1",
          "MD5": "082E4269176E0A5C29B2EC143E284AA4"
        }
      },
      {
        "_index": "rds",
        "_type": "rds",
        "_id": "295",
        "_score": 10.455494,
        "_source": {
          "ProductCode": 14557,
          "SHA-1": "00BDDBD88ED400EA7EA1C165EB5E7343A9119A29",
          "OpSystemCode": "358",
          "SpecialCode": "",
          "FileName": "idct_mmi.c",
          "FileSize": 10793,
          "CRC32": "6692D1E1",
          "MD5": "082E4269176E0A5C29B2EC143E284AA4"
        }
      }
    ]
  }
}

# Result
{% for key, value in result.iteritems() %}
           <tr>
                <th> {{ key }} </th>
                <td> {{ value }} </td>
           </tr>
        {% endfor %}

<td><a id="prod_code" href="{{ url_for('find_question',question_id=3) }}" onclick="send_prod( {{ row[3] }} )">{{ row[3] }}</a></td>
<td><a id="op_code" href="{{ url_for('find_question',question_id=4) }}" onclick="send_os( {{ row[4] }} )">{{ row[4] }}</a></td>
#//Don't need the onclick
@application.route('/find_question/<int:question_id>', methods=['GET', 'POST'])  #int has been used as a filter that only integer will be passed in the url otherwise it will give a 404 error
def find_question(question_id):
    return ('you asked for question{0}'.format(question_id))
'''
