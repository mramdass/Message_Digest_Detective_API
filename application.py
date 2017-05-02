#!/usr/bin/env python2.7
'''
    Munieshwar (Kevin) Ramdass
    Professor Sambit Sahu
    CS-GY 9223 - Cloud Computing
    31 March 2017

    Message Digest Detective
'''

try:
    import os, sys, json, argparse, urllib, urllib2, requests, certifi, multiprocessing, boto3
    from flask import Flask, render_template, abort, request, redirect, jsonify, url_for
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
except Exception as e:
    print e
    exit(1)

application = Flask(__name__)

# Elastic Cloud Credentials
elastic_cloud_endpoint = 'https://2d0242d7f9f24454edb6f8e2e0f6e10c.us-east-1.aws.found.io'
elastic_cloud_username = 'elastic'
elastic_cloud_password = 'op9044rR4zh9seNFBj2E8630'

# VirusTotal URL for reviewing hashes
vt_url = 'https://www.virustotal.com/vtapi/v2/file/report'
vt_api_key = 'dff56d4665c68c503ce39982fedafa1ca1eab99dbc5e356576f8a47156b73a38'

AWSAccessKeyId = "<>"
AWSSecretKey = "<>"
session = boto3.Session(aws_access_key_id=AWSAccessKeyId, aws_secret_access_key=AWSSecretKey, region_name='us-east-1')
sqs = session.resource('sqs')
q = sqs.get_queue_by_name(QueueName='rds')
print q.url

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

@application.route('/')
def index(): return render_template('index.html')

@application.route('/', methods=['GET', 'POST'])
def batch():
    global es
    try:
        if request.method == 'POST':
            body = loads(request.get_data())
            if 'query' in body: return dumps(es.search(index="rds", body=body))
            body = {
                'data': {'DataType': 'String', 'StringValue': str(body['data'])},
                'contact': {'DataType': 'String', 'StringValue': body['contact']}
            }
            q.send_message(MessageBody="A batch", MessageAttributes=body)
    except Exception as e:
        print 'Error:', e
    return 'OK'

def is_md5_or_sha1(string):
    if len(string) not in [32, 40]: return False
    try: integer = int(string, 16)
    except ValueError: return False
    return True

def virtustotal_call(digest):
    global vt_api_key, vt_url
    if not is_md5_or_sha1(digest): return False
    parameters = {'resource': digest, 'apikey': vt_api_key}
    try:
        data = urllib.urlencode(parameters)
        req = urllib2.Request(vt_url, data)
        response = urllib2.urlopen(req)
        return json.loads(response.read())
    except Exception as e:
        print e

@application.route('/result', methods=['POST'])
def digest():
    global es
    fields = ['SHA-1', 'ProductCode', 'OpSystemCode', 'SpecialCode', 'FileName', 'FileSize', 'CRC32', 'MD5']
    keyword = request.form['words']
    specifics = {
        "query": {
            "multi_match": {
                "query": keyword,
                "fields": fields,
                "lenient": True  # Allows checks with integer fields
            }
        },
        "size": 150
    }
    res = es.search(index="rds", body=specifics)
    x = {
        "ProductCode": ['ProductCode'],
        "SHA-1": ['SHA-1'],
        "OpSystemCode": ['OpSystemCode'],
        "SpecialCode": ['SpecicalCode'],
        "FileName": ['FileName'],
        "FileSize": ['FileSize'],
        "CRC32": ['CRC32'],
        "MD5": ['MD5']
    }
    if 'hits' in res:
        if 'hits' in res['hits']:
            if res['hits']['total'] == 0:
                if not is_md5_or_sha1(keyword):
                    x = {'Search': ['Search', keyword], 'State': ['State', 'Unknown']}
                    x = zip(x['Search'], x['State'])
                else:
                    print 'Redirecting to VirusTotal'
                    try:
                        link = virtustotal_call(keyword)['permalink']
                        return redirect(link)
                    except Exception as e:
                        print e
                    return redirect('https://www.virustotal.com')
            else:
                for hit in res['hits']['hits']:
                    x['ProductCode'].append(hit['_source']['ProductCode'])
                    x['SHA-1'].append(hit['_source']['SHA-1'])
                    x['OpSystemCode'].append(hit['_source']['OpSystemCode'])
                    x['SpecialCode'].append(hit['_source']['SpecialCode'])
                    x['FileName'].append(hit['_source']['FileName'])
                    x['FileSize'].append(hit['_source']['FileSize'])
                    x['CRC32'].append(hit['_source']['CRC32'])
                    x['MD5'].append(hit['_source']['MD5'])
                x = zip(x['SHA-1'], x['MD5'], x['FileName'], x['ProductCode'], x['OpSystemCode'], x['SpecialCode'], x['FileSize'], x['CRC32'])
    return render_template('result.html', result=x)

@application.route('/select_prod/<string:code>', methods=['GET', 'POST'])
def details_prod(code):
    global es
    #post = request.args.get('post', 0, type=str)
    #print post

    code = int(code)
    res = es.search(index="prod", body={"query": {"match": {"ProductCode": code}}, "size": 150})
    x = {
        "ProductCode": ['ProductCode'],
        "ProductName": ['ProductName'],
        "ProductVersion": ['ProductVersion'],
        "OpSystemCode": ['OpSystemCode'],
        "MfgCode": ['MfgCode'],
        "Language": ['Language'],
        "ApplicationType": ['ApplicationType']
    }
    if 'hits' in res:
        if 'hits' in res['hits']:
            for hit in res['hits']['hits']:
                x['ProductCode'].append(hit['_source']['ProductCode'])
                x['ProductName'].append(hit['_source']['ProductName'])
                x['ProductVersion'].append(hit['_source']['ProductVersion'])
                x['OpSystemCode'].append(hit['_source']['OpSystemCode'])
                x['MfgCode'].append(hit['_source']['MfgCode'])
                x['Language'].append(hit['_source']['Language'])
                x['ApplicationType'].append(hit['_source']['ApplicationType'])
            x = zip(x['ProductCode'], x['ProductName'], x['ProductVersion'], x['OpSystemCode'], x['MfgCode'], x['Language'], x['ApplicationType'])
    return render_template('prod.html', result=x)

@application.route('/select_os/<string:code>', methods=['GET', 'POST'])
def details_os(code):
    global es
    #post = request.args.get('post', 0, type=str)
    #print post

    res = es.search(index="os", body={"query": {"match": {"OpSystemCode": code}}, "size": 150})
    x = {
        "OpSystemCode": ['OpSystemCode'],  # NSRL RDS has this as an integer
        "OpSystemName": ['OpSystemName'],
        "OpSystemVersion": ['OpSystemVersion'],
        "MfgCode": ['MfgCode']
    }
    if 'hits' in res:
        if 'hits' in res['hits']:
            for hit in res['hits']['hits']:
                x['OpSystemCode'].append(hit['_source']['OpSystemCode'])
                x['OpSystemName'].append(hit['_source']['OpSystemName'])
                x['OpSystemVersion'].append(hit['_source']['OpSystemVersion'])
                x['MfgCode'].append(hit['_source']['MfgCode'])
            x = zip(x['OpSystemCode'], x['OpSystemName'], x['OpSystemVersion'], x['MfgCode'])
    return render_template('os.html', result=x)

@application.route('/select_mfg/<string:code>', methods=['GET', 'POST'])
def details_mfg(code):
    global es
    #post = request.args.get('post', 0, type=str)
    #print post

    res = es.search(index="mfg", body={"query": {"match": {"MfgCode": code}}, "size": 150})
    x = {
        "MfgCode": ['MfgCode'],
        "MfgName": ['MfgName']
    }
    if 'hits' in res:
        if 'hits' in res['hits']:
            for hit in res['hits']['hits']:
                x['MfgCode'].append(hit['_source']['MfgCode'])
                x['MfgName'].append(hit['_source']['MfgName'])
            x = zip(x['MfgCode'], x['MfgName'])
    return render_template('mfg.html', result=x)

@application.errorhandler(404)
def page_not_found(e): return render_template('404.html'), 404



def return_json(data):
    # Create SNS topic and push data there
    return jsonify(results=data)

if __name__ == '__main__':
    application.run()
