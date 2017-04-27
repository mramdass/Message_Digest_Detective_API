#!/usr/bin/env python2.7
'''
    Munieshwar (Kevin) Ramdass
    Professor Sambit Sahu
    CS-GY 9223 - Cloud Computing
    31 March 2017

    Message Digest Detective
'''

try:
    import os, sys, json, argparse, urllib, urllib2, requests, certifi, multiprocessing
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
elastic_cloud_endpoint = ''
elastic_cloud_username = ''
elastic_cloud_password = ''

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

'''
@application.route('/result', methods=['POST'])
def digest(): return render_template('result.html', result={'8f7fhr7fhr8fjgndksnf7dnfmcbdmfhd': 'Benign',\
                                                            '9fbdjd7fhndjsjsc5cbfnfjdjf5fhndm': 'Malicious',\
                                                            '8f7fhgcht5hgh87jhv78jhnfmcbdmfhd': 'Benign',\
                                                            '5gfchgvhkbkkj87jhv78jhnfmcbdmfhd': 'Benign',\
                                                            '5gfchgvhhhgct8h98hkk9fdfmcbdmfhd': 'Benign'})
'''

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
        }
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
            if len(res['hits']['hits']) == 0:
                x = {'Search': ['Search', keyword], 'State': ['State', 'Unknown']}
                x = zip(x['Search'], x['State'])
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
        else:
            x = {'Search': ['Search', keyword], 'State': ['State', 'Unknown']}
            x = zip(x['Search'], x['State'])
    else:
        x = {'Search': ['Search', keyword], 'State': ['State', 'Unknown']}
        x = zip(x['Search'], x['State'])
    return render_template('result.html', result=x)

@application.route('/select_prod', methods=['GET', 'POST'])
def details_prod():
    print 'receiving prod'
    post = request.args.get('post', 0, type=str)
    print post
    return redirect(url_for('index'))

@application.route('/select_os', methods=['GET', 'POST'])
def details_os():
    print 'receiving os'
    post = request.args.get('post', 0, type=str)
    print post
    return redirect(url_for('index'))

@application.errorhandler(404)
def page_not_found(e): return render_template('404.html'), 404



def return_json(data):
    # Create SNS topic and push data there
    return jsonify(results=data)

if __name__ == '__main__':
    application.run()
