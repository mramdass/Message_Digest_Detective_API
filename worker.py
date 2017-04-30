#!/usr/bin/env python2.7
try:
    import json, argparse, urllib, urllib2, boto3, requests, ast, certifi
    from json import dumps, loads, dump, load
    from elasticsearch import Elasticsearch, RequestsHttpConnection, serializer, compat, exceptions
    from multiprocessing import Pool
    from time import time, sleep
except Exception as e:
    print '\t', e
    exit()

# Elastic Cloud Credentials
elastic_cloud_endpoint = 'https://2d0242d7f9f24454edb6f8e2e0f6e10c.us-east-1.aws.found.io'
elastic_cloud_username = 'elastic'
elastic_cloud_password = 'op9044rR4zh9seNFBj2E8630'

AWSAccessKeyId = "<>"
AWSSecretKey = "<>"

sns = boto3.client(
    "sns",
    aws_access_key_id=AWSAccessKeyId,
    aws_secret_access_key=AWSSecretKey,
    region_name="us-east-1"
)

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

session = boto3.Session(aws_access_key_id=AWSAccessKeyId, aws_secret_access_key=AWSSecretKey, region_name='us-east-1')
sqs = session.resource('sqs')
q = sqs.get_queue_by_name(QueueName='rds')

def worker():
    global q, sns
    print 'Worker Initialized'
    attributes = ['data', 'contact']
    while True:
        responses = q.receive_messages(MessageAttributeNames=attributes)
        if len(responses) != 0:
            for response in responses:
                if response.message_attributes is None:
                    response.delete()
                    continue
                data = response.message_attributes.get('data').get('StringValue').replace("'", '"')
                contact = response.message_attributes.get('contact').get('StringValue')
                data = ast.literal_eval(data)
                unknown = {}
                for i in data:
                    specifics = {
                        "query": {
                            "multi_match": {
                                "query": i,
                                "fields": "SHA-1"
                            }
                        },
                        "size": 1
                    }
                    res = es.search(index="rds", body=specifics)
                    if res['hits']['total'] == 0: unknown[i] = data[i]
                report = ''
                for i in unknown:
                    report += i + ': '
                    for j in unknown[i]:
                        report += j + ', '
                    report += '\n'
                try:
                    sns.publish(
                        PhoneNumber=contact,
                        Message=report
                    )
                    print 'Notification sent'
                    response.delete()
                except Exception as e: print e
        sleep(2)


if __name__ == "__main__":
    print 'Running Worker'
    p = Pool(4, worker, ())
    while True: pass
