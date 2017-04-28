# Message Digest Detective
### Munieshwar (Kevin) Ramdass
### CS-GY 9223 - Cloud Computing
### Spring 2017

## Sypnosis
The intuition behind Message Digest Detective (MDD) is to be able to scan an entire directory of sub-directories and files which may include thousands of files in less than an hour - a Windows 7 System32 scan of 3,357 files returned results in 20.5 minutes. The National Science Research Library has an RDS of beign hashes found on computers. MDD works by comparing hashes from single user input via the web interface or batch input via a script. The single request will return immediate data via the web interface while the script may take a bit longer but the goal is to then send a report of the results to the user via AWS SNS to their email. The time to beat is about 20 minutes for a batch of hashes.  

## Running
```
python application.py
python input.py -r <path to directory that contains zipped RDS and detail files>
python input.py -u <sha-1> -m <md5> -p <product code> -o <operation system code> -s <special code> -f <file name> -a <file size> -c <CRC32>
python worker.py
python client.py -p <path to scan>
```
Note: -p specifies the file system path of the directory the user wishes to scan. The System32 Folder is ideally what MDD is meant to scan. -u specifies the (new) hash to update. This requires all other information to be supplied. -r will upload the rds to AWS Elasticsearch.

## Architecture
### Front End
Front end is a web interface that uses Python Flask. This takes in a keyword. It could be any of the following fields:
```
['SHA-1', 'ProductCode', 'OpSystemCode', 'SpecialCode', 'FileName', 'FileSize', 'CRC32', 'MD5']
```
Should an input of SHA-1 or MD5 hash not match, the user will be redirected to the VirusTotal website. If the user input is not a SHA-1 or MD5 hash and not found, the user will receive an "unknown" response.

### Back End
Python Flask handles searches to the AWS Elasticsearch storage among other requests such as batch requests. Batch requests will be queued using AWS SQS. A worker will then handle batch searches.  
A second back end is implemented for administrative purposes. This includes uploading the RDS for the first time and updating it. The input.py script is used for this.

### Worker
Worker will take user batches from AWS SQS and run searches on AWS Elasticsearch. The results will then be posted on a topic on AWS SNS which will notify the user.

### AWS SQS
Holds batch requests. This is a list of SHA-1 or MD5 hashes.

### AWS SNS
Alerts the user via email about the result of his/her batch request.

## Screenshots
![alt tag](https://github.com/mramdass/Message_Digest_Detective_API/blob/master/Screenshots/Page_Index.PNG)
![alt tag](https://github.com/mramdass/Message_Digest_Detective_API/blob/master/Screenshots/Page_Result.PNG)
![alt tag](https://github.com/mramdass/Message_Digest_Detective_API/blob/master/Screenshots/Page_Prod.PNG)
![alt tag](https://github.com/mramdass/Message_Digest_Detective_API/blob/master/Screenshots/Page_OS.PNG)
![alt tag](https://github.com/mramdass/Message_Digest_Detective_API/blob/master/Screenshots/Page_Mfg.PNG)
![alt tag](https://github.com/mramdass/Message_Digest_Detective_API/blob/master/Screenshots/Page_Redirect_VirusTotal.PNG)
