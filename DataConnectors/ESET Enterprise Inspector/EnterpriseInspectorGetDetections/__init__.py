# Title:          ESET Enterprise Inspector Data Connector
# Language:       Python
# Version:        1.1
# Author(s):      ESET Netherlands - Donny Maasland
# Last Modified:  12/21/2021
# Comment:        Add support for cloud hosted instances
#
# DESCRIPTION
# This Function App calls the ESET Enterprise Inspector API (https://help.eset.com/eei/latest/en-US/api.html)
# and gathers all new detections that have been triggered.
#
# The response from the ESET Enterprise Inspector API is recieved in JSON format. This function will build
# the signature and authorization header needed to post the data to the Log Analytics workspace via 
# the HTTP Data Connector API. The Function App will will post all detections to the ESETEnterpriseInspector_CL
# table in Log Analytics.

import datetime
import logging
import json
import os

import azure.functions as func

from distutils.util import strtobool
from enterpriseinspector import EnterpriseInspector
from esetinspect.models import _to_json

ei = None

def main(eeitimer: func.TimerRequest, inputblob: func.InputStream, outputblob: func.Out[func.InputStream], outputqueue: func.Out[str]):

    utc_timestamp = datetime.datetime.utcnow().replace(
        tzinfo=datetime.timezone.utc).isoformat()

    if eeitimer.past_due:
        logging.info('The timer is past due!')

    # Set variables
    base_url = os.getenv('baseUrl')
    client_id = os.getenv('clientId')
    username = os.getenv('eeiUsername')
    password = os.getenv('eeiPassword')
    domain = bool(strtobool(os.getenv('domainLogin')))
    verify = bool(strtobool(os.getenv('verifySsl')))
    start_from_id = int(os.getenv('startFromID'))

    # Connect to ESET Enterprise Inspector server
    global ei
    if ei is None:
        ei = EnterpriseInspector(
            base_url=base_url,
            username=username,
            password=password,
            domain=domain,
            verify=verify,
            client_id=client_id
        )

    # Get last processed detection id
    if inputblob:
        last_id = json.loads(inputblob.read())['id']
    else:
        last_id = start_from_id

    # Get new detections
    detections = ei.detections(last_id)

    # Get detection details and send to queue
    if detections:
        logging.info('Processing detections..')

        outputqueue.set(
            json.dumps([detection.to_dict() for detection in detections], default=_to_json)
        )
 
        # Write last succesfully processed detection to blob storage
        latest_detection = detections[-1]

        outputblob.set(
            json.dumps({
                'id': latest_detection.id
            })
        )
                
        logging.info('Done processing detections.')

    logging.info('Python timer trigger function ran at %s', utc_timestamp)
