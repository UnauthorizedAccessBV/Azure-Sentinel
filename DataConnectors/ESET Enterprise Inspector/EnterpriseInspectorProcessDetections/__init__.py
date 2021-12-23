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

import logging
import json
import os
import re

import azure.functions as func

from datacollector import post_data
from distutils.util import strtobool
from enterpriseinspector import EnterpriseInspector
from esetinspect.models import _to_json

ei = None

def main(eeimsg: func.QueueMessage) -> None:

    detection = json.loads(eeimsg.get_body().decode('utf-8'))
    logging.info(f"Queue trigger function processed item: {detection['id']}")

    # Set variables
    base_url = os.getenv('baseUrl')
    client_id = os.getenv('clientId')
    username = os.getenv('eeiUsername')
    password = os.getenv('eeiPassword')
    domain = bool(strtobool(os.getenv('domainLogin')))
    verify = bool(strtobool(os.getenv('verifySsl')))
    workspace_id = os.getenv('workspaceId')
    workspace_key = os.getenv('workspaceKey')
    logAnalyticsUri = os.getenv('logAnalyticsUri')
    log_type = 'ESETEnterpriseInspector'

    if ((logAnalyticsUri in (None, '') or str(logAnalyticsUri).isspace())):    
        logAnalyticsUri = 'https://' + workspace_id + '.ods.opinsights.azure.com'

    pattern = r'https:\/\/([\w\-]+)\.ods\.opinsights\.azure.([a-zA-Z\.]+)$'
    match = re.match(pattern,str(logAnalyticsUri))
    
    if(not match):
        raise Exception("ESET Enterprise Inspector: Invalid Log Analytics Uri.")

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

    # Get detection details
    detection_details = ei.detection_details(detection)

    # Send data via data collector API
    body = json.dumps(detection_details, default=_to_json)
    post_data(
        customer_id=workspace_id,
        shared_key=workspace_key,
        body=body,
        log_type=log_type,
        logAnalyticsUri = logAnalyticsUri
    )
