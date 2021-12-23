import math
import logging

from urllib.parse import urljoin
from esetinspect.client import EsetInspectClient

class EnterpriseInspector:
    """A small class used for communicating with the ESET Enterprise Inspector server"""
    def __init__(self, base_url, username, password, domain=False, verify=True, client_id=None):
        
        self.base_url = base_url
        self.username = username
        self.password = password
        self.domain = domain
        self.verify = verify
        self.page_size = 100
        self.token = None
        self.client_id = client_id

        self._client = EsetInspectClient(
            url = self.base_url,
            username = self.username,
            password = self.password,
            domain = self.domain,
            verify = self.verify,
            client_id = self.client_id
        )
        
        if not self.verify:
            logging.warning(
                'Verification of SSL certificate has been disabled!'
            )

        self._client.login()

    def detections(self, last_id):

        params = {
            'order_by': 'id asc',
            'filter': f'id gt {last_id}',
            'count': True,
        }

        # Get the first batch of detections
        logging.info('Getting list of detections..')

        resp = self._client.list_detections(**params)
        count = resp['count']
        detections = resp['value']
        pages = math.ceil(count / self.page_size)

        logging.info(f'Found {count} detection(s).')

        # Check if there are more pages
        if pages > 1:
            logging.info(f'Detections spread over {pages} pages.')

            for skip in range(self.page_size, count, self.page_size):
                current_page = int(skip / self.page_size + 1)
                logging.info(f'Getting page {current_page}.')
                params.update({
                    'skip': skip,
                    'count': False
                })
                resp = self._client.list_detections(**params)
                detections += resp['value']
        
        return detections


    def enrich(self, detection_details):

        # Resolve "moduleSignatureType"
        signature_types = {
            90: 'Trusted',
            80: 'Valid',
            75: 'AdHoc',
            70: 'None',
            60: 'Invalid',
            0: 'Unkown'
        }

        try:
            signature_type = signature_types[detection_details['module_signature_type']]
        except KeyError:
            signature_type = signature_types[0]

        # Resolve "type"
        types = {
            0: 'UnknownAlarm',
            1: 'RuleActivated',
            2: 'MalwareFoundOnDisk',
            3: 'MalwareFoundInMemory',
            4: 'ExploitDetected',
            5: 'FirewallDetection',
            7: 'BlockedAddress',
            8: 'CryptoBlockerDetection',
        }

        try:
            detection_type = types[detection_details['type']]
        except KeyError:
            detection_type = types[0]

        # Create deeplink
        deep_link = urljoin(
            self.base_url,
            f"/console/detection/{detection_details['id']}",
        )

        detection_details.update({
            'type': detection_type,
            'module_signature_type': signature_type,
            'deep_link': deep_link
        })

        return detection_details


    def detection_details(self, detection):

        # Get detection details
        resp = self._client.get_detection(detection['id']).to_dict()

        # Enrich detection details
        detection_details = self.enrich(resp)

        return detection_details
