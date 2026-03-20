"""
Shared HTTP session for OpenSearch requests.

Provides a pre-configured requests.Session with auth and SSL settings
from config, so individual modules don't repeat boilerplate.
"""

import requests
import urllib3

import config

# Suppress InsecureRequestWarning for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

session = requests.Session()
session.verify = False
if config.OPENSEARCH_USERNAME and config.OPENSEARCH_PASSWORD:
    session.auth = (config.OPENSEARCH_USERNAME, config.OPENSEARCH_PASSWORD)
