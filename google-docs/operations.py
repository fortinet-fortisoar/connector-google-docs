"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

import json
from requests import request
from connectors.core.connector import get_logger, ConnectorError
from .google_api_auth import *
from .constants import *

DOCS_API_VERSION = 'v1'

logger = get_logger('google-docs')


def api_request(method, endpoint, connector_info, config, params=None, data=None, headers={}):
    try:
        go = GoogleAuth(config)
        endpoint = go.host + "/" + endpoint
        token = go.validate_token(config, connector_info)
        headers['Authorization'] = token
        headers['Content-Type'] = 'application/json'
        response = request(method, endpoint, headers=headers, params=params, data=data, verify=go.verify_ssl)
        try:
            from connectors.debug_utils.curl_script import make_curl
            make_curl(method, endpoint, headers=headers, params=params, data=data, verify_ssl=go.verify_ssl)
        except Exception as err:
            logger.error(f"Error in curl utils: {str(err)}")
        if response.ok or response.status_code == 204:
            if 'json' in str(response.headers):
                return response.json()
            else:
                return response
        else:
            logger.error("{0}".format(response.status_code))
            raise ConnectorError("{0}:{1}".format(response.status_code, response.text))
    except requests.exceptions.SSLError:
        raise ConnectorError('SSL certificate validation failed')
    except requests.exceptions.ConnectTimeout:
        raise ConnectorError('The request timed out while trying to connect to the server')
    except requests.exceptions.ReadTimeout:
        raise ConnectorError(
            'The server did not send any data in the allotted amount of time')
    except requests.exceptions.ConnectionError:
        raise ConnectorError('Invalid Credentials')
    except Exception as err:
        raise ConnectorError(str(err))


def check_payload(payload):
    l = {}
    for k, v in payload.items():
        if isinstance(v, dict):
            x = check_payload(v)
            if len(x.keys()) > 0:
                l[k] = x
        elif isinstance(v, list):
            p = []
            for c in v:
                if isinstance(c, dict):
                    x = check_payload(c)
                    if len(x.keys()) > 0:
                        p.append(x)
                elif c is not None and c != '':
                    p.append(c)
            if p != []:
                l[k] = p
        elif v is not None and v != '':
            l[k] = v
    return l


def build_payload(payload):
    payload = {k: v for k, v in payload.items() if v is not None and v != ''}
    return payload


def create_document(config, params, connector_info):
    try:
        url = '{0}/documents'.format(DOCS_API_VERSION)
        response = api_request('POST', url, connector_info, config)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_document_details(config, params, connector_info):
    try:
        url = '{0}/documents/{1}'.format(DOCS_API_VERSION, params.get('document_id'))
        query_parameters = {
            "suggestionsViewMode": SUGGESTIONS_VIEW_MODE.get(params.get('suggestionsViewMode')) if params.get(
                'suggestionsViewMode') else ''
        }
        query_parameters = build_payload(query_parameters)
        response = api_request('GET', url, connector_info, config, params=query_parameters)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def update_documents(config, params, connector_info):
    try:
        url = '{0}/documents/{1}:batchUpdate'.format(DOCS_API_VERSION, params.get('document_id'))
        payload = {
            "requests": params.get('additional_parameters'),
            "writeControl": {
                "requiredRevisionId": params.get('requiredRevisionId'),
                "targetRevisionId": params.get('targetRevisionId')
            }
        }
        payload = check_payload(payload)
        response = api_request('POST', url, connector_info, config, data=json.dumps(payload))
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def _check_health(config, connector_info):
    try:
        return check(config, connector_info)
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


operations = {
    'create_document': create_document,
    'get_document_details': get_document_details,
    'update_documents': update_documents
}
