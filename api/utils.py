import json
from http import HTTPStatus
from ssl import SSLCertVerificationError
from typing import Optional
from urllib.parse import quote

import requests
from authlib.jose import jwt
from authlib.jose.errors import JoseError
from flask import request, current_app, jsonify
from requests.exceptions import SSLError


def get_jwt():
    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return jwt.decode(token, current_app.config['SECRET_KEY'])
    except (KeyError, ValueError, AssertionError, JoseError):
        return {}


def get_key() -> Optional[str]:
    return get_jwt().get('key')  # HIBP_API_KEY


def get_json(schema):
    data = request.get_json(force=True, silent=True, cache=False)

    error = schema.validate(data) or None
    if error:
        data = None
        error = {
            'code': 'invalid payload received',
            'message': f'Invalid JSON payload received. {json.dumps(error)}.',
        }

    return data, error


def fetch_breaches(key, email, truncate=False):
    if key is None:
        error = {
            'code': 'access denied',
            'message': 'Access to HIBP denied due to invalid API key.',
        }
        return None, error

    url = current_app.config['HIBP_API_URL'].format(
        email=quote(email, safe=''),
        truncate=str(truncate).lower(),
    )

    headers = {
        'user-agent': current_app.config['CTR_USER_AGENT'],
        'hibp-api-key': key,
    }

    try:
        response = requests.get(url, headers=headers)
    except SSLError as error:
        # Go through a few layers of wrapped exceptions.
        error = error.args[0].reason.args[0]
        # Assume that a certificate could not be verified.
        assert isinstance(error, SSLCertVerificationError)
        reason = getattr(error, 'verify_message', error.args[0]).capitalize()
        error = {
            'code': 'ssl certificate verification failed',
            'message': f'Unable to verify SSL certificate: {reason}.',
        }
        return None, error

    if response.status_code == HTTPStatus.BAD_REQUEST:
        return [], None

    if response.status_code == HTTPStatus.UNAUTHORIZED:
        error = {
            'code': 'access denied',
            'message': 'Access to HIBP denied due to invalid API key.',
        }
        return None, error

    if response.status_code == HTTPStatus.NOT_FOUND:
        return [], None

    if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
        error = response.json()
        # The HIBP API error response payload is already well formatted,
        # so use the original message containing some suggested timeout.
        error = {
            'code': 'too many requests',
            'message': error['message'],
        }
        return None, error

    if response.status_code == HTTPStatus.SERVICE_UNAVAILABLE:
        error = {
            'code': 'service unavailable',
            'message': (
                'Service temporarily unavailable. '
                'Please try again later.'
            ),
        }
        return None, error

    # Any other error types aren't officially documented,
    # so simply can't be handled in a meaningful way...
    if response.status_code != HTTPStatus.OK:
        error = {
            'code': 'oops',
            'message': 'Something went wrong.',
        }
        return None, error

    return response.json(), None


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(error, data=None):
    # According to the official documentation, an error here means that the
    # corresponding TR module is in an incorrect state and needs to be
    # reconfigured, or the third-party service is down (for example, the API
    # being queried has temporary issues) and thus unresponsive:
    # https://visibility.amp.cisco.com/help/alerts-errors-warnings.
    error['type'] = 'fatal'

    payload = {'errors': [error]}
    if data:
        payload['data'] = data

    return jsonify(payload)
