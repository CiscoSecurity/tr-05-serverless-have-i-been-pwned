import json
import time
from http import HTTPStatus
from typing import Optional
from urllib.parse import quote

import requests
from authlib.jose import jwt
from authlib.jose.errors import JoseError
from flask import request, current_app, jsonify


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
        'user-agent': current_app.config['HIBP_USER_AGENT'],
        'hibp-api-key': key,
    }

    response = requests.get(url, headers=headers)

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
        # Try again after some timeout suggested by the HIBP API.
        timeout = int(response.headers['retry-after'])
        time.sleep(timeout)
        return fetch_breaches(key, email, truncate=truncate)

    if response.status_code == HTTPStatus.SERVICE_UNAVAILABLE:
        error = {
            'code': 'service unavailable',
            'message': (
                'Service temporarily unavailable. '
                'Please try again later.'
            ),
        }
        return None, error

    assert response.status_code == HTTPStatus.OK

    return response.json(), None


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(error):
    # According to the official documentation, an error here means that the
    # corresponding TR module is in an incorrect state and needs to be
    # reconfigured, or the third-party service is down (for example, the API
    # being queried has temporary issues) and thus unresponsive:
    # https://visibility.amp.cisco.com/help/alerts-errors-warnings.
    error['type'] = 'fatal'

    return jsonify({'errors': [error]})
