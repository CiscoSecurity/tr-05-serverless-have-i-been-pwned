from http import HTTPStatus
from unittest import mock
from unittest.mock import call
from urllib.parse import quote

from pytest import fixture

from .utils import headers
from api.utils import get_key
from tests.unit.api.mock_for_tests import EXPECTED_RESPONSE_OF_JWKS_ENDPOINT


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='function')
def hibp_api_request():
    with mock.patch('requests.get') as mock_request:
        yield mock_request


def hibp_api_response(status_code):
    mock_response = mock.MagicMock()

    mock_response.status_code = status_code

    if status_code == HTTPStatus.UNAUTHORIZED:
        mock_response.json = lambda: {
            "message": "Unauthorized error from 3rd party"
        }
    elif status_code == HTTPStatus.TOO_MANY_REQUESTS:
        mock_response.json = lambda: {
            'message': 'Rate limit is exceeded. Try again in 3 seconds.'
        }

    return mock_response


def test_health_call_success(
        route, client, hibp_api_request, rsa_api_response, valid_jwt
):
    app = client.application

    hibp_api_request.side_effect = (
        rsa_api_response(EXPECTED_RESPONSE_OF_JWKS_ENDPOINT),
        hibp_api_response(HTTPStatus.OK),
        rsa_api_response(EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)
    )

    response = client.post(route, headers=headers(valid_jwt()))

    email = app.config['HIBP_TEST_EMAIL']

    expected_url = app.config['HIBP_API_URL'].format(
        email=quote(email, safe=''),
        truncate='true',
    )

    expected_headers = {
        'user-agent': app.config['CTR_USER_AGENT'],
        'hibp-api-key': get_key()
    }

    calls = [call('https://visibility.amp.cisco.com/.well-known/jwks'),
             call(expected_url, headers=expected_headers),
             call('https://visibility.amp.cisco.com/.well-known/jwks')]

    hibp_api_request.assert_has_calls(calls)

    expected_payload = {'data': {'status': 'ok'}}

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


def test_health_call_with_external_error_from_hibp_failure(route,
                                                           client,
                                                           hibp_api_request,
                                                           rsa_api_response,
                                                           valid_jwt):
    for status_code, error_code, error_message, is_authentic in [
        (
                HTTPStatus.UNAUTHORIZED,
                'access denied',
                'Authorization failed: Unauthorized error from 3rd party',
                False,
        ),
        (
                HTTPStatus.TOO_MANY_REQUESTS,
                'too many requests',
                'Rate limit is exceeded. Try again in 3 seconds.',
                True,
        ),
        (
                HTTPStatus.SERVICE_UNAVAILABLE,
                'service unavailable',
                'Service temporarily unavailable. Please try again later.',
                False,
        ),
        (
                HTTPStatus.INTERNAL_SERVER_ERROR,
                'oops',
                'Something went wrong.',
                False,
        ),
    ]:
        app = client.application

        hibp_api_request.side_effect = (
            rsa_api_response(EXPECTED_RESPONSE_OF_JWKS_ENDPOINT),
            hibp_api_response(status_code),
            rsa_api_response(EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)
        )

        response = client.post(route, headers=headers(valid_jwt()))

        email = app.config['HIBP_TEST_EMAIL']

        expected_url = app.config['HIBP_API_URL'].format(
            email=quote(email, safe=''),
            truncate='true',
        )

        expected_headers = {
            'user-agent': app.config['CTR_USER_AGENT'],
            'hibp-api-key': get_key()
        }

        calls = [call('https://visibility.amp.cisco.com/.well-known/jwks'),
                 call(expected_url, headers=expected_headers),
                 call('https://visibility.amp.cisco.com/.well-known/jwks')]

        hibp_api_request.assert_has_calls(calls)

        hibp_api_request.reset_mock()

        expected_payload = {
            'errors': [
                {
                    'code': error_code,
                    'message': error_message,
                    'type': 'fatal',
                }
            ]
        }

        assert response.status_code == HTTPStatus.OK
        assert response.get_json() == expected_payload
