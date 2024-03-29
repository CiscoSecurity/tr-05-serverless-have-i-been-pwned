from http import HTTPStatus
from unittest import mock
from unittest.mock import call
from urllib.parse import quote

from pytest import fixture

from api.mappings import Indicator, Sighting, Relationship
from api import enrich
from tests.unit.api.mock_for_tests import EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
from .utils import headers


def implemented_routes():
    yield '/observe/observables'
    yield '/refer/observables'


@fixture(scope='module',
         params=implemented_routes(),
         ids=lambda route: f'POST {route}')
def implemented_route(request):
    return request.param


@fixture(scope='module')
def invalid_json():
    return [{'type': 'unknown', 'value': ''}]


def test_enrich_call_with_invalid_json_failure(implemented_route,
                                               client,
                                               invalid_json):
    response = client.post(implemented_route, json=invalid_json)

    # The actual error message is quite unwieldy, so let's just ignore it.
    expected_payload = {
        'errors': [
            {
                'code': 'invalid payload received',
                'message': mock.ANY,
                'type': 'fatal',
            }
        ]
    }

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


def hibp_api_routes():
    yield '/observe/observables'


@fixture(scope='module',
         params=hibp_api_routes(),
         ids=lambda route: f'POST {route}')
def hibp_api_route(request):
    return request.param


def all_routes():
    yield '/observe/observables'
    yield '/refer/observables'


@fixture(scope='module',
         params=all_routes(),
         ids=lambda route: f'POST {route}')
def any_route(request):
    return request.param


def hibp_api_response(status_code):
    mock_response = mock.MagicMock()

    mock_response.status_code = status_code

    if status_code == HTTPStatus.OK:
        description_html = (
            'This is the <i>{id}</i> breach found on <b>HIBP</b>. Please '
            'visit the <em>official</em> <a href="{id}.com">website</a> '
            'to check if your account has been <strong>compromised</strong>.'
        )

        payload_list = [
            EXPECTED_RESPONSE_OF_JWKS_ENDPOINT,
            [],
            [
                {
                    'Name': 'FirstExposure',
                    'Title': 'First Customer Data Exposure',
                    'Domain': 'first.com',
                    'BreachDate': '1970-01-01',
                    'Description': description_html.format(id='first'),
                    'DataClasses': ['Email addresses'],
                    'IsVerified': False,
                },
                {
                    'Name': 'SecondExposure',
                    'Title': 'Second Customer Data Exposure',
                    'Domain': 'second.com',
                    'BreachDate': '1970-01-02',
                    'Description': description_html.format(id='second'),
                    'DataClasses': ['Email addresses'],
                    'IsVerified': True,
                },
                {
                    'Name': 'ThirdExposure',
                    'Title': 'Third Customer Data Exposure',
                    'Domain': 'third.com',
                    'BreachDate': '1970-01-03',
                    'Description': description_html.format(id='third'),
                    'DataClasses': ['Email addresses', 'Passwords'],
                    'IsVerified': True,
                },
            ],
            EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
        ]

        payload_list_iter = iter(payload_list)

        mock_response.json = lambda: next(payload_list_iter)
    elif status_code == HTTPStatus.UNAUTHORIZED:
        mock_response.json = lambda: {
            "message": "Unauthorized error from 3rd party"
        }
    elif status_code == HTTPStatus.TOO_MANY_REQUESTS:
        mock_response.json = lambda: {
            'message': 'Rate limit is exceeded. Try again in 3 seconds.'
        }

    return mock_response


@fixture(scope='module')
def expected_payload(any_route, client):
    app = client.application

    payload = None

    if any_route.startswith('/observe'):
        description_md = (
            'This is the *{id}* breach found on **HIBP**. Please '
            'visit the *official* [website]({id}.com) '
            'to check if your account has been **compromised**.'
        )

        titles = [
            f'{id.capitalize()} Customer Data Exposure'
            for id in ['first', 'second', 'third']
        ]

        start_times = [
            f'1970-01-0{day}T00:00:00Z'
            for day in [1, 2, 3]
        ]

        valid_times = [
            {'start_time': start_time}
            for start_time in start_times
        ]

        observed_times = [
            {'start_time': start_time}
            for start_time in start_times
        ]

        for observed_time in observed_times:
            observed_time['end_time'] = observed_time['start_time']

        source_email = {'type': 'email', 'value': 'dummy@gmail.com'}

        source_uri = app.config['HIBP_UI_URL'].format(
            email=quote('dummy@gmail.com', safe='')
        )

        related_domains = [
            {'type': 'domain', 'value': f'{id}.com'}
            for id in ['first', 'second', 'third']
        ]

        # Implement a dummy class initializing its instances
        # only after the first comparison with any other object.
        class LazyEqualizer:
            NONE = object()

            def __init__(self):
                self.value = self.NONE

            def __eq__(self, other):
                if self.value is self.NONE:
                    self.value = other

                return self.value == other

        indicator_refs = [LazyEqualizer() for _ in range(3)]
        sighting_refs = [LazyEqualizer() for _ in range(3)]

        payload = {
            'indicators': {
                'count': 3,
                'docs': [
                    {
                        'confidence': 'High',
                        'description': description_md.format(id='third'),
                        'id': indicator_refs[2],
                        'severity': 'High',
                        'short_description': titles[2],
                        'tags': ['Email addresses', 'Passwords'],
                        'title': 'ThirdExposure',
                        'valid_time': valid_times[2],
                        **Indicator.DEFAULTS
                    },
                    {
                        'confidence': 'High',
                        'description': description_md.format(id='second'),
                        'id': indicator_refs[1],
                        'severity': 'Medium',
                        'short_description': titles[1],
                        'tags': ['Email addresses'],
                        'title': 'SecondExposure',
                        'valid_time': valid_times[1],
                        **Indicator.DEFAULTS
                    },
                    {
                        'confidence': 'Medium',
                        'description': description_md.format(id='first'),
                        'id': indicator_refs[0],
                        'severity': 'Medium',
                        'short_description': titles[0],
                        'tags': ['Email addresses'],
                        'title': 'FirstExposure',
                        'valid_time': valid_times[0],
                        **Indicator.DEFAULTS
                    },
                ],
            },
            'sightings': {
                'count': 3,
                'docs': [
                    {
                        'confidence': 'High',
                        'description': (
                            f'{source_email["value"]} '
                            f'present in {titles[2]} breach.'
                        ),
                        'id': sighting_refs[2],
                        'observables': [source_email],
                        'observed_time': observed_times[2],
                        'relations': [{
                            'origin': Sighting.DEFAULTS['source'],
                            'origin_uri': source_uri,
                            'related': related_domains[2],
                            'relation': 'Leaked_From',
                            'source': source_email,
                        }],
                        'severity': 'High',
                        'source_uri': source_uri,
                        'targets': [{
                            'observables': [source_email],
                            'observed_time': observed_times[2],
                            'type': 'email',
                        }],
                        **Sighting.DEFAULTS
                    },
                    {
                        'confidence': 'High',
                        'description': (
                            f'{source_email["value"]} '
                            f'present in {titles[1]} breach.'
                        ),
                        'id': sighting_refs[1],
                        'observables': [source_email],
                        'observed_time': observed_times[1],
                        'relations': [{
                            'origin': Sighting.DEFAULTS['source'],
                            'origin_uri': source_uri,
                            'related': related_domains[1],
                            'relation': 'Leaked_From',
                            'source': source_email,
                        }],
                        'severity': 'Medium',
                        'source_uri': source_uri,
                        'targets': [{
                            'observables': [source_email],
                            'observed_time': observed_times[1],
                            'type': 'email',
                        }],
                        **Sighting.DEFAULTS
                    },
                    {
                        'confidence': 'Medium',
                        'description': (
                            f'{source_email["value"]} '
                            f'present in {titles[0]} breach.'
                        ),
                        'id': sighting_refs[0],
                        'observables': [source_email],
                        'observed_time': observed_times[0],
                        'relations': [{
                            'origin': Sighting.DEFAULTS['source'],
                            'origin_uri': source_uri,
                            'related': related_domains[0],
                            'relation': 'Leaked_From',
                            'source': source_email,
                        }],
                        'severity': 'Medium',
                        'source_uri': source_uri,
                        'targets': [{
                            'observables': [source_email],
                            'observed_time': observed_times[0],
                            'type': 'email',
                        }],
                        **Sighting.DEFAULTS
                    },
                ],
            },
            'relationships': {
                'count': 3,
                'docs': [
                    {
                        'id': mock.ANY,
                        'source_ref': sighting_refs[2],
                        'target_ref': indicator_refs[2],
                        **Relationship.DEFAULTS
                    },
                    {
                        'id': mock.ANY,
                        'source_ref': sighting_refs[1],
                        'target_ref': indicator_refs[1],
                        **Relationship.DEFAULTS
                    },
                    {
                        'id': mock.ANY,
                        'source_ref': sighting_refs[0],
                        'target_ref': indicator_refs[0],
                        **Relationship.DEFAULTS
                    },
                ],
            },
        }

    if any_route.startswith('/refer'):
        emails = [
            quote(email, safe='')
            for email in [
                'dummy@cisco.com',
                'dummy@gmail.com',
            ]
        ]

        urls = [
            app.config['HIBP_UI_URL'].format(email=email)
            for email in emails
        ]

        payload = [
            {
                'id': f'ref-hibp-search-email-{email}',
                'title': 'Search for this email',
                'description': (
                    'Check this email status with Have I Been Pwned'
                ),
                'url': url,
                'categories': ['Search', 'Have I Been Pwned'],
            }
            for email, url in zip(emails, urls)
        ]

    assert payload is not None, f'Unknown route: {any_route}.'

    return {'data': payload}


def test_enrich_call_success(any_route,
                             client,
                             valid_json,
                             hibp_api_request,
                             valid_jwt,
                             expected_payload):
    app = client.application

    response = None

    if any_route.startswith('/observe'):
        hibp_api_request.return_value = hibp_api_response(HTTPStatus.OK)

        response = client.post(any_route,
                               json=valid_json,
                               headers=headers(valid_jwt()))

        emails = [
            observable['value']
            for observable in valid_json
            if observable['type'] == 'email'
        ]

        expected_urls = [
            app.config['HIBP_API_URL'].format(
                email=quote(email, safe=''),
                truncate='false',
            )
            for email in emails
        ]

        expected_headers = {
            'User-Agent': app.config['CTR_USER_AGENT'],
            'hibp-api-key': enrich.get_key()
        }

        hibp_api_request.assert_has_calls([
            mock.call(expected_url, headers=expected_headers)
            for expected_url in expected_urls
        ])

    if any_route.startswith('/refer'):
        response = client.post(any_route, json=valid_json)

    assert response is not None, f'Unknown route: {any_route}.'

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


def test_enrich_call_with_external_error_from_hibp_failure(hibp_api_route,
                                                           client,
                                                           valid_json,
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

        response = client.post(hibp_api_route,
                               json=valid_json,
                               headers=headers(valid_jwt()))

        email = next(
            observable['value']
            for observable in valid_json
            if observable['type'] == 'email'
        )

        expected_url = app.config['HIBP_API_URL'].format(
            email=quote(email, safe=''),
            truncate='false',
        )

        expected_headers = {
            'User-Agent': app.config['CTR_USER_AGENT'],
            'hibp-api-key': enrich.get_key()
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
