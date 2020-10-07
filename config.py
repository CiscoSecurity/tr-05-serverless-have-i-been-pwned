import os

from uuid import NAMESPACE_X500

from version import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', None)

    # HIBP returns 403 Forbidden "API request must include a user agent"
    # when using angle brackets, only round brackets are acceptable...
    CTR_USER_AGENT = (
        'Cisco Threat Response Integrations '
        '(tr-integrations-support@cisco.com)'
    )

    CTR_ENTITIES_LIMIT_DEFAULT = 100

    try:
        CTR_ENTITIES_LIMIT = int(os.environ['CTR_ENTITIES_LIMIT'])
        assert CTR_ENTITIES_LIMIT > 0
    except (KeyError, ValueError, AssertionError):
        CTR_ENTITIES_LIMIT = CTR_ENTITIES_LIMIT_DEFAULT

    HIBP_TEST_EMAIL = 'user@example.com'

    NAMESPACE_BASE = NAMESPACE_X500

    HIBP_API_URL = (
        'https://haveibeenpwned.com/api/v3/breachedaccount/{email}'
        '?truncateResponse={truncate}'
    )

    HIBP_UI_URL = 'https://haveibeenpwned.com/account/{email}'
