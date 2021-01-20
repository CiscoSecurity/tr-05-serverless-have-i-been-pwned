from uuid import NAMESPACE_X500

from __version__ import VERSION


class Config:
    VERSION = VERSION

    # HIBP returns 403 Forbidden "API request must include a user agent"
    # when using angle brackets, only round brackets are acceptable...
    CTR_USER_AGENT = (
        'SecureX Threat Response Integrations '
        '(tr-integrations-support@cisco.com)'
    )

    CTR_ENTITIES_LIMIT_DEFAULT = 100

    HIBP_TEST_EMAIL = 'user@example.com'

    NAMESPACE_BASE = NAMESPACE_X500

    HIBP_API_URL = (
        'https://haveibeenpwned.com/api/v3/breachedaccount/{email}'
        '?truncateResponse={truncate}'
    )

    HIBP_UI_URL = 'https://haveibeenpwned.com/account/{email}'
