from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables


def test_positive_indicator_email(module_headers):
    """Perform testing for enrich observe observables endpoint to get
    indicator for observable from Have I Been Pwned module

    ID: CCTRI-843-2a0ae451-954a-4daf-b4e9-33f8f7b2e8b0

    Steps:
        1. Send request to enrich deliberate observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected indicator for
            observable from Have I Been Pwned module

    Importance: Critical
    """
    payload = {'type': 'email', 'value': 'fluffy@cisco.com'}
    response_from_all_modules = enrich_observe_observables(
        payload=[payload],
        **{'headers': module_headers}
    )['data']
    response_from_hibp_module = get_observables(
        response_from_all_modules, 'Have I Been Pwned')
    assert response_from_hibp_module['module'] == 'Have I Been Pwned'
    assert response_from_hibp_module['module_instance_id']
    assert response_from_hibp_module['module_type_id']
    indicators = response_from_hibp_module['data']['indicators']
    assert len(indicators['docs']) > 0
    # check some generic properties
    for indicator in indicators['docs']:
        assert indicator['type'] == 'indicator'
        assert indicator['producer'] == 'Have I Been Pwned'
        assert indicator['source'] == 'Have I Been Pwned Breaches'
        assert indicator['tlp'] == 'white'
        if (
            indicator['confidence'] == 'High'
            and 'Passwords' in indicator['tags']
        ):
            assert indicator['severity'] == 'High'
        else:
            assert indicator['severity'] == 'Medium'
    assert indicators['count'] == len(indicators['docs'])
    # check properties of one unique indicator
    indicator = [d for d in indicators['docs'] if d['title'] == 'PDL'][0]
    assert indicator[
        'short_description'] == 'Data Enrichment Exposure From PDL Customer'
    assert (
        'Exposed information included email addresses, '
        'phone numbers, social media'
    ) in indicator['description']
    tags = [
        'Email addresses',
        'Employers',
        'Geographic locations',
        'Job titles',
        'Names',
        'Phone numbers',
        'Social media profiles'
    ]
    assert indicator['tags'] == tags
    assert indicator['confidence'] == 'High'
