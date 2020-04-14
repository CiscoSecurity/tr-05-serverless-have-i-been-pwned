from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables


def test_positive_sighting_email(module_headers):
    """Perform testing for enrich observe observables endpoint to get
    sighting for observable from Have I Been Pwned module

    ID: CCTRI-812-57f2d8d6-a897-4ce4-abcf-331296e2d86a

    Steps:
        1. Send request to enrich deliberate observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected sighting for
            observable from Have I Been Pwned module

    Importance: Critical
    """
    payload = {'type': 'email', 'value': 'fluffy@cisco.com'}
    response = enrich_observe_observables(
        payload=[payload],
        **{'headers': module_headers}
    )['data']
    sightings = get_observables(
        response, 'Have I Been Pwned')['data']['sightings']
    assert sightings['count'] == 14
    # check some generic properties
    for sighting in sightings['docs']:
        assert sighting['type'] == 'sighting'
        assert sighting['internal'] is False
        assert sighting['title'] == 'Found on Have I Been Pwned'
        assert sighting['observables'] == [payload]
        assert sighting['source'] == 'Have I Been Pwned'
        assert sighting['source_uri'] == (
            'https://haveibeenpwned.com/account/fluffy%40cisco.com'
        )
        assert sighting['targets'][0]['type'] == 'email'
        assert sighting['targets'][0]['observables'] == [payload]
    # check properties of one unique sighting
    sighting = [
        d for d in sightings['docs'] if 'Apollo' in d['description']][0]
    assert sighting['description'] == (
        'fluffy@cisco.com present in Apollo breach.'
    )
    relation = {
        'origin': 'Have I Been Pwned',
        'origin_uri': 'https://haveibeenpwned.com/account/fluffy%40cisco.com',
        'relation': 'Leaked_From',
        'source': payload,
        'related': {'value': 'apollo.io', 'type': 'domain'}
    }
    assert sighting['relations'][0] == relation
    assert sighting['confidence'] == 'High'
    assert sighting['severity'] == 'Medium'
