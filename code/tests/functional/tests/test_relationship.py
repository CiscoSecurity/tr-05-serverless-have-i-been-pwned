from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from tests.functional.tests.constants import MODULE_NAME


def test_positive_relationship_email(module_headers):
    """Perform testing for enrich observe observables endpoint to get
    relationship for observable from Have I Been Pwned module

    ID: CCTRI-812-b5f9429c-dfab-4280-adf7-32f7c81b7214

    Steps:
        1. Send request to enrich deliberate observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected relationship for
            observable from Have I Been Pwned module and it connects expected
            entities

    Importance: Critical
    """
    observable = [{'type': 'email', 'value': 'user@example.com'}]
    response = enrich_observe_observables(
        payload=observable,
        **{'headers': module_headers}
    )
    module_response = get_observables(response, MODULE_NAME)['data']
    # Get one indicator to check for relation
    indicator = [
        d for d
        in module_response['indicators']['docs']
        if d['title'] == 'Apollo'
    ][0]
    # Get one sighting that is expected to be connected to taken indicator
    sighting = [
        d for d
        in module_response['sightings']['docs']
        if 'Apollo' in d['description']
    ][0]
    # Validate that entities are connected
    relationship = [
        d for d
        in module_response['relationships']['docs']
        if d['source_ref'] == sighting['id']
    ]
    assert relationship, 'There is no relationship for provided sighting'
    assert relationship[0]['type'] == 'relationship'
    assert relationship[0]['relationship_type'] == 'sighting-of'
    assert relationship[0]['target_ref'] == indicator['id']
