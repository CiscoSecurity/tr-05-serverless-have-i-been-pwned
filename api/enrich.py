from functools import partial

from flask import Blueprint

from api.mappings import Indicator, Sighting, Relationship
from api.schemas import ObservableSchema
from api.utils import (
    get_json, jsonify_data, jsonify_errors, get_key, fetch_breaches
)

enrich_api = Blueprint('enrich', __name__)


get_observables = partial(get_json, schema=ObservableSchema(many=True))


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    # There are no verdicts to extract.
    return jsonify_data({})


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    observables, error = get_observables()

    if error:
        return jsonify_errors(error)

    emails = [
        observable['value']
        for observable in observables
        if observable['type'] == 'email'
    ]

    key = get_key()

    indicators = []
    sightings = []
    relationships = []

    for email in emails:
        breaches, error = fetch_breaches(key, email)

        if error:
            return jsonify_errors(error)

        count = len(breaches)

        for breach in breaches:
            indicator = Indicator.map(breach)
            sighting = Sighting.map(breach, count, email)
            relationship = Relationship.map(indicator, sighting)

            indicators.append(indicator)
            sightings.append(sighting)
            relationships.append(relationship)

    data = {}

    def format_docs(docs):
        return {'count': len(docs), 'docs': docs}

    if indicators:
        data['indicators'] = format_docs(indicators)

    if sightings:
        data['sightings'] = format_docs(sightings)

    if relationships:
        data['relationships'] = format_docs(relationships)

    return jsonify_data(data)


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    # There are no references (i.e. clickable links) to show.
    return jsonify_data([])
