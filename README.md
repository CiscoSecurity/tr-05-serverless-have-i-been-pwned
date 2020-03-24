[![Travis CI Build Status](https://travis-ci.com/CiscoSecurity/tr-05-serverless-have-i-been-pwned.svg?branch=develop)](https://travis-ci.com/CiscoSecurity/tr-05-serverless-have-i-been-pwned)

# Have I Been Pwned Relay API

A sample Relay API implementation using the
[Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
as an example of a third-party Threat Intelligence service provider.

The API itself is just a simple Flask (WSGI) application which can be easily
packaged and deployed as an AWS Lambda Function working behind an AWS API
Gateway proxy using [Zappa](https://github.com/Miserlou/Zappa).

An already deployed Relay API (e.g., packaged as an AWS Lambda Function) can
be pushed to Threat Response as a Relay Module using the
[Threat Response Relay CLI](https://github.com/threatgrid/tr-lambda-relay).

## Installation

```bash
pip install -U -r requirements.txt
```

## Testing

```bash
pip install -U -r test-requirements.txt
```

- Check for *PEP 8* compliance: `flake8 .`.
- Run the suite of unit tests: `pytest -v tests/unit/`.

## Deployment

```bash
pip install -U -r deploy-requirements.txt
```

As an AWS Lambda Function:
- Deploy: `zappa deploy dev`.
- Check: `zappa status dev`.
- Update: `zappa update dev`.
- Monitor: `zappa tail dev --http`.

As a TR Relay Module:
- Create: `relay add`.
- Update: `relay edit`.
- Delete: `relay remove`.

**Note.** For convenience, each TR Relay CLI command may be prefixed with
`env $(cat .env | xargs)` to automatically read the required environment
variables from a `.env` file (i.e.`TR_API_CLIENT_ID`, `TR_API_CLIENT_PASSWORD`,
`URL`, `JWT`) and pass them to the corresponding command.

## Usage

```bash
pip install -U -r use-requirements.txt
```

```bash
export URL=<...>
export JWT=<...>

http POST "${URL}"/health Authorization:"Bearer ${JWT}"
http POST "${URL}"/observe/observables Authorization:"Bearer ${JWT}" < observables.json
```

## Mapping Details

Each HIBP breach for an email generates 3 CTIM entities: an indicator,
a sighting, and a corresponding relationship between them. The actual mapping
from HIBP fields to CTIM fields is quite straightforward.

The only non-obvious piece of that mapping is the logic for inferring the
actual values for the `confidence` and `severity` fields. Suppose there is
a `breach` for some email. If the `breach` is verified (field `IsVerified`,
type `boolean`), then the value for `confidence` will be `High`, otherwise
`Medium`. At the same time, each `breach` also knows some information about
the nature of the data compromised in the `breach` as a string array of
impacted data classes (field `DataClasses`, type `string[]`). Thus if the
`breach` is verified and the password is also known to be compromised (i.e. the
data classes contain the `Passwords` data class), then the value for `severity`
will be `High`, otherwise `Medium`.

The rules mentioned above can be easily expressed in Python using the following
code snippet:
```python
entity['confidence'] = ['Medium', 'High'][breach['IsVerified']]

entity['severity'] = ['Medium', 'High'][
    breach['IsVerified'] and 'Passwords' in breach['DataClasses']
]
```
(the `entity` here is either an `indicator` or a `sighting`).
