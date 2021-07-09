[![Gitter Chat](https://img.shields.io/badge/gitter-join%20chat-brightgreen.svg)](https://gitter.im/CiscoSecurity/Threat-Response "Gitter Chat")

# NOTE! This code has been upgraded and the current release no longer supports installation in AWS
If you wish to deploy in AWS, use [this](https://github.com/CiscoSecurity/tr-05-serverless-have-i-been-pwned/releases/tag/v1.2.1) previous release.

# Have I Been Pwned Relay (Cisco Hosted)

A Cisco SecureX Concrete Relay implementation using
[Have I Been Pwned](https://haveibeenpwned.com/FAQs)
as a third-party Cyber Threat Intelligence service provider.

The Relay itself is just a simple application written in Python that can be easily packaged and deployed.  This relay is now Cisco Hosted and no longer requires AWS Lambda.

The code is provided here purely for educational purposes.

## Rationale

- We need an application that will translate API requests from SecureX Threat Response to the third-party integration, and vice versa.
- We need an application that can be completely self contained within a virtualized container using Docker.


## Testing (Optional)

If you want to test the application you will require Docker and several dependencies from the [requirements.txt](code/requirements.txt) file:
```
pip install --upgrade --requirement code/requirements.txt
```

You can perform two kinds of testing:

- Run static code analysis checking for any semantic discrepancies and [PEP 8](https://www.python.org/dev/peps/pep-0008/) compliance:

  `flake8 code`

- Run the suite of unit tests and measure the code coverage:
  `cd code`
  `coverage run --source api/ -m pytest --verbose tests/unit/ && coverage report`

**NOTE.** If you need input data for testing purposes you can use data from the
[observables.json](code/observables.json) file.

### Building the Docker Container
In order to build the application, we need to use a `Dockerfile`.  

 1. Open a terminal.  Build the container image using the `docker build` command.

```
docker build -t tr-05-have-i-been-pwned .
```

 2. Once the container is built, and an image is successfully created, start your container using the `docker run` command and specify the name of the image we have just created.  By default, the container will listen for HTTP requests using port 9090.

```
docker run -dp 9090:9090 --name tr-05-have-i-been-pwned tr-05-have-i-been-pwned
```

 3. Watch the container logs to ensure it starts correctly.

```
docker logs tr-05-have-i-been-pwned
```

 4. Once the container has started correctly, open your web browser to http://localhost:9090.  You should see a response from the container.

```
curl http://localhost:9090
```

## Implementation Details

This application was developed and tested under Python version 3.9.

### Implemented Relay Endpoints

- `POST /health`
  - Verifies the Authorization Bearer JWT and decodes it to restore the
  original credentials.
  - Authenticates to the underlying external service to check that the provided
  credentials are valid and the service is available at the moment.

- `POST /observe/observables`
  - Accepts a list of observables and filters out unsupported ones.
  - Verifies the Authorization Bearer JWT and decodes it to restore the
  original credentials.
  - Makes a series of requests to the underlying external service to query for
  some cyber threat intelligence data on each supported observable.
  - Maps the fetched data into appropriate CTIM entities.
  - Returns a list per each of the following CTIM entities (if any extracted):
    - `Indicator`,
    - `Sighting`,
    - `Relationship`.

- `POST /refer/observables`
  - Accepts a list of observables and filters out unsupported ones.
  - Builds a search link per each supported observable to pivot back to the
  underlying external service and look up the observable there.
  - Returns a list of those links.
  
- `POST /version`
  - Returns the current version of the application.

### Supported Types of Observables

- `email`

### CTIM Mapping Specifics

Each HIBP breach for an email generates 3 CTIM entities: an `Indicator`,
a `Sighting`, and the corresponding `Relationship` between them. The actual
mapping from HIBP fields to CTIM fields is quite straightforward.

The only non-obvious piece of the mapping is the logic for inferring the
actual values for the `confidence` and `severity` fields. Suppose there is
a `breach` for an email. If the `breach` is verified (field `IsVerified`,
type `boolean`), then the value for `confidence` will be `High`, otherwise
`Medium`. At the same time, each `breach` also knows some information about
the nature of the data compromised in the `breach` as a string array of
impacted data classes (field `DataClasses`, type `string[]`). Thus, if the
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
(the `entity` here is either an `Indicator` or a `Sighting`).
