# privacy-proxy

A self-hosted proxy between AI tools and a cloud model API that inspects every request and
stops phone numbers, national IDs and other private data from leaving.

## Language

**Operator**:
The person or organisation that runs a proxy and writes its Policy file and Deny-list.
_Avoid_: Owner, admin

**Detector**:
One check the proxy runs on a request, for one kind of private data (a phone number, a
Swedish personnummer, a card number, the Deny-list).
_Avoid_: entity, recogniser, rule

**Detection**:
One hit of a Detector in a request: its kind and where it was found, never its text.
_Avoid_: finding, match

**Refusal**:
The proxy's answer to a request it will not forward: an error to the caller naming the kind
of data found, never the data itself.
_Avoid_: block, rejection

**Masking**:
Forwarding a request with each Detection replaced by a Placeholder, which the reply keeps.
_Avoid_: redaction, anonymisation, strip and restore

**Placeholder**:
The stand-in text Masking puts where a Detection was, naming its kind and its order in the
request.
_Avoid_: token, tag

**Deny-list**:
An optional file of one Operator's own identifiers (names, addresses, odd numbers), held only as
salted hashes, that the proxy treats as private data.
_Avoid_: hard list, blocklist

**Policy file**:
The one YAML file that says which Detectors a proxy runs, in which regions and
countries, and whether each ends in a Refusal or Masking.
_Avoid_: config, rules file
