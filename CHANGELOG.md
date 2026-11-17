# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-17

### Added

- **Policy file.** One YAML file, named by `POLICY_PATH`, sets each Detector
  (`national_id`, `phone`, `card`, `iban`, `deny_list`) to `refuse`, `mask` or `off`.
  With no file, every Detector is on and refuses. A file the proxy can't use stops
  startup with a message naming the key, never a value.
- **Phone Detector.** Phone numbers written with a `+` are read for every country
  and, for each region listed under `phone.regions`, in that country's national
  format. By default (`match: grouped`) a number counts only when written with a `+`
  or a separator, never as a bare run of digits; `match: valid` reads any valid
  number.
- **National ID Detectors per country.** Validated ID numbers for 16 countries (SE,
  FI, DE, GB, US, PL, ES, IT, CA, AU, IN, KR, TH, TR, ZA, NG), chosen with
  `national_id.countries`. SE, FI, ES, IT and ZA are on by default.
- **Masking on the API lane.** With `action: mask`, a request carrying only hits of
  masked Detectors goes on with each hit replaced by a Placeholder such as
  `<PHONE_NUMBER_1>`, and the reply keeps the Placeholder. The masked body is checked
  again before it is sent. The Subscription lane refuses instead, and startup says
  so. The log line of a masked request carries `masked: true`.
- A startup line listing the Detectors that are on.
- Apache-2.0 licence, a public README with the threat model and a quickstart,
  `SECURITY.md`, `CONTRIBUTING.md` and this changelog.

### Changed

- **A default install now refuses more.** With no Policy file, a request carrying a
  phone number written with a `+`, or a valid Finnish, Spanish, Italian or South
  African ID, is refused, where before only Swedish personnummer, card numbers,
  IBANs and Deny-list entries were. To narrow it, set `phone: {action: off}` or
  `national_id: {countries: [SE]}` in a Policy file.
- **The Deny-list is optional.** With `DENYLIST_PATH` unset the proxy starts with no
  Deny-list and says so, where before it did not start. A path that is set but
  empty or unreadable still stops startup.
- `docker-compose.example.yml` starts with no other files: the Policy file, the
  Deny-list and the proxy keys are each switched on by their own variable and read
  from a `config` directory beside it. `PRIVACY_PROXY_IMAGE` picks the image.
