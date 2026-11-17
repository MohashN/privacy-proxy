# Security policy

## Reporting a vulnerability

Report it privately through GitHub's private vulnerability reporting: on this
repository, open the **Security** tab and choose **Report a vulnerability**. Please
don't open a public issue or pull request for it.

A good report says what a request can get past the proxy, or what the proxy can be
made to reveal, and gives the smallest request or configuration that shows it. Use
made-up data: a test number such as `+44 20 7946 0958`, never a real person's.

Things that count as a vulnerability here:

- data a Detector is documented to catch leaving in a request that was not refused
  or masked;
- request text, a key or a header value reaching the log;
- a proxy key getting past its model list or its spend cap;
- a request that makes the proxy pass traffic on unchecked.

The limits listed under "What it doesn't catch" in the [README](README.md) are known
and documented, not vulnerabilities. Ideas for closing them are welcome as ordinary
issues.

## Supported versions

Fixes go into the latest minor release. Older releases get none: upgrade to the
latest.
