# Project guidance

## Public repository safety

This repository is public. Never commit private hostnames, IP addresses,
device names, account details, personal filesystem paths, or internal network
topology. Describe routing behavior generically and keep private implementation
details in private documentation.

## Testing

Run the fast test suite from the repository root:

```bash
node --check switchy.pac.js
node test-switchy-pac.js
```
