# Contributing to RemotePower

Pull requests welcome!

## How to contribute

1. Fork the repo
2. Create a branch from `devel` (not `main`)
3. Make your changes
4. Test with `install-server.sh` on a clean machine
5. Open a PR against `devel`

## Ideas for contributions

- Docker Compose setup
- Additional webhook formats
- Windows client agent
- Metrics / history graphs
- Rate limiting on the API

## Code style

- Python: follow the existing CGI style, no extra dependencies unless essential
- Bash: `set -euo pipefail`, same colour helpers as install scripts
- JS: vanilla only, no frameworks
