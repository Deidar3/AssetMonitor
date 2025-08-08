# AssetMonitor

The main purpose of this tool is to monitor assets and alert when new assets are discovered. It leverages the `subfinder` and `httpx` tools by providing either a single domain or a file containing multiple domains. The tool integrates with the HackerOne API to scan wildcard domains from program scopes.

If a Discord webhook is configured in `config.yaml`, the tool will send notifications about newly found assets discovered by subfinder and alive domains identified using httpx. When both the `--screenshots` option and the Discord webhook are enabled, screenshot files will be sent in a `.tar.gz` archive format (.zip was blocked during testing).

On the first run, only `subdomains.txt` files will be created. On subsequent runs, the tool will compare the current results to the existing `subdomains.txt` files. If new assets are found, whether alive or not, the results will be saved locally (regardless of Discord notifications) and sent to the Discord webhook if configured. Newly found subdomains are appended to the `subdomains.txt` file.

Domains can also be provided with the `http` or `https` protocols (e.g., https://example.com/), and the tool will automatically extract the domain.

### Prerequisites: 
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [httpx](https://github.com/projectdiscovery/httpx)
- [Go version 1.24](https://go.dev/doc/install) or higher
- Python dependencies: 
`pip install -r requirements.txt`

### Run using docker image:
#### Build image:
```
docker build -t assetmonitor .
```
#### Example usage:
```
docker run --rm \
  -v ~/.config/assetmonitor:/root/.config/assetmonitor \
  assetmonitor -d example.com
```

### Usage
```yaml
usage: assetmonitor.py [options]

options:
  -h, --help            show this help message and exit

  -d, --domain DOMAIN   Domain to enumerate

  -o, --output OUTPUT   Output directory (default assetmonitor)

  -l, --list LIST       File containing list of domains

  -ss, --screenshots    Take screenshots of alive subdomains using a headless browser from HTTPX

  -h1, --hackerone HACKERONE File containing names of hackerone programs to monitor

  -h1p, --hackeroneprogram HACKERONEPROGRAM Single HackerOne program to monitor

  -u, --update          Update hackerone assets scope from loaded file

  -w, --workers WORKERS Number of concurrent workers (default 5)

  -dc, --discord        Enable Discord notifications via webhook provided in config.yaml
  
```

#### Examples
`python3 assetmonitor.py -l domains_file.txt`

`python3 assetmonitor.py -dc -d example.com`

`python3 assetmonitor.py -ss -dc -h1 hackerone_programs.txt -o mydirectory`

`python3 assetmonitor.py -h1p programname -w 3`

## Example config.yaml
Config will be stored in $HOME/.config/assetmonitor/config.yaml
```
hackerone-username: test123
hackerone-api: TQihxQSUThzYmOsnhBHUZWUV9ZPPNjmEJK1FcLnZtTc=
discord-webhook: https://discord.com/api/webhooks/404386597852410728/yqbVC8RRO0vmD8bz5DE9yQ5b04LbVB6xYughB7lfqAZwDkLGoYbNjz9L8SZRLz 
```

## Additional information:
- For better results, insert API keys in the subfinder config
- The HackerOne scope fetching feature does not verify if domains are in scope after running subfinder and httpx, please review the final results to ensure they are relevant!