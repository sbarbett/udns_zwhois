# udns_zwhois

`udns_zwhois` is a Python-based CLI tool designed to fetch Zone and WHOIS properties from UltraDNS.

## Directory Structure

```
udns_zwhois
├── src
│   └── zwhois.py
├── README.md
├── LICENSE.md
├── .gitignore
└── requirements.txt
```

## Requirements

- Python 3.x
- `requests`
- `python-whois`

You can install the required Python packages using the following command:

```
pip install -r requirements.txt
```

## Usage

You can run the `zwhois.py` script from the command line using the following syntax:

```
python3 src/zwhois.py --username YOUR_USERNAME --password YOUR_PASSWORD
```

Or by using a bearer token:

```
python3 src/zwhois.py --token YOUR_BEARER_TOKEN
```

Optionally, you can write the output to a file in JSON or CSV format:

```
python3 src/zwhois.py --token YOUR_BEARER_TOKEN --output-file output.json
```

Or

```
python3 src/zwhois.py --token YOUR_BEARER_TOKEN --output-file output.csv --format csv
```

## License

This project is licensed under the terms of the MIT license. For more details, see [LICENSE.md](./LICENSE.md).
