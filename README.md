# udns_zwhois

`udns_zwhois` is a Python-based CLI tool that interfaces with Vercara's UltraDNS API to fetch zone properties. It also supplements this data with additional information sourced from WHOIS lookups.

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
- The following Python libraries:
  - `requests`
  - `python-whois`
  - `tqdm`

### Installation

To install the required Python packages, navigate to the root directory of the project and execute:

```bash
pip install -r requirements.txt
```

## Usage

Run the `zwhois.py` script from the command line:

### Using credentials:

```bash
python3 src/zwhois.py --username YOUR_USERNAME --password YOUR_PASSWORD
```

### Using a bearer token:

```bash
python3 src/zwhois.py --token YOUR_BEARER_TOKEN
```

_Note: If you choose to supply a bearer token directly to the script, it will not be able to automatically refresh when it expires. For long-running processes, I recommend using credentials._

### Output Options:

You can specify the desired output format (either JSON or CSV) and write the results to a file:

```bash
python3 src/zwhois.py {AUTH_DETAILS} --output-file output.json --format json
```

Or for CSV format:

```bash
python3 src/zwhois.py {AUTH_DETAILS} --output-file output.csv --format csv
```

## Examples

- Fetching data using credentials and saving to a CSV:

  ```bash
  python3 src/zwhois.py --username admin --password secret123 --output-file data.csv --format csv
  ```

- Fetching data using a token and displaying on the terminal:

  ```bash
  python3 src/zwhois.py --token ABCDEFGHIJKLMNOPQRSTUVWXYZ
  ```

## License

This project is licensed under the terms of the MIT license. For more details, see [LICENSE.md](./LICENSE.md).
```