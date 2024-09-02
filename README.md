# Unitas

Unitas is a powerful network scan parser and analyzer tool designed to simplify the process of managing and analyzing network scan results. With Unitas, you can easily parse scan files from various tools, including Nmap and Nessus, merge scan results, search for specific ports or services, generate markdown reports, and even automate the export of scans from Nessus.

## Features

- Parse scan files from Nmap and Nessus
- Merge multiple scan results into a single, comprehensive report
- Search for specific ports or services across all scanned hosts
- Generate well-formatted markdown reports for easy sharing and collaboration
- Export scans from Nessus for seamless integration with your workflow
- Identify hosts that are up but have no open ports
- Generate Nmap commands to re-scan ports that were not service scanned
- Filter out uncertain services to focus on confirmed findings
- Concurrent parsing of scan files for improved performance

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/unitas.git
   ```

2. Navigate to the project directory:
   ```
   cd unitas
   ```

## Usage

To use Unitas, run the `unitas.py` script with the appropriate arguments:

```
python unitas.py /path/to/scan/folder [options]
```

### Options

- `-v`, `--verbose`: Enable verbose output (sets log level to DEBUG)
- `-V`, `--version`: Show the version number and exit
- `-u`, `--update`: Update existing markdown from state.md or stdin
- `-s`, `--search`: Search for specific port numbers or service names (comma-separated)
- `-U`, `--url`: Adds the protocol of the port as URL prefix
- `-S`, `--service`: Show only service scanned ports
- `-r`, `--rescan`: Print an Nmap command to re-scan the ports not service scanned
- `-e`, `--export`: Export all scans from Nessus
- `-m`, `--merge`: Merge scans in the folder

### Examples

Parse scan files in a folder and generate a markdown report:
```
python unitas.py /path/to/scan/folder
```

Search for specific ports:
```
python unitas.py /path/to/scan/folder -s "80,443"
```

Search for specific services with URL prefix:
```
python unitas.py /path/to/scan/folder -s "http,https" -U
```

Generate an Nmap command to re-scan non-service scanned ports:
```
python unitas.py /path/to/scan/folder -r
```

Export scans from Nessus:
```
python unitas.py /path/to/scan/folder -e
```

Merge scan files in a folder:
```
python unitas.py /path/to/scan/folder -m
```

## Configuration

Unitas uses a configuration file (`~/.unitas`) to store Nessus API credentials. If the configuration file doesn't exist, Unitas will create a template for you. Make sure to update the `secret_key`, `access_key`, and `url` fields with your Nessus API credentials.

## Contributing

Contributions are welcome! If you find a bug or have a feature request, please open an issue on the GitHub repository. If you'd like to contribute code, please fork the repository and submit a pull request.

## License

This project is licensed under the [GPL-3.0 License](LICENSE).
