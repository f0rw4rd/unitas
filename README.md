# Unitas

Unitas is a powerful network scan parser and analyzer tool designed to simplify the process of managing and analyzing network scan results. With Unitas, you can easily parse scan files from various tools, including Nmap and Nessus, merge scan results, search for specific ports or services, generate markdown reports, and even automate the export of scans from Nessus.

## Features

- Parse scan files from Nmap and Nessus
- Merge multiple scan results into a single, comprehensive report per scanner 
- Search for specific ports or services across all scanned hosts
- Generate well-formatted markdown reports for easy sharing and collaboration
- Export scans from Nessus for seamless integration with your workflow
- Identify hosts that are up but have no open ports
- Generate Nmap commands to re-scan ports that were not service scanned
- Filter out uncertain services to focus on confirmed findings
- Concurrent parsing of scan files for improved performance

## Installation

```
pip install git+https://github.com/f0rw4rd/unitas@latest
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
- `-U`, `--url`: Adds the protocol of the port as URL prefix (used for search)
- `-S`, `--service`: Show only service scanned ports 
- `-r`, `--rescan`: Print an Nmap command to re-scan the ports not service scanned
- `-e`, `--export`: Export all scans from Nessus
- `-m`, `--merge`: Merge scans in the folder


## Markdown Table Output

The markdown output looks something like this: 

|IP|Hostname|Port|Status|Comment|
|--|--|--|--|---|
|10.31.112.29  |qa3app09                |445/tcp(smb)          |TBD|                             |
|10.31.112.29  |qa3app09                |3389/tcp(msrdp)       |TBD|TLS                          |
|12.233.108.201|preprod.boardvantage.net|443/tcp(https?)       |TBD|                             |
|74.207.244.221|scanme.nmap.org         |22/tcp(ssh)           |TBD|OpenSSH 5.3p1 Debian 3ubuntu7|
|74.207.244.221|scanme.nmap.org         |80/tcp(http)          |TBD|Apache httpd 2.2.14          |
|198.38.82.159 |joaquinlp.me            |21/tcp(ftp?)          |TBD|                             |
|198.38.82.159 |joaquinlp.me            |25/tcp(smtp?)         |TBD|                             |

The markdown table generated by Unitas displays only the *open* ports discovered during the scan. Services marked with a question mark at the end (e.g., `http?`) indicate that the port was scanned, but no service information was obtained. In other words, these ports were simply port scanned and not service scanned.

The "Status" column in the markdown table does not represent the port state (e.g., open, closed, filtered) but rather serves as a status field for you to track your progress or add notes. You can use this column to mark ports that you have investigated or add any relevant comments.

Unitas also provides a useful feature that allows you to update your markdown table without losing your custom comments. This can be particularly helpful when you need to rerun scans and want to preserve your notes. To update the table, simply use the `-u` flag followed by the path to your `state.md` file or pipe the updated scan results to Unitas via stdin.

For example, to update the table in the `state.md` file:

```
python unitas.py /path/to/scan/folder -u state.md
```

Or to update the table using stdin:

```
cat updated_scan_results.md | python unitas.py -u
```

This feature ensures that your comments and notes are retained while the table is updated with the latest scan results.

### Other Examples

Search for specific ports:
```
python unitas.py /path/to/scan/folder -s "80,443"
```

Search for specific services with URL prefix (filter non service scanned entries):
```
python unitas.py /path/to/scan/folder -s "http,https" -U --service
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
* creates a single nessus file for all nessus scans, two duplicate scan will lead to duplicate hosts in the scan
* creates a single nmap scan xml and html report if xsltproc is installed
```
python unitas.py /path/to/scan/folder -m
```

## Configuration

Unitas uses a configuration file (`~/.unitas`) to store Nessus API credentials. If the configuration file doesn't exist, Unitas will create a template for you. Make sure to update the `secret_key`, `access_key`, and `url` fields with your Nessus API credentials.

## Changelog

### 1.0.2 (wip)
* fixed bug #1
* fixed bug #2

### 1.0.1
* improved merging
* added docs 

### 1.0.0
* first release

## Contributing

Contributions are welcome! If you find a bug or have a feature request, please open an issue on the GitHub repository. If you'd like to contribute code, please fork the repository and submit a pull request.

## License

This project is licensed under the [GPL-3.0 License](LICENSE).
