# Unitas

[![PyPI version](https://img.shields.io/pypi/v/unitas.svg)](https://pypi.org/project/unitas/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Unitas is a powerful network scan parser and analyzer tool designed to simplify the process of managing and analyzing network scan results. With Unitas, you can easily parse scan files from various tools, including Nmap and Nessus, merge scan results, search for specific ports or services, generate markdown reports, and even automate the export of scans from Nessus.

## Features

- Parse scan files from Nmap and Nessus
- Merge multiple scan results into a single, comprehensive report per scanner 
- Search for specific ports or services across all scanned hosts
- Track source information for each port (which scanner and file detected it)
- Generate well-formatted markdown reports for easy sharing and collaboration
- Export scans from Nessus for seamless integration with your workflow
- Identify hosts that are up but have no open ports
- Generate Nmap commands to re-scan ports that were not service scanned
- Filter out uncertain services to focus on confirmed findings
- Concurrent parsing of scan files for improved performance
- Interactive web visualization with built-in HTTP server

## Installation

```
pip install unitas
```

## Usage

To use Unitas, run the `unitas.py` script with the appropriate arguments:

```
unitas /path/to/scan/folder [options]
```

### Options

- `-v`, `--verbose`: Enable verbose output (sets log level to DEBUG)
- `-V`, `--version`: Show the version number and exit
- `-u`, `--update`: Update existing markdown from state.md or stdin
- `-s`, `--search`: Search for specific port numbers or service names (comma-separated)
- `-U`, `--url`: Adds the protocol of the port as URL prefix (used for search)
- `-w`, `--urls [web|all]`: Print the services as URLs, one per line, to pipe into other tools
- `-S`, `--service`: Show only service scanned ports 
- `-r`, `--rescan`: Print an Nmap command to re-scan the ports not service scanned
- `-e`, `--export`: Export all scans from Nessus
- `-m`, `--merge`: Merge scans in the folder
- `-g`, `--grep`: Print host and ports in a grep-able format (including hosts that have no open ports)
- `-j`, `--json`: Export scan results as a JSON file that can be loaded by the HTML viewer
- `-o`, `--origin`: Show origin information (source scanner type, file, and date) for each port
- `-M`, `--mac-report`: Generate a markdown report of MAC addresses for network inventory
- `-H`, `--http-server`: Start an HTTP server with interactive visualization of scan results
- `-R`, `--html-report [FILE]`: Write a single self-contained HTML report (default: `unitas_report.html`)
- `--port`: Specify the port for the HTTP server (default: 8000)
- `--read-only`: With `-H`, never write `state.md`
- `--report-title`: Specify a custom title for the merged Nessus report

### Service URLs

To feed the scan results into other tooling, print the services as URLs. Only the URLs
go to stdout (logging goes to stderr), so the output can be piped directly:

```
unitas /path/to/scan/folder -w | tee web-targets.txt
eyewitness --web -f web-targets.txt
```

```
http://10.31.112.21:80
https://10.31.112.21:443
http://10.31.112.22:8080
```

`-w` (or `--urls web`) prints http/https services only: ports whose service name looks
like HTTP, plus well known web ports that were only port scanned. TLS is taken from the
service name, the TLS comment or the port. `--urls all` uses the service name as scheme
for every identified service instead:

```
unitas /path/to/scan/folder --urls all
ssh://10.31.112.21:22
smb://10.31.112.21:445
```

Combine it with `-S` to skip ports that were never service scanned.

## Interactive Visualization

Unitas includes a built-in web interface for visualizing your network scan results. This interactive tool allows you to explore your network topology, filter by services and ports, and perform various analyses.

### Using the Web Interface

To start the web visualization server:

```
unitas /path/to/scan/folder -H
```

The server keeps the folder open rather than serialising it once:

1. Every scan file in the folder is parsed and folded into one state
2. The triage is merged in from `<scan folder>/state.md`, which the server owns
3. A local HTTP server starts on loopback (default port 8000) and your browser opens
4. The folder is re-read every two seconds, so a scan dropped in while the server runs
   shows up without a restart

Because `state.md` lives in the scan folder and is rewritten atomically, the browser and
the CLI work on the same file:

```
unitas /path/to/scan/folder -H       # leave it running, triage as scans land
unitas /path/to/scan/folder -u       # picks up the same state.md
```

You can specify a custom port if needed:

```
unitas /path/to/scan/folder -H --port 9000
```

`--read-only` serves the folder without ever writing `state.md`, for a share you do not
own or an engagement folder you would rather not touch.

### Single File Report

To hand the results to someone else, or to archive them with the engagement, write the
viewer and the scan data into one HTML file:

```
unitas /path/to/scan/folder -R
```

The file opens straight from the filesystem, needs no server and no network connection
(the graph library ships with it), and contains every view of the web interface.

### Triage in the Browser

The Ports view is editable: the status column (TBD / In progress / Done) and the comment
column can be changed while working through the hosts. Both the Ports and the Hosts view
have a select column with shift-click ranges and a "Mark as" bar, so a run of ports or a
set of hosts is one gesture rather than one click per row; on the Hosts view it marks
every port of the selected hosts. Against a running `-H` server the edits go to
`<scan folder>/state.md`; from a single file report or a dropped JSON they are stored in
the browser and "Export state.md" writes them out in the format `unitas -u` merges back
in.

The search box takes field operators, so "445" does not also drag in every comment and
hostname containing it: `service:smb`, `port:445`, `state:tbd`, `net:10.31.112.`,
`comment:"default creds"`, `proto:udp`, `host:dc01`, and `-` in front of any clause (or a
bare word) negates it. Clauses combine with AND, and a bare word still matches the whole
row.

"Group by" turns the Ports view into a worklist: each service or subnet gets a header with
its own progress ("smb - 14 ports, 7 hosts, 3 done") and collapses once it is finished.
The counts follow the triage and the filters, and sorting a column sorts inside each group
rather than scattering them.

The keyboard triages the Ports and Hosts views without the mouse: `j`/`k` move the cursor,
`x` selects the row (`Shift` extends the range), `d`/`p`/`u` mark Done / In progress / TBD
-- the selection when there is one, otherwise the row under the cursor -- and `n` jumps
into the note, and `g` cycles the grouping.

"Copy Visible" copies whatever the current search and status filters leave on screen as
web URLs, `service://host:port` URLs, `ip:port` pairs, bare IPs, or an nmap re-scan
command -- the same rules the `-w/--urls` flag uses.

### Visualization Features

The web interface provides several powerful features:
- Interactive network graph showing hosts and services
- Filter by service type, port range, and subnets
- Highlight TLS/SSL services
- View detailed information about hosts and services
- Run automated analyses including:
  - Finding common services
  - Identifying network segments
  - Highlighting unusual ports
  - Finding most connected hosts
- Export the graph as a PNG image

To stop the server, press Ctrl+C in your terminal.

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
unitas /path/to/scan/folder -u state.md
```

Or to update the table using stdin:

```
cat updated_scan_results.md | unitas -u
```

This feature ensures that your comments and notes are retained while the table is updated with the latest scan results.

### Other Examples

Search for specific ports:
```
unitas /path/to/scan/folder -s "80,443"
```

Search for specific services with URL prefix (filter non service scanned entries):
```
unitas /path/to/scan/folder -s "http,https" -U --service
```

Generate an Nmap command to re-scan non-service scanned ports:
```
unitas /path/to/scan/folder -r
```

Export scans from Nessus:
```
unitas /path/to/scan/folder -e
```

Merge scan files in a folder:
* creates a single nessus file for all nessus scans, two duplicate scan will lead to duplicate hosts in the scan
* creates a single nmap scan xml and html report if xsltproc is installed
```
unitas /path/to/scan/folder -m
```

Output hosts and ports in a grepable format:
```
unitas /path/to/scan/folder -g
```

Export scan results as JSON and launch the interactive visualization:
```
unitas /path/to/scan/folder -H
```

## Configuration

Unitas uses a configuration file (`~/.unitas`) to store Nessus API credentials. If the configuration file doesn't exist, Unitas will create a template for you. Make sure to update the `secret_key`, `access_key`, and `url` fields with your Nessus API credentials.

## Changelog

### 1.2.0
* Added MAC address reporting with `-M/--mac-report` flag
* Network inventory feature to track MAC addresses and vendors
* Markdown output format for MAC address reports
* Integrates with MAC vendor lookup

### 1.1.0
* Added interactive network visualization with `-H/--http-server` flag
* Built-in HTTP server for viewing network topology
* Interactive graph with filtering and analysis capabilities
* Auto-loading of scan data in the web interface
* Customizable server port with `--port` option

### 1.0.4

* nessus title feature
* fixed a bug in merge detection
* added github workflow

### 1.0.3
* improved the service lookup
* fixed a bug if a directory with .xml is found

### 1.0.2
* fixed bug #1
* fixed bug #2
* improved nessus export (speedup by fixing the file exist check and change filename of exports to include the scan id)
* added grep-able output feature
* improved command for re-scan nmap command

### 1.0.1
* improved merging
* added docs 

### 1.0.0
* first release

## Contributing

Contributions are welcome! If you find a bug or have a feature request, please open an issue on the GitHub repository. If you'd like to contribute code, please fork the repository and submit a pull request.

## Support

If you find this project useful, consider supporting development:

[![Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/f0rw4rd)

## License

This project is licensed under the [GPL-3.0 License](LICENSE).