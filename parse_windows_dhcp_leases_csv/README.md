# parse_windows_dhcp_leases_csv

Small script to parse the Microsoft Windows DHCP Server leases CSV export and
convert it to the workstation format paedML Linux 6.0 can import.
Microsoft Windows Server → paedML Linux 6.0: One step in the right direction :wink:
Implementing a second export format matching the
[linuxmuster.net](https://linuxmuster.net/) format should also be possible.

Example structure of the input file:

    IP-Adresse,Name,Leaseablaufdatum,Typ,Eindeutige Kennung,Beschreibung
    192.0.2.25,DAP-2310.example.com,Reservierung (aktiv),DHCP,685d4351adcf,AP05

## Features

* Autodetection of the type of the host based on hostname presets.
* Regex substitutions for the hostname.
* Filter out hostnames.
* Error checking.

## Synopsis

```
usage: parse_windows_dhcp_leases_csv.py [-h] [-V] [-d] [-v] -i INPUT_FILE
                                        [-o OUTPUT_FILE] [-f {PaedML_Linux_6}]
                                        [-s SUBNETWORK_ID]
                                        [-I IGNORE_FQDN_REGEX]
                                        [-r RENAME_VIA_CSV]

optional arguments:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit
  -d, --debug           Print lots of debugging statements
  -v, --verbose         Be verbose
  -i INPUT_FILE, --input-file INPUT_FILE
                        File path to the input file to process.
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Where to write the output file. If not given, no final
                        output will be produced.
  -f {PaedML_Linux_6}, --output-format {PaedML_Linux_6}
                        Format of the output file. Default: PaedML_Linux_6.
  -s SUBNETWORK_ID, --subnetwork-id SUBNETWORK_ID
                        New subnetwork address plus subnetwork prefix for the
                        hosts. Default: 10.1.0.0/24.
  -I IGNORE_FQDN_REGEX, --ignore-fqdn-regex IGNORE_FQDN_REGEX
                        Regular expression checked against the input FQDNs. If
                        the regular expression matches, the FQDN will not be
                        exported.
  -r RENAME_VIA_CSV, --rename-via-csv RENAME_VIA_CSV
                        Allows you to do mass rename via a provided CSV file.
                        It is based on substation using regular expressions.
                        The first column is case insensitive search pattern,
                        the second one the replacement string.
```

## Example usage

Using [this input from Windows DHCP Server](https://github.com/hamcos/deployment-scripts/blob/master/parse_windows_dhcp_leases_csv/example_data/win_dhcp_export.csv)
combined with [this regex rename specification](https://github.com/hamcos/deployment-scripts/blob/master/parse_windows_dhcp_leases_csv/example_data/regex_rename.csv), the following script invocation:

```Shell
./parse_windows_dhcp_leases_csv.py --input-file example_data/win_dhcp_export.csv --rename-via-csv example_data/regex_rename.csv --ignore-fqdn-regex '(:?phone|android|privat)' --output-file example_data/export_file_for_paedml_linux_6
```

is able to produce [this output suitable for importing by paedML Linux 6.0](https://github.com/hamcos/deployment-scripts/blob/master/parse_windows_dhcp_leases_csv/example_data/export_file_for_paedml_linux_6).

## Quick and dirty integration testing

A mini working example is bundled, just invoke `make --always-make examples` to run it.
The files in the `example_data/` directory should not be changed by running this command as the output formats are deterministic.
You can use this as simple integration testing when working on the script.
