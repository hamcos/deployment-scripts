#!/usr/bin/env python3
# encoding: utf-8

__license__ = 'AGPL-3.0'
__author__ = 'Robin Schneider <robin.schneider@hamcos.de>'
#
# @author Copyright (C) 2016 Robin Schneider <ypid@riseup.net>
# @company hamcos IT Service GmbH http://www.hamcos.de
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, version 3 of the
# License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
Small script to parse the Microsoft Windows DHCP Server leases CSV export and
convert it to the workstation format paedML Linux 6.0 can import.
Microsoft Windows Server → paedML Linux 6.0: One step in the right direction ;)
Implementing a second export format matching the
[linuxmuster.net](https://linuxmuster.net/) format should also be possible.

Example structure of the input file:

IP-Adresse,Name,Leaseablaufdatum,Typ,Eindeutige Kennung,Beschreibung
192.0.2.25,DAP-2310.example.com,Reservierung (aktiv),DHCP,685d4351adcf,AP05
"""

__version__ = '0.2'
__status__ = 'Production'

# core modules {{{
import logging
import re
import csv
import socket
# }}}

# }}}

CSV_field_not_used = ''

client_type_fully_managed = re.compile(
    r'''
    (:?
        (:?
            pc|
            nb|
            computer|
        )[0-9]+
        |
        teacher|
        lehrer
    )
    ''',
    re.IGNORECASE | re.VERBOSE
)

client_type_ip_managed = re.compile(
    r'''
    (:?
        (:?
            ap|
            printer
        )[0-9]+
    )
    ''',
    re.IGNORECASE | re.VERBOSE
)


# https://stackoverflow.com/a/4017219
def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True


def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True


def is_dublicate_hostname(store_info, hostname, row_line):
    for mac_address, info in store_info.items():
        if info['hostname'] == hostname:
            logger.warning(
                "Ignoring line: Duplicate ({}) hostname: {}".format(
                    hostname,
                    row_line,
                )
            )
            return True
    return False


# main {{{
if __name__ == '__main__':
    from argparse import ArgumentParser

    # Script Arguments {{{
    args_parser = ArgumentParser(
        description=__doc__,
        # epilog=__doc__,
    )
    args_parser.add_argument(
        '-V', '--version',
        action='version',
        version='%(prog)s {version}'.format(version=__version__)
    )
    args_parser.add_argument(
        '-d', '--debug',
        help="Print lots of debugging statements",
        action="store_const",
        dest="loglevel",
        const=logging.DEBUG,
        default=logging.WARNING,
    )
    args_parser.add_argument(
        '-v', '--verbose',
        help="Be verbose",
        action="store_const",
        dest="loglevel",
        const=logging.INFO,
    )
    args_parser.add_argument(
        '-i', '--input-file',
        help="File path to the input file to process.",
        required=True,
    )
    args_parser.add_argument(
        '-o', '--output-file',
        help="Where to write the output file."
        " If not given, no final output will be produced.",
    )
    args_parser.add_argument(
        '-f', '--output-format',
        help="Format of the output file."
        " Default: %(default)s.",
        default='PaedML_Linux_6',
        choices=[
            'PaedML_Linux_6',
            #  'linuxmuster.net',
        ],
    )
    args_parser.add_argument(
        '-s', '--subnetwork-id',
        help="New subnetwork address plus subnetwork prefix for the hosts."
        " Default: %(default)s.",
        default='10.1.0.0/24'
    )
    args_parser.add_argument(
        '-I', '--ignore-fqdn-regex',
        help="Regular expression checked against the input FQDNs."
        " If the regular expression matches, the FQDN will not be exported.",
    )
    args_parser.add_argument(
        '-r', '--rename-via-csv',
        help="Allows you to do mass rename via a provided CSV file."
        " It is based on substation using regular expressions."
        " The first column is case insensitive search pattern,"
        " the second one the replacement string.",
    )
    args = args_parser.parse_args()
    logger = logging.getLogger(__file__)
    logging.basicConfig(
        format='%(levelname)s: %(message)s',
        level=args.loglevel,
    )
    # }}}

    store_info = dict()
    ignore_fqdn_re = None
    if args.ignore_fqdn_regex:
        ignore_fqdn_re = re.compile(args.ignore_fqdn_regex)

    replacement_spec = dict()
    if args.rename_via_csv:
        with open(args.rename_via_csv, newline='') as csvfile:
            spamreader = csv.reader(csvfile, delimiter=',', quotechar='|')
            for item in spamreader:
                if len(item) != 2:
                    logger.debug(
                        "Line has not exactly two cells "
                        " related to --rename-via-csv: {}".format(
                            item,
                        )
                    )
                    continue

                if item[0] in replacement_spec:
                    logger.warning(
                        "Line with search pattern ({}) appeared"
                        " related to --rename-via-csv: {}".format(
                            item[0],
                            item,
                        )
                    )
                    continue
                replacement_spec[item[0]] = item[1]

    with open(args.input_file, newline='') as csvfile:
        spamreader = csv.reader(csvfile, delimiter=',', quotechar='|')
        for item in spamreader:
            row_line = ', '.join(item)
            ip_address = item[0]
            # RFC4343: Domain Name System (DNS) Case Insensitivity
            # Clarification:
            fqdn = item[1].lower()
            hostname, _ = '{}.'.format(fqdn).split('.', 1)
            mac_address = item[4].lower()
            description = item[5]

            if ignore_fqdn_re and ignore_fqdn_re.search(fqdn):
                logger.info(
                    "Ignoring line: FQDN ({}) matched"
                    " --ignore-fqdn-regex: {}".format(
                        fqdn,
                        row_line,
                    )
                )
                continue

            if not is_valid_ipv4_address(ip_address):
                logger.info(
                    "Ignoring line: Invalid ({}) IP address: {}".format(
                        ip_address,
                        row_line,
                    )
                )
                continue

            mac_address_split = re.findall(r'[0-9a-f]{2}', mac_address)
            if not len(mac_address_split) == 6:
                # I have seen a MAC address with a tailing '00000' behind.
                # But in this case, a second entry with the same, valid MAC
                # address followed.
                # Not sure what that says about the quality of the Windows DHCP
                # Server …
                logger.warning(
                    "Ignoring line: Invalid ({}) MAC address: {}".format(
                        mac_address,
                        row_line,
                    )
                )
                continue
            mac_address = ':'.join(mac_address_split)

            if mac_address in store_info:
                logger.warning(
                    "Ignoring line: Duplicate ({}) MAC address: {}".format(
                        mac_address,
                        row_line,
                    )
                )
                continue

            if replacement_spec:
                for pattern, replace_with in replacement_spec.items():
                    hostname = re.sub(
                        pattern,
                        replace_with.format(
                            description,
                        ),
                        hostname,
                        0,
                        re.IGNORECASE,
                    )
                hostname = hostname.lower()

            lmz_paedml_linux_type = ''
            # Windows-System managed via OPSI          :  windows
            # Univention Corporate Client (Linux, UCC) :  ucc
            # Device with IP address (printer, AP)     :  ipmanagedclient

            if client_type_fully_managed.search(hostname):
                lmz_paedml_linux_type = 'windows'

            if client_type_ip_managed.search(hostname):
                lmz_paedml_linux_type = 'ipmanagedclient'

            if is_dublicate_hostname(store_info, hostname, row_line):
                continue

            store_info[mac_address] = {
                'ip_address': ip_address,
                'hostname': hostname,
                'description': description,
                'lmz_paedml_linux_type': lmz_paedml_linux_type,

            }

    if logger.isEnabledFor(logging.DEBUG):
        import pprint
        pprint.pprint(store_info)

    # Make output deterministic.
    store_info_sorted = sorted(
        store_info.items(),
        key=lambda x: '{}{}'.format(x[1]['hostname'], x[0])
    )

    if args.output_format == 'PaedML_Linux_6' and args.output_file:
        with open(args.output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(
                f,
                delimiter='\t',
                # https://stackoverflow.com/a/17725590
                lineterminator='\n',
                quotechar='|',
                quoting=csv.QUOTE_MINIMAL,
            )
            for item in store_info_sorted:
                writer.writerow([
                    item[1]['lmz_paedml_linux_type'],
                    item[1]['hostname'],
                    item[0],
                    'schule',  # Default LDAP OU for paedML Linux 6.0.
                    args.subnetwork_id,
                    item[1]['description'],  # Inventory ID
                    CSV_field_not_used,
                    CSV_field_not_used,
                    CSV_field_not_used,
                    CSV_field_not_used,
                    0,  # BIOS: 0; UEFI: 1
                    ''  # Additional MAC addresses, separated by comma

                ])

# }}}
