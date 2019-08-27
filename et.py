#!/usr/bin/env python3

from argparse import ArgumentParser
from etrecon.etrecon import ETRecon


if '__main__' == __name__:
    # generate args
    arg_parser = ArgumentParser('ETRecon - analyze pcap files in order to detect who i.e. a device is phoning to. '
                                'Like ET phoning home. Get it?')
    arg_parser.add_argument('-f', '--files', required=True, nargs='+', help='One or more pcap files to analyze')
    arg_parser.add_argument('-i', '--ignoreips', required=False, nargs='*', default=[],
                            help='Exclude these IPs from the collected IPs communication list')
    arg_parser.add_argument('--displayfilter', required=False, default='tcp or udp',
                            help='Set wireshark display filter. Default: "tcp or udp"')
    arg_parser.add_argument('--jsonfile', required=False, help='Write output to JSON file')
    # parse args
    args = arg_parser.parse_args()

    # generate instance
    etr = ETRecon()
    etr.ignore_ips = set(args.ignoreips)
    etr.analyze_capture(args.files, args.displayfilter)

    print('IPs communicating:')
    print('\n'.join(etr.destination_ips))
    print('')

    # print results
    print('Resolved DNS names:')
    for name, ips in etr.dns_names.items():
        print('{}: {}'.format(name, ', '.join(ips)))
    print('')

    print('Used SNI:')
    for sni, ips in etr.tls_sni.items():
        print('{}: {}'.format(sni, ', '.join(ips)))
    print('')

    print('Used HTTP hosts:')
    for name, ips in etr.http_hosts.items():
        print('{}: {}'.format(name, ', '.join(ips)))
    print('')

    print('Unhandled protocols:')
    print(', '.join(etr.unhandled_protocols))

    if args.jsonfile:
        etr.write_json(args.jsonfile)
        print('Wrote JSON to: "{}"'.format(args.jsonfile))
