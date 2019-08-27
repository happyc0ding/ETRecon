from collections import OrderedDict
import json

import pyshark


class ETRecon:

    def __init__(self):
        # using lists to preserve order
        self.data = {
            'destination_ips': [],
            'dns_names': OrderedDict(),
            'tls_sni': OrderedDict(),
            'http_hosts': OrderedDict(),
            'unhandled_protocols':  [],
        }

        self.ignore_ips = set()

    @property
    def destination_ips(self):
        return self.data['destination_ips']

    @property
    def dns_names(self):
        return self.data['dns_names']

    @property
    def tls_sni(self):
        return self.data['tls_sni']

    @property
    def http_hosts(self):
        return self.data['http_hosts']

    @property
    def unhandled_protocols(self):
        return self.data['unhandled_protocols']

    def get_as_json(self):
        return json.dumps(self.data)

    def write_json(self, file_path):
        with open(file_path, 'w') as json_file:
            json.dump(self.data, json_file, indent=4)

    def analyze_capture(self, file_paths, display_filter):
        # iterate files
        for file_path in file_paths:
            # parse file
            with pyshark.FileCapture(file_path, display_filter=display_filter) as capture:
                for pkt in capture:
                    # get ip and dst port
                    dst_ip = ''
                    dst_port = ''
                    try:
                        dst_ip = pkt.ip.dst
                    except AttributeError:
                        try:
                            dst_ip = '[{}]'.format(pkt.ipv6.dst)
                        except AttributeError:
                            pass
                    try:
                        dst_port = pkt.tcp.dstport
                    except AttributeError:
                        try:
                            dst_port = pkt.udp.dstport
                        except AttributeError:
                            pass

                    # ignore pkts without ip and port
                    if not (dst_port and dst_ip):
                        if pkt.highest_layer not in self.unhandled_protocols:
                            self.unhandled_protocols.append(pkt.highest_layer)
                        continue
                    ip_port = '{}:{}'.format(dst_ip, dst_port)

                    # add communication
                    if dst_ip not in self.destination_ips and dst_ip not in self.ignore_ips:
                        self.destination_ips.append(dst_ip)

                    # handle dns
                    if 'dns' == pkt.highest_layer.lower():
                        if '1' == pkt.dns.qry_type:
                            # handle query
                            try:
                                self.dns_names[pkt.dns.qry_name]
                            except KeyError:
                                self.dns_names[pkt.dns.qry_name] = []
                        # handle response
                        try:
                            # filter <ROOT>
                            if '41' != pkt.dns.resp_type:
                                # this should only occur if we somehow missed the query
                                try:
                                    self.dns_names[pkt.dns.resp_name]
                                except KeyError:
                                    self.dns_names[pkt.dns.resp_name] = []
                                # check ip4/6 responses
                                try:
                                    # ipv4
                                    resolved_ip = pkt.dns.a
                                except AttributeError:
                                    # ipv6
                                    resolved_ip = '[{}]'.format(pkt.dns.aaaa)
                                if resolved_ip not in self.dns_names[pkt.dns.resp_name]:
                                    self.dns_names[pkt.dns.resp_name].append(resolved_ip)
                        # not a dns response
                        except AttributeError:
                            pass

                    # handle tls
                    elif pkt.highest_layer.lower().startswith('tls'):
                        try:
                            # handshake, client hello
                            if '22' == pkt.tls.record_content_type:
                                sni = pkt.tls.handshake_extensions_server_name
                                try:
                                    self.tls_sni[sni]
                                except KeyError:
                                    self.tls_sni[sni] = []

                                if ip_port not in self.tls_sni[sni]:
                                    self.tls_sni[sni].append(ip_port)
                        except AttributeError:
                            pass

                    # handle http
                    elif 'http' == pkt.highest_layer.lower():
                        try:
                            hostname = pkt.http.host
                            if ':' in hostname:
                                hostname = '[{}]'.format(hostname)
                            try:
                                self.http_hosts[hostname]
                            except KeyError:
                                self.http_hosts[hostname] = []

                            if ip_port not in self.http_hosts:
                                self.http_hosts[hostname].append(ip_port)
                        except AttributeError:
                            pass

                    elif pkt.highest_layer not in self.unhandled_protocols:
                        self.unhandled_protocols.append(pkt.highest_layer)
