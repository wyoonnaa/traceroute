# sudo python3 trace.py (что-то)

# для проверки ipv4
# msu.ru
# 192.168.0.1 - локальный
# 8474737364oskdk инвалидный адрес
# 127.0.0.1 - да

# для проверки ipv6
# локальный 2001:0DB8:0000:0000:ABCD::1234
# рандомный ed9a:fe9d:77ed:b4e5:f338:4d34:3b23:3068

import socket
import sys
import re
import time
import ipaddress
from prettytable import PrettyTable

UDP_PORT = 34434
MAX_HOPS = 10
TIMEOUT = 2
NUM_ATTEMPTS = 3
INTERVAL = 0.5

TABLE_HEADERS = ['TTL', 'IP Address', 'Time', 'Netname, Country/Address, Origin']
table = PrettyTable(TABLE_HEADERS)


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 trace.py <address>")
        return

    address = sys.argv[1]
    traceroute(address)


def is_local_ip(address):
    try:
        ip = ipaddress.ip_address(address)
        if ip.is_loopback or ip.is_link_local or ip.is_private:
            return 'local'
        return 'no local'
    except ValueError:
        return 'invalid'


def whois_query(address):
    message = ''
    try:
        with socket.socket(socket.AF_INET6 if ':' in address
                           else socket.AF_INET, socket.SOCK_STREAM) as s:
            who = socket.gethostbyname("whois.iana.org")
            s.connect((who, 43))
            s.send((address + "\r\n").encode())
            while True:
                data = s.recv(2024)
                message += data.decode()
                if not data:
                    break

            whois_server = ''
            for line in message.split('\n'):
                if 'refer' in line.lower():
                    whois_server = line.split()[-1]
                    break

        message2 = ''
        with socket.socket(socket.AF_INET6 if ':' in address
                           else socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((whois_server, 43))
            s.send((address + "\r\n").encode())
            while True:
                data = s.recv(2024)
                message2 += data.decode('iso-8859-1')
                if not data:
                    break
    except Exception as e:
        print(f"Whois query failed: {e}")
        return "Query failed"

    return " " + parse_whois_info(message2)


def parse_whois_info(message2):
    whois_data = {
        'netname': '',
        'country': '',
        'origin': '',
        'address': ''
    }
    output = ''

    for keyword in whois_data.keys():
        search_result = re.search(fr"{keyword}:\s+\S+", message2)
        if search_result:
            output += search_result.group().split(':')[1].strip() + " "

    return output if output != "" else "no information"


def send_udp_packet(udp_socket, host, port, ttl):
    for attempt in range(NUM_ATTEMPTS):
        try:
            udp_socket.sendto(b'qq', (host, port))
            return
        except socket.error:
            time.sleep(INTERVAL)


def traceroute(address):
    current_hop_ip = None

    try:
        host = socket.getaddrinfo(address, None)[0][4][0]
    except socket.gaierror:
        print(f"{address} is invalid")
        sys.exit()

    if is_local_ip(host) == 'local':
        print(f"  {is_local_ip(host)}\r\n")
        sys.exit()

    for ttl in range(1, MAX_HOPS + 1):
        family = socket.AF_INET6 if ':' in host else socket.AF_INET
        udp_socket = socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        ttl_option = socket.IPV6_UNICAST_HOPS if family == socket.AF_INET6 \
            else socket.IP_TTL
        udp_socket.setsockopt(socket.IPPROTO_IPV6 if family == socket.AF_INET6
                              else socket.SOL_IP, ttl_option, ttl)

        icmp_socket = socket.socket(family, socket.SOCK_RAW,
                                    socket.IPPROTO_ICMPV6
                                    if family == socket.AF_INET6
                                    else socket.IPPROTO_ICMP)
        icmp_socket.bind(('', UDP_PORT))
        icmp_socket.settimeout(TIMEOUT)

        send_udp_packet(udp_socket, host, UDP_PORT, ttl)

        try:
            start_time = time.time()
            data, address = icmp_socket.recvfrom(2048)
            end_time = time.time()
            time_taken = (end_time - start_time) * 1000

            current_hop_ip = address[0]

            if is_local_ip(current_hop_ip) == 'local':
                table.add_row([ttl, current_hop_ip,
                               f"{time_taken:.2f} ms", "local"])
            else:
                table.add_row([ttl, current_hop_ip, f"{time_taken:.2f} ms",
                               whois_query(current_hop_ip)])
        except socket.timeout:
            table.add_row([ttl, "timeout", "timeout", "timeout"])

        udp_socket.close()
        icmp_socket.close()

        if current_hop_ip == host:
            break

    print(table)


if __name__ == "__main__":
    main()
