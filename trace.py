import socket
from socket import timeout
import sys
import re
import time
import ipaddress
from datetime import datetime
from prettytable import PrettyTable

udp_port = 34434
ttl = 30
TTL = 30
local_host = ""
timeOUT = 2
num_attempts = 3
interval = 0.5

th = ['TTL', 'IP Address', 'Time', 'Netname, Country/Address, Origin']
table = PrettyTable(th)


def main():
    address = sys.argv[1]
    traceroute(address)


def ip_local(address):
    try:
        ip = ipaddress.ip_address(address)
        if ip.is_loopback or ip.is_link_local or ip.is_private:
            return 'local'
        else:
            return 'no local'
    except ValueError:
        return 'invalid'


def whois(address):
    with socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_STREAM) as s:
        who = socket.gethostbyname("whois.iana.org")
        s.connect((who, 43))
        s.send((address + "\r\n").encode())
        message = b""
        while True:
            stroka = s.recv(2024)
            message += stroka
            if stroka == b"":
                break

        message = message.decode()
        whois_server = ''
        for line in message.split('\n'):
            if 'refer' in line.lower():
                whois_server = line.split()[-1]

        with socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_STREAM) as sock_second:
            sock_second.connect((whois_server, 43))
            sock_second.send((address + "\r\n").encode())
            response2 = ""
            while True:
                response2 += sock_second.recv(2024).decode('iso-8859-1')
                if not sock_second.recv(2024):
                    break
            message2 = response2
        return (f" {parse_whois_info(message2)}")


def parse_whois_info(message2):
    whois_data = {
        'netname': '',
        'country': '',
        'origin': '',
        'address': ''
    }
    output = ''

    for keyword in whois_data.keys():
        search_result = re.search(fr"{keyword}:\s+\w+", message2)
        if search_result:
            output += search_result.group().split(':')[1].strip() + " "

    return output if output != "" else "no information"


def send_udp_with_retries(udp_socket, host, udp_port, ttl):
    for attempt in range(num_attempts):
        try:
            udp_socket.sendto('qq'.encode(), (host, udp_port))
            return
        except socket.error as e:
            # print(f"Attempt {attempt+1} failed: {e}")
            time.sleep(interval)


def traceroute(address):
    address_marshrutizatora = ""
    try:
        host = socket.getaddrinfo(address, None)[0][4][0]

    except socket.gaierror:
        print(address, " is invalid")
        exit()

    if ip_local(host) == 'local':
        print("  ", ip_local(host), "\r\n")
        exit()

    for ttl in range(1, TTL):
        family = socket.AF_INET6 if ':' in host else socket.AF_INET
        udp_socket = socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        udp_socket.setsockopt(socket.IPPROTO_IPV6 if ':' in host else socket.IPPROTO_IP, socket.IP_TTL, ttl)

        icmp_socket = socket.socket(family, socket.SOCK_RAW,
                                    socket.IPPROTO_ICMPV6 if ':' in host else socket.IPPROTO_ICMP)
        icmp_socket.bind((local_host, udp_port))
        icmp_socket.settimeout(timeOUT)

        send_udp_with_retries(udp_socket, host, udp_port, ttl)

        try:
            start_time = time.time()
            _, (address_marshrutizatora, _) = icmp_socket.recvfrom(2024)
            end_time = time.time()
            time_taken = (end_time - start_time) * 100

            if ip_local(address_marshrutizatora) == 'local':
                table.add_row([ttl, address_marshrutizatora, f"{time_taken:.2f}", "local"])
            else:
                table.add_row([ttl, address_marshrutizatora, f"{time_taken:.2f}", f"{whois(address_marshrutizatora)}"])

        except timeout:
            table.add_row([ttl, "timeout", "timeout", "timeout", ])

        if address_marshrutizatora == host or address == host:
            break
    print(table)


if __name__ == "__main__":
    main()


# cd /Users/mac/PycharmProjects/traceroute/src/trace.py
# sudo python3 trace.py (что-то)

# для проверки ipv4
# msu.ru
# 192.168.0.1 - локальный
# 139.99.237.62 - Австралия
# 8474737364oskdk инвалидный адрес
# 127.0.0.1 - да

# для проверки ipv6
# локальный 2001:0DB8:0000:0000:ABCD::1234
# рандомный ed9a:fe9d:77ed:b4e5:f338:4d34:3b23:3068