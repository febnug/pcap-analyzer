# skrip paiton buat analisis file capture dari wireshark
# butuh dependensis, openpyxl, pyshark dan pandas
# kalo belum install pip, di install dulu sudo apt-get install python3-pip
# install, pip install openpyxl pyshark pandas
# butuh tshark juga
# install, sudo apt-get install tshark

import pyshark
import pandas as pd

def analyze_pcap_to_excel(pcap_file, output_excel):
    capture = pyshark.FileCapture(pcap_file, keep_packets=False)

    tcp_list, dns_list, http_list, tls_list, icmp_list = [], [], [], [], []

    print(f"Analisis file: {pcap_file}")

    for pkt in capture:
        try:
            timestamp = pkt.sniff_time.isoformat()
            src = pkt.ip.src if hasattr(pkt, 'ip') else ''
            dst = pkt.ip.dst if hasattr(pkt, 'ip') else ''
        except AttributeError:
            timestamp = src = dst = ''

        # TCP
        if 'TCP' in pkt:
            try:
                tcp_list.append({
                    'No': pkt.number,
                    'Time': timestamp,
                    'Source IP': src,
                    'Destination IP': dst,
                    'Src Port': pkt.tcp.srcport,
                    'Dst Port': pkt.tcp.dstport,
                    'Flags': pkt.tcp.flags
                })
            except AttributeError:
                pass

        # DNS
        if 'DNS' in pkt:
            try:
                dns_list.append({
                    'No': pkt.number,
                    'Time': timestamp,
                    'Source IP': src,
                    'Destination IP': dst,
                    'Query Name': pkt.dns.qry_name if hasattr(pkt.dns, 'qry_name') else '',
                    'Response': pkt.dns.a if hasattr(pkt.dns, 'a') else ''
                })
            except AttributeError:
                pass

        # HTTP
        if 'HTTP' in pkt:
            try:
                http_list.append({
                    'No': pkt.number,
                    'Time': timestamp,
                    'Source IP': src,
                    'Destination IP': dst,
                    'Method': getattr(pkt.http, 'request_method', ''),
                    'Host': getattr(pkt.http, 'host', ''),
                    'URI': getattr(pkt.http, 'request_uri', ''),
                    'User-Agent': getattr(pkt.http, 'user_agent', '')
                })
            except AttributeError:
                pass

        # TLS
        if 'TLS' in pkt:
            try:
                tls_list.append({
                    'No': pkt.number,
                    'Time': timestamp,
                    'Source IP': src,
                    'Destination IP': dst,
                    'Version': getattr(pkt.tls, 'record_version', ''),
                    'Handshake Type': getattr(pkt.tls, 'handshake_type', ''),
                    'Server Name': getattr(pkt.tls, 'handshake_extensions_server_name', '')
                })
            except AttributeError:
                pass

        # ICMP
        if 'ICMP' in pkt:
            try:
                icmp_list.append({
                    'No': pkt.number,
                    'Time': timestamp,
                    'Source IP': src,
                    'Destination IP': dst,
                    'Type': pkt.icmp.type,
                    'Code': pkt.icmp.code
                })
            except AttributeError:
                pass

    capture.close()

    # Simpan semua ke Excel
    with pd.ExcelWriter(output_excel, engine='openpyxl') as writer:
        if tcp_list:
            pd.DataFrame(tcp_list).to_excel(writer, sheet_name='TCP', index=False)
        if dns_list:
            pd.DataFrame(dns_list).to_excel(writer, sheet_name='DNS', index=False)
        if http_list:
            pd.DataFrame(http_list).to_excel(writer, sheet_name='HTTP', index=False)
        if tls_list:
            pd.DataFrame(tls_list).to_excel(writer, sheet_name='TLS', index=False)
        if icmp_list:
            pd.DataFrame(icmp_list).to_excel(writer, sheet_name='ICMP', index=False)

    print(f"✅ Output disimpan ke: {output_excel}")


if __name__ == "__main__":
    pcap_path = "capture.pcapng"          # ganti sesuai nama file pcap kamu
    output_path = "hasil_analisis.xlsx"   # output Excel
    analyze_pcap_to_excel(pcap_path, output_path)
