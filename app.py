from flask import Flask, request, jsonify, render_template, send_file
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, Ether, DNS, DNSQR
import pandas as pd
import io
from collections import Counter
from datetime import datetime
import os
from collections import defaultdict

app = Flask(__name__)

analysis_results = pd.DataFrame()
bandwidth_usage = defaultdict(int)
port_usage = defaultdict(int)

def analyze_packet(packet):
    result = {
        'Timestamp': datetime.fromtimestamp(float(packet.time)).isoformat(),
        'Protocol': 'Unknown',
        'Source': 'Unknown',
        'Destination': 'Unknown',
        'Flags': 'N/A',
        'Length': 0,
        'MAC Source': 'N/A',
        'MAC Destination': 'N/A',
        'DNS Query': 'N/A',
        'Source Port': 'N/A',
        'Destination Port': 'N/A'
    }
    if packet.haslayer(IP):
        protocol = 'IPv4'
        source = packet[IP].src
        destination = packet[IP].dst
        length = packet[IP].len  # Total length of IP packet
        result['Protocol'] = protocol
        result['Source'] = source
        result['Destination'] = destination
        result['Length'] = length

        # Update bandwidth usage by source IP
        bandwidth_usage[source] += length

        if packet.haslayer(TCP):
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
            flags = packet[TCP].flags
            result['Source Port'] = source_port
            result['Destination Port'] = destination_port
            result['Flags'] = str(flags)
            port_usage[source_port] += 1
            port_usage[destination_port] += 1

        elif packet.haslayer(UDP):
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport
            result['Source Port'] = source_port
            result['Destination Port'] = destination_port
            port_usage[source_port] += 1
            port_usage[destination_port] += 1

    elif packet.haslayer(IPv6):
        protocol = 'IPv6'
        source = packet[IPv6].src
        destination = packet[IPv6].dst
        length = packet[IPv6].plen  # Total payload length of IPv6 packet
        result['Protocol'] = protocol
        result['Source'] = source
        result['Destination'] = destination
        result['Length'] = length

        # Update bandwidth usage by source IP
        bandwidth_usage[source] += length

        if packet.haslayer(TCP):
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
            flags = packet[TCP].flags
            result['Source Port'] = source_port
            result['Destination Port'] = destination_port
            result['Flags'] = str(flags)
            port_usage[source_port] += 1
            port_usage[destination_port] += 1

        elif packet.haslayer(UDP):
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport
            result['Source Port'] = source_port
            result['Destination Port'] = destination_port
            port_usage[source_port] += 1
            port_usage[destination_port] += 1

    if packet.haslayer(Ether):
        mac_src = packet[Ether].src
        mac_dst = packet[Ether].dst
        result['MAC Source'] = mac_src
        result['MAC Destination'] = mac_dst

    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        dns_query = packet[DNSQR].qname.decode()
        result['DNS Query'] = dns_query

    return result

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_pcap():
    global analysis_results

    pcap_file = request.files['pcap']
    pcap_data = pcap_file.read()

    pcap_buffer = io.BytesIO(pcap_data)
    packets = rdpcap(pcap_buffer)
    packet_count = len(packets)

    packet_details = [analyze_packet(packet) for packet in packets]
    df = pd.DataFrame(packet_details)

    analysis_results = df

    top_source_ips = Counter(analysis_results['Source']).most_common(5)
    top_destination_ips = Counter(analysis_results['Destination']).most_common(5)
    
    # Exclude 'N/A' from top DNS queries
    dns_queries_filtered = analysis_results['DNS Query'].dropna()
    dns_queries_filtered = dns_queries_filtered[dns_queries_filtered != 'N/A']
    top_dns_queries = Counter(dns_queries_filtered).most_common(5)
    
    top_ports_used = Counter(port_usage).most_common(5)

    return jsonify({
        'packet_count': packet_count,
        'analysis_results': df.to_json(orient='records'),
        'top_source_ips': top_source_ips,
        'top_destination_ips': top_destination_ips,
        'top_dns_queries': top_dns_queries,
        'top_ports_used': top_ports_used
    })

@app.route('/visualization')
def visualization():
    return render_template('visualization.html')

@app.route('/get_visualization_data')
def get_visualization_data():
    global analysis_results, port_usage

    if analysis_results.empty:
        return jsonify({'error': 'No data available'}), 400

    protocol_counts = Counter(analysis_results['Protocol'])
    length_counts = Counter(analysis_results['Length'])
    dns_counts = Counter(analysis_results['DNS Query'].dropna())
    timestamp_counts = Counter(analysis_results['Timestamp'])
    source_ip_counts = Counter(analysis_results['Source'])
    destination_ip_counts = Counter(analysis_results['Destination'])
    port_usage_counts = Counter(port_usage)

    visualization_data = {
        'protocols': {
            'labels': list(protocol_counts.keys()),
            'data': list(protocol_counts.values())
        },
        'lengths': {
            'labels': list(length_counts.keys()),
            'data': list(length_counts.values())
        },
        'dns': {
            'labels': list(dns_counts.keys()),
            'data': list(dns_counts.values())
        },
        'timestamps': {
            'labels': list(timestamp_counts.keys()),
            'data': list(timestamp_counts.values())
        },
        'source_ips': {
            'labels': list(source_ip_counts.keys()),
            'data': list(source_ip_counts.values())
        },
        'destination_ips': {
            'labels': list(destination_ip_counts.keys()),
            'data': list(destination_ip_counts.values())
        },
        'ports_used': {
            'labels': [str(port) for port in port_usage_counts.keys()],
            'data': list(port_usage_counts.values())
        }
    }

    return jsonify(visualization_data)


@app.route('/download_analysis_csv')
def download_analysis_csv():
    global analysis_results

    if analysis_results.empty:
        return jsonify({'error': 'No analysis data available'}), 400

    csv_filename = 'analysis_results.csv'
    analysis_results.to_csv(csv_filename, index=False)

    return send_file(csv_filename, as_attachment=True)

@app.route('/download_visualization_csv')
def download_visualization_csv():
    global analysis_results

    if (analysis_results.empty):
        return jsonify({'error': 'No visualization data available'}), 400

    csv_filename = 'visualization_results.csv'

    visualization_data = {
        'Protocol': analysis_results['Protocol'],
        'Source': analysis_results['Source'],
        'Destination': analysis_results['Destination'],
        'Flags': analysis_results['Flags'],
        'Length': analysis_results['Length'],
        'MAC Source': analysis_results['MAC Source'],
        'MAC Destination': analysis_results['MAC Destination'],
        'DNS Query': analysis_results['DNS Query'],
        'Source Port': analysis_results['Source Port'],
        'Destination Port': analysis_results['Destination Port']
    }

    df = pd.DataFrame(visualization_data)
    df.to_csv(csv_filename, index=False)

    return send_file(csv_filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
