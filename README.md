
Network Traffic Analyzer Using Python
A Python-based educational packet analyzer that captures IP packet metadata on an authorized network interface, identifies common protocols, displays live results, and writes packet records to CSV.

Features
Capture IPv4 and IPv6 packet metadata using Scapy
Identify DNS, TCP, UDP, ICMP, and other IP packets
Display source and destination IP addresses
Display TCP/UDP source and destination ports when available
Record packet size and timestamp
Show DNS query names when available
Count packets by protocol
Save results to packet_log.csv
Requirements
Python 3.9 or later recommended
Scapy
Packet-capture support and permissions for your operating system
Windows, macOS, or Linux
Project structure
network_traffic_analyzer/
├── network_analyzer.py
├── requirements.txt
├── README.md
└── packet_log.csv   # generated automatically
Installation
Open a terminal in the project folder and run:

python -m pip install -r requirements.txt
Windows
Install Npcap from its official website if Scapy cannot capture packets. Run the terminal with appropriate permissions only when required. Select a valid network interface if your environment requires an explicit interface configuration.

Linux / macOS
Packet capture may require elevated privileges or configured capture permissions. Use the minimum privileges necessary.

Run the analyzer
python network_analyzer.py
Generate ordinary traffic on your own computer, such as visiting a website or running:

nslookup example.com
Stop capture with Ctrl+C. The program prints a summary and saves captured metadata in packet_log.csv.

CSV columns
Timestamp
Source IP
Destination IP
Protocol
Source Port
Destination Port
Packet Size (bytes)
DNS Query
Protocol identification
DNS: A DNS layer is present.
TCP: A TCP layer is present when DNS is not identified first.
UDP: A UDP layer is present when DNS/TCP is not identified first.
ICMP: An ICMP layer is present.
OTHER: Another captured IP protocol.
The protocol label is a simple educational classification, not a full protocol dissector. DNS packets are labelled DNS even though they are carried over UDP or TCP.

Troubleshooting
Scapy missing: Run python -m pip install -r requirements.txt.
No packets: Check the selected interface, capture permissions, and whether traffic is visible to the capture session.
Windows capture failure: Confirm Npcap is installed and available.
Permission denied: Use the appropriate OS-specific capture permissions; avoid running with elevated privileges unless needed.
CSV write error: Check folder permissions and whether the CSV file is locked by another application.
Computer Networks concepts demonstrated
IP addressing, IPv4/IPv6, TCP, UDP, ICMP, DNS, packet capture, source/destination ports, packet size, timestamps, and CSV-based logging.

Safety and limitations
Capture only traffic on devices and networks you own or are explicitly authorized to inspect. The program records packet metadata; it does not decrypt HTTPS/TLS payloads. Captured traffic may contain sensitive information, so protect the CSV file and delete it when no longer needed.

⋮⋮⋮⋮⋮⋮⋮⋮⋮⋮⋮⋮⋮⋮⋮⋮⋮⋮⋮⋮
