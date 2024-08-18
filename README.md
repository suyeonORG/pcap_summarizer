# PCAP Summarizer

This utility is designed to analyze and summarize network packet captures from Wireshark `.pcap` **exported in JSON format**. It extracts and highlights key information such as identifying routers, clients, and servers on the network, and detecting potential network issues based on ARP, ICMP, and DHCP packet analysis.

## Features

- **Device Categorization**: Identifies and categorizes devices as routers, clients, or servers based on their network behavior.
- **ARP Analysis**: Detects and summarizes ARP (Address Resolution Protocol) requests and replies, identifying potential issues.
- **ICMP Analysis**: Analyzes ICMP (Internet Control Message Protocol) messages to detect possible network issues such as unreachable destinations or timeouts.
- **DHCP Analysis**: Tracks DHCP (Dynamic Host Configuration Protocol) messages, identifying IP allocation issues and network device behavior.
- **Network Summary**: Generates a comprehensive summary of the network's activity and highlights key devices and any detected issues.

## Requirements

- **Node.js**: This utility requires Node.js to run. Ensure that you have Node.js installed on your system. You can download and install it from the official [Node.js website](https://nodejs.org/).

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/packet-analysis-utility.git
   cd packet-analysis-utility
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

## Usage

To use the utility, you'll need a packet capture file in JSON format. This can be generated using Wireshark by exporting the packet data as JSON.

### Command-Line Options

- `-v`: Verbose output. Prints a detailed analysis including device categorization, ARP, ICMP, and DHCP issues, along with a network summary.
- `-s`: Summary only. Prints only the network summary, highlighting the main points.
- `-o`: Output detailed analysis without the summary. Prints device categorization and issues detected without the final summary.

### Example Commands

1. **Verbose output (detailed analysis with summary):**

   ```bash
   node main -v sample1.json
   ```

2. **Summary only:**

   ```bash
   node main -s sample2.json
   ```

3. **Detailed output without summary:**

   ```bash
   node main -o sample2.json
   ```

### Input File

The input file should be a JSON file containing packet data exported from Wireshark. This file is provided as an argument to the script.

### Example JSON Export

To export a JSON file from Wireshark:

1. Open the capture file in Wireshark.
2. Go to `File > Export Packet Dissections > As JSON...`.
3. Save the file and use it as input for this utility.

## Output

Depending on the selected option, the utility will print either the full detailed analysis or just a summary to the console. This output includes:

- A categorized list of devices on the network (routers, clients, servers).
- Issues detected in ARP, ICMP, and DHCP communications.
- A summary of network behavior, including any detected anomalies or critical devices.

```txt
[DEVICES]
Device_1: [ip_addr, name, mac_addr] (Router, D-Link, Netgear, TP-Link, Tenda)
Device_1: [different_ip_addr, name, mac_addr] (Router, D-Link, Netgear, TP-Link, Tenda)
Device_2: [192.168.0.29, Intel_..., mac_addr] (Terminal)

[MAIN DEVICES]
[Device_2, Intel_..., mac_addr]
  Activities:

[POTENTIAL SERVERS]

[POTENTIAL ROUTERS]
...

[ARP ISSUES]
[Device_4] is asking who has IP 192.168.4.14.
[Device_1] is asking who has IP 192.168.4.1.
[Device_4] responded that it has IP 192.168.4.1 (Device_1).
...

[ICMP ISSUES]
[INFO] ICMP Type 134 detected. Packet #54 [Source IP: Unknown, Destination IP: Unknown]
[INFO] ICMP Type 143 detected. Packet #57 [Source IP: Unknown, Destination IP: Unknown]
[ERROR] ICMP Destination Unreachable - Likely a routing issue or a firewall blocking traffic. Packet #76 [Source IP: 192.168.4.1, Destination IP: 192.168.4.14]
[INFO] ICMP Type 143 detected. Packet #79 [Source IP: Unknown, Destination IP: Unknown]

[DHCP ISSUES]
[DISCOVER] Device_1 sent a DHCP Discover. Packet #46 [Source IP: 0.0.0.0, Destination IP: 255.255.255.255]
[DISCOVER] Device_1 sent a DHCP Discover. Packet #58 [Source IP: 0.0.0.0, Destination IP: 255.255.255.255]
[OFFER] DHCP Offer received from Device_4. Packet #59 [Source IP: 192.168.4.1, Destination IP: 192.168.4.14]
[DISCOVER] Device_1 sent a DHCP Discover. Packet #60 [Source IP: 0.0.0.0, Destination IP: 255.255.255.255]
[OFFER] DHCP Offer received from Device_5. Packet #61 [Source IP: 192.168.0.1, Destination IP: 192.168.0.29]
[OFFER] DHCP Offer received from Device_4. Packet #62 [Source IP: 192.168.4.1, Destination IP: 192.168.4.14]

[DHCP ASSUMPTIONS]
[ASSUMPTION] Device_1 encountered issues obtaining an IP address.
[ASSUMPTION] Device_4 was offered an IP address.
[ASSUMPTION] Device_5 was offered an IP address.

[HIGH-LEVEL SUMMARY]
DHCP activity detected, with some devices possibly encountering issues obtaining an IP address.
Multiple ARP requests and responses were observed, indicating active network device communication and possible network reconfiguration.
Several ICMP messages detected, which could indicate network probing or issues such as unreachable devices or routing problems.
Overall, the network activity appears to be standard with several key devices acting as routers, terminals, and potentially servers.
```

## Contribution

Contributions are welcome! Please fork this repository and submit a pull request with your improvements.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
