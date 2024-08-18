const fs = require('fs');

// Predefined list of known router IP addresses and their manufacturers
const knownRouters = {
    "192.168.0.1": ["D-Link", "Netgear", "TP-Link", "Tenda"],
    "192.168.1.1": ["Linksys", "Cisco", "ASUS", "TP-Link"],
    "192.168.1.254": ["Thomson", "Alcatel"],
    "192.168.0.254": ["Divers fabricants"],
    "192.168.2.1": ["Belkin", "SMC"],
    "10.0.0.1": ["Comcast Xfinity", "certaines configurations d'entreprises"],
    "10.0.1.1": ["Apple AirPort"],
    "192.168.11.1": ["Buffalo"],
    "192.168.100.1": ["Certains modems câble (Motorola, Arris)"],
    "192.168.10.1": ["TRENDnet", "certaines configurations personnalisées"],
    "192.168.3.1": ["Certains modèles Huawei"],
    "192.168.15.1": ["Certains modèles Linksys et Cisco"],
    "192.168.8.1": ["Huawei Mobile WiFi", "Certaines configurations de routeurs"],
    "192.168.30.1": ["Certaines configurations TP-Link"],
    "192.168.50.1": ["ASUS", "Certains routeurs personnalisés"],
    "192.168.168.1": ["Certaines configurations personnalisées"],
    "192.168.178.1": ["AVM Fritz!Box", "Certains modèles de routeurs européens"],
    "192.168.254.254": ["Certains modems satellite"],
    "192.168.123.254": ["Certaines configurations Edimax"],
    "192.168.88.1": ["MikroTik", "Certains modèles de routeurs personnalisés"],
    "10.1.1.1": ["D-Link", "Certains modèles de routeurs en Australie"],
    "10.10.10.1": ["Certaines configurations de routeurs", "Certains réseaux d'entreprise"],
};

// Function to detect router role based on IP address
function detectRouterRole(ipAddress) {
    return knownRouters[ipAddress] || null;
}

// Function to analyze and track ARP requests
function analyzeARP(packets, devices) {
    const arpIssues = [];
    const arpRequests = {};
    const deviceArpCounts = {};  // To track ARP requests count per device

    packets.forEach((packet, index) => {
        try {
            if (packet._source.layers.arp) {
                const srcIp = packet._source.layers.arp['arp.src.proto_ipv4'];
                const dstIp = packet._source.layers.arp['arp.dst.proto_ipv4'];

                const srcDevice = devices.Routers[srcIp] || devices.Terminals[srcIp] || {};
                const dstDevice = devices.Routers[dstIp] || devices.Terminals[dstIp] || {};

                const srcDeviceId = srcDevice.id || srcIp;
                const dstDeviceId = dstDevice.id || dstIp;

                // Track ARP requests per device
                if (!arpRequests[srcIp]) {
                    arpRequests[srcIp] = [];
                }
                arpRequests[srcIp].push(`[${srcDeviceId}] is asking who has IP ${dstIp}.`);

                // Count the ARP requests initiated by each device
                if (!deviceArpCounts[srcIp]) {
                    deviceArpCounts[srcIp] = 0;
                }
                deviceArpCounts[srcIp]++;

                // Generate a brief summary for each ARP packet
                if (packet._source.layers.arp['arp.opcode'] === '1') { // ARP Request
                    arpIssues.push(`[${srcDeviceId}] is asking who has IP ${dstIp}.`);
                } else if (packet._source.layers.arp['arp.opcode'] === '2') { // ARP Reply
                    arpIssues.push(`[${srcDeviceId}] responded that it has IP ${srcIp} (${dstDeviceId}).`);
                }
            }
        } catch (error) {
            console.error(`Error processing ARP packet #${index + 1}: ${error.message}`);
        }
    });

    // Identify the main device by the number of ARP requests sent
    let mainDevice = null;
    let maxArpRequests = 0;
    Object.keys(deviceArpCounts).forEach(ip => {
        if (deviceArpCounts[ip] > maxArpRequests) {
            maxArpRequests = deviceArpCounts[ip];
            mainDevice = devices.Routers[ip] || devices.Terminals[ip];
        }
    });

    // Highlight the main device in the ARP analysis
    if (mainDevice) {
        arpIssues.push(`[MAIN DEVICE] ${mainDevice.id} (${mainDevice.name}) is identified as the main device due to the high number of ARP requests (${maxArpRequests}).`);
    }

    return { arpIssues, arpRequests };
}

// Function to process packets and identify ICMP messages with more detail
function analyzeICMP(packets) {
    const icmpIssues = [];
    packets.forEach((packet, index) => {
        try {
            if (packet._source.layers.icmpv6 || packet._source.layers.icmp) {
                const icmpType = packet._source.layers.icmpv6 ? packet._source.layers.icmpv6['icmpv6.type'] : packet._source.layers.icmp['icmp.type'];
                const srcIp = packet._source.layers.ip ? packet._source.layers.ip['ip.src'] : 'Unknown';
                const dstIp = packet._source.layers.ip ? packet._source.layers.ip['ip.dst'] : 'Unknown';
                const packetInfo = `Packet #${index + 1} [Source IP: ${srcIp}, Destination IP: ${dstIp}]`;

                switch (icmpType) {
                    case "8":
                        icmpIssues.push(`[ERROR] ICMP Echo Request - Possible Ping sweep or ICMP Flood. ${packetInfo}`);
                        break;
                    case "3":
                        icmpIssues.push(`[ERROR] ICMP Destination Unreachable - Likely a routing issue or a firewall blocking traffic. ${packetInfo}`);
                        break;
                    case "11":
                        icmpIssues.push(`[ERROR] ICMP Time Exceeded - Possible network loop or TTL expiration. ${packetInfo}`);
                        break;
                    case "0":
                        icmpIssues.push(`[INFO] ICMP Echo Reply - Normal operation response. ${packetInfo}`);
                        break;
                    case "4":
                        icmpIssues.push(`[ERROR] ICMP Source Quench - Congestion control signal, network might be overwhelmed. ${packetInfo}`);
                        break;
                    case "5":
                        icmpIssues.push(`[INFO] ICMP Redirect - Router indicating an alternate route. ${packetInfo}`);
                        break;
                    case "12":
                        icmpIssues.push(`[ERROR] ICMP Parameter Problem - Likely caused by a malformed header. ${packetInfo}`);
                        break;
                    default:
                        icmpIssues.push(`[INFO] ICMP Type ${icmpType} detected. ${packetInfo}`);
                }
            }
        } catch (error) {
            console.error(`Error processing ICMP packet #${index + 1}: ${error.message}`);
        }
    });
    return icmpIssues;
}

// Function to process packets and identify DHCP messages with detailed analysis
function analyzeDHCP(packets) {
    const dhcpIssues = [];
    packets.forEach((packet, index) => {
        try {
            if (packet._source.layers.bootp) {
                const bootpMessageType = packet._source.layers.bootp['bootp.option.dhcp'];
                const srcIp = packet._source.layers.ip ? packet._source.layers.ip['ip.src'] : 'Unknown';
                const dstIp = packet._source.layers.ip ? packet._source.layers.ip['ip.dst'] : 'Unknown';
                const packetInfo = `Packet #${index + 1} [Source IP: ${srcIp}, Destination IP: ${dstIp}]`;

                switch (bootpMessageType) {
                    case "1":
                        dhcpIssues.push(`[DISCOVER] DHCP Discover detected. ${packetInfo}`);
                        break;
                    case "2":
                        dhcpIssues.push(`[OFFER] DHCP Offer detected. ${packetInfo}`);
                        break;
                    case "3":
                        dhcpIssues.push(`[REQUEST] DHCP Request detected. ${packetInfo}`);
                        break;
                    case "5":
                        dhcpIssues.push(`[ACK] DHCP Acknowledgement detected. ${packetInfo}`);
                        break;
                    case "6":
                        dhcpIssues.push(`[NACK] DHCP Negative Acknowledgement detected. ${packetInfo}`);
                        break;
                    case "7":
                        dhcpIssues.push(`[RELEASE] DHCP Release detected. ${packetInfo}`);
                        break;
                    default:
                        dhcpIssues.push(`[INFO] DHCP Message Type ${bootpMessageType} detected. ${packetInfo}`);
                }
            }
        } catch (error) {
            console.error(`Error processing DHCP packet #${index + 1}: ${error.message}`);
        }
    });
    return dhcpIssues;
}


// Disqualifies devices that are likely not clients based on packet analysis
function disqualifyClientRole(packet, forwardingTable) {
    try {
        const srcIp = packet._source.layers.ip ? packet._source.layers.ip['ip.src'] : null;
        const srcMac = packet._source.layers.eth ? packet._source.layers.eth['eth.src'] : null;

        if (!srcIp || !srcMac) {
            return false;
        }

        // Check for DHCP Offer (indicating a server/router behavior)
        if (packet._source.layers.bootp && packet._source.layers.bootp['bootp.option.dhcp'] === '2') {
            return true; // Disqualify if the device sends DHCP Offers
        }

        // Check if the device is sending ICMP Redirect messages (indicating routing behavior)
        if (packet._source.layers.icmp && packet._source.layers.icmp['icmp.type'] === '5') {
            return true; // Disqualify if the device sends ICMP Redirects
        }

        // Check for NAT behavior (modifying source or destination addresses)
        if (packet._source.layers.nat) {
            return true; // Disqualify if the device is performing NAT
        }

        // Check for specific routing protocols or services typically handled by routers
        if (packet._source.layers.ospf || packet._source.layers.bgp) {
            return true; // Disqualify if the device is participating in routing protocols
        }

        // Check for frequent ARP requests, potentially indicating a router or scanning behavior
        if (packet._source.layers.arp && packet._source.layers.arp['arp.opcode'] === '1') {
            // Example logic to increment and check request count (would need to track this externally)
            if (forwardingTable[srcMac] && forwardingTable[srcMac].arpRequestCount > 100) { // Threshold is adjustable
                return true; // Disqualify if the device sends a large number of ARP requests
            }
        }

        // Check manufacturer information from MAC address (OUI)
        const manufacturer = packet._source.layers.eth['eth.src.oui_resolved'];
        const knownRouterManufacturers = ["Cisco", "TP-Link", "Netgear", "Linksys", "D-Link"];
        if (manufacturer && knownRouterManufacturers.includes(manufacturer)) {
            return true; // Disqualify if the manufacturer is known for routers
        }

        // Check if the IP address is commonly used by routers
        const knownRouterIps = [
            "192.168.0.1", "192.168.1.1", "192.168.1.254", 
            "192.168.0.254", "192.168.2.1", "10.0.0.1",
            "10.0.1.1", "192.168.11.1", "192.168.100.1",
            "192.168.10.1", "192.168.3.1", "192.168.15.1"
        ];
        if (knownRouterIps.includes(srcIp)) {
            return true; // Disqualify if the IP is a known router IP
        }

        return false; // If none of the above conditions are met, do not disqualify
    } catch (error) {
        console.error(`Error in disqualifyClientRole: ${error.message}`);
        return false; // If an error occurs, do not disqualify the device
    }
}


// Function to detect client behavior based on packet analysis
// Function to detect client behavior based on packet analysis and disqualify non-client roles
// Function to detect client behavior based on packet analysis and disqualify non-client roles
function detectClientRole(packet, devices, forwardingTable) {
    let score = 0;

    try {
        // Apply disqualification criteria first
        if (disqualifyClientRole(packet, devices, forwardingTable)) {
            return 0; // If disqualified, return a score of 0 to indicate non-client
        }

        // Check for DHCP Discover
        if (packet._source.layers.bootp && packet._source.layers.bootp['bootp.option.dhcp'] === '1') {
            score += 15; // High score for DHCP Discover
        }

        // Check for DHCP Request
        if (packet._source.layers.bootp && packet._source.layers.bootp['bootp.option.dhcp'] === '3') {
            score += 10; // High score for DHCP Request
        }

        // Analyze ARP Requests
        if (packet._source.layers.arp && packet._source.layers.arp['arp.opcode'] === '1') {
            const srcIp = packet._source.layers.arp['arp.src.proto_ipv4'];
            const dstIp = packet._source.layers.arp['arp.dst.proto_ipv4'];

            const srcDevice = devices.Routers[srcIp] || devices.Terminals[srcIp];
            const dstDevice = devices.Routers[dstIp] || devices.Terminals[dstIp];

            if (dstDevice) {
                score += 20; // Higher score if ARP Request is targeting a known device
            } else {
                score += 5; // Lower score if ARP Request is targeting an unknown device
            }

            // If the source device is a known device, consider it more central
            if (srcDevice) {
                score += 10; // Higher score if ARP Request is coming from a known device
            }
        }

        // Analyze ARP Replies
        if (packet._source.layers.arp && packet._source.layers.arp['arp.opcode'] === '2') {
            const srcIp = packet._source.layers.arp['arp.src.proto_ipv4'];
            const dstIp = packet._source.layers.arp['arp.dst.proto_ipv4'];

            const srcDevice = devices.Routers[srcIp] || devices.Terminals[srcIp];
            const dstDevice = devices.Routers[dstIp] || devices.Terminals[dstIp];

            if (srcDevice && dstDevice) {
                score += 15; // Higher score if both the source and destination are known devices
            } else {
                score += 10; // Lower score if only one is known
            }
        }

        // Check for TCP SYN
        if (packet._source.layers.tcp && packet._source.layers.tcp['tcp.flags'] === '0x0002') {
            score += 5; // TCP SYN (indicating potential client initiating connection)
        }

        // Check for TCP PSH+ACK
        if (packet._source.layers.tcp && packet._source.layers.tcp['tcp.flags'] === '0x0018') {
            score += 3; // TCP PSH+ACK (indicating active client connection)
        }

    } catch (error) {
        console.error(`Error in detectClientRole: ${error.message}`);
    }

    return score;
}

// Function to detect server behavior based on packet analysis
function detectServerRole(packet) {
    let score = 0;
    try {
        if (packet._source.layers.http) {
            const httpCode = packet._source.layers.http['http.response.code'];
            score += (httpCode === '200') ? 15 : 10; // Higher score for HTTP 200 OK responses
        }
        if (packet._source.layers.dns && packet._source.layers.dns['dns.flags.response'] === '1') {
            score += 10; // DNS response
        }
        if (packet._source.layers.icmp && packet._source.layers.icmp['icmp.type'] === '0') {
            score += 7; // ICMP Echo Reply
        }
        if (packet._source.layers.tcp && (packet._source.layers.tcp['tcp.port'] === '443' || packet._source.layers.tcp['tcp.port'] === '80')) {
            score += 5; // Specific ports (HTTPS/HTTP)
        }
    } catch (error) {
        console.error(`Error in detectServerRole: ${error.message}`);
    }
    return score;
}

// Function to detect router behavior based on packet analysis
function detectRouterRoleByActivity(packet) {
    let score = 0;
    try {
        if (packet._source.layers.dhcp) {
            const dhcpType = packet._source.layers.dhcp['dhcp.type'];

            if (dhcpType === "2") { // DHCP Offer
                score += 70; // High score for DHCP Offer
            } else if (dhcpType === "5") { // DHCP ACK
                score += 100; // Very high score for DHCP ACK
            }
        }

        if (packet._source.layers.arp && packet._source.layers.arp['arp.opcode'] === '2') {
            score += 10; // ARP Reply, a common router activity
        }

        if (packet._source.layers.icmpv6 && packet._source.layers.icmpv6['icmpv6.type'] === '134') {
            score += 15; // ICMP Router Advertisement, indicating a router role
        }

        if (packet._source.layers.icmp && packet._source.layers.icmp['icmp.type'] === '5') {
            score += 20; // ICMP Redirect Message, indicating routing behavior
        }
    } catch (error) {
        console.error(`Error in detectRouterRoleByActivity: ${error.message}`);
    }

    return score;
}

// Function to categorize and list devices with detailed information
function categorizeDevices(packets) {
    const devices = {
        Routers: {},
        Terminals: {}
    };
    const deviceMap = {}; // Map to keep track of MAC/IP to deviceId
    let deviceCounter = 1;

    packets.forEach(packet => {
        try {
            if (packet._source.layers.ip && packet._source.layers.eth) {
                const ipAddress = packet._source.layers.ip['ip.src'];
                const macAddress = packet._source.layers.eth['eth.src'];
                const deviceName = packet._source.layers.eth['eth.src_tree'] ? packet._source.layers.eth['eth.src_tree']['eth.src_resolved'] : 'Unknown';

                // Check if this MAC or IP already has a deviceId assigned
                let deviceId = deviceMap[macAddress] || deviceMap[ipAddress];
                if (!deviceId) {
                    deviceId = `Device_${deviceCounter++}`;
                    // Store the mapping for both MAC and IP
                    deviceMap[macAddress] = deviceId;
                    deviceMap[ipAddress] = deviceId;
                }

                const role = detectRouterRole(ipAddress);
                const deviceInfo = { id: deviceId, ip: ipAddress, name: deviceName, mac: macAddress };

                if (role) {
                    devices.Routers[ipAddress] = { ...deviceInfo, role: role.join(', ') };
                } else {
                    devices.Terminals[ipAddress] = deviceInfo;
                }
            }
        } catch (error) {
            console.error(`Error in categorizeDevices for packet: ${error.message}`);
        }
    });

    return devices;
}

// Function to identify main devices (clients), servers, and routers
function identifyMainDevices(packets, devices) {
    const mainDevices = {};
    const serverDevices = {};
    const clientDevices = {};

    packets.forEach((packet, index) => {
        try {
            if (packet._source.layers.ip && packet._source.layers.eth) {
                const ipAddress = packet._source.layers.ip['ip.src'];
                const macAddress = packet._source.layers.eth['eth.src'];
                const device = devices.Routers[ipAddress] || devices.Terminals[ipAddress] || null;

                if (device) {
                    const deviceId = device.id;

                    if (!mainDevices[deviceId]) {
                        mainDevices[deviceId] = { ...device, websites: new Set(), activities: [], clientScore: 0, serverScore: 0, routerScore: 0 };
                    }

                    // Calculate and accumulate scores
                    mainDevices[deviceId].clientScore += detectClientRole(packet, devices, mainDevices);
                    mainDevices[deviceId].serverScore += detectServerRole(packet);
                    mainDevices[deviceId].routerScore += detectRouterRoleByActivity(packet);

                    // Track web domains accessed by this device (indicating it might be a server)
                    if (packet._source.layers.http && packet._source.layers.http['http.host']) {
                        mainDevices[deviceId].websites.add(packet._source.layers.http['http.host']);
                    } else if (packet._source.layers.tls && packet._source.layers.tls['tls.handshake.extensions_server_name']) {
                        mainDevices[deviceId].websites.add(packet._source.layers.tls['tls.handshake.extensions_server_name']);
                    }

                    // Track ARP requests or DHCP activity (indicating client behavior)
                    if (packet._source.layers.arp || packet._source.layers.bootp) {
                        mainDevices[deviceId].activities.push(`Packet #${index + 1}: ${packet._source.layers.frame['frame.protocols']}`);
                    }
                }
            }
        } catch (error) {
            console.error(`Error in identifyMainDevices for packet #${index + 1}: ${error.message}`);
        }
    });

    // Determine the main role based on the highest score for each device
    Object.keys(mainDevices).forEach(deviceId => {
        try {
            const device = mainDevices[deviceId];
            const highestScore = Math.max(device.clientScore, device.serverScore, device.routerScore);

            if (device.routerScore === highestScore) {
                devices.Routers[device.ip] = { ...device, role: 'Router' };
                delete devices.Terminals[device.ip]; // Ensure the device is only classified once
            } else if (device.serverScore === highestScore) {
                serverDevices[deviceId] = { ...device, role: 'Server' };
                delete devices.Routers[device.ip]; // Ensure the device is not classified as Router
            } else if (device.clientScore === highestScore) {
                clientDevices[deviceId] = { ...device, role: 'Client' };
                delete devices.Routers[device.ip]; // Ensure the device is not classified as Router
            }
        } catch (error) {
            console.error(`Error in determining main role for device ${deviceId}: ${error.message}`);
        }
    });

    return { mainDevices, serverDevices, clientDevices };
}

function analyzeDHCP(packets, devices) {
    const dhcpIssues = [];
    const dhcpExchanges = {};
    
    packets.forEach((packet, index) => {
        try {
            if (packet._source.layers.dhcp) {
                let dhcpType = packet._source.layers.dhcp['dhcp.type'];

                if (!dhcpType) {
                    console.log(`Undefined DHCP message type in packet #${index + 1}:`, JSON.stringify(packet._source.layers.dhcp, null, 2));
                    dhcpIssues.push(`[INFO] DHCP Message Type undefined detected in packet #${index + 1}`);
                    return;
                }

                const srcIp = packet._source.layers.ip ? packet._source.layers.ip['ip.src'] : 'Unknown';
                const dstIp = packet._source.layers.ip ? packet._source.layers.ip['ip.dst'] : 'Unknown';
                const macAddress = packet._source.layers.eth ? packet._source.layers.eth['eth.src'] : 'Unknown';
                const packetInfo = `Packet #${index + 1} [Source IP: ${srcIp}, Destination IP: ${dstIp}]`;

                const srcDevice = devices.Routers[srcIp] || devices.Terminals[srcIp] || {};
                const srcDeviceId = srcDevice.id || macAddress;

                let messageType = '';

                switch (dhcpType) {
                    case "1":
                        messageType = 'Discover';
                        dhcpIssues.push(`[DISCOVER] ${srcDeviceId} sent a DHCP Discover. ${packetInfo}`);
                        break;
                    case "2":
                        messageType = 'Offer';
                        dhcpIssues.push(`[OFFER] DHCP Offer received from ${srcDeviceId}. ${packetInfo}`);
                        break;
                    case "3":
                        messageType = 'Request';
                        dhcpIssues.push(`[REQUEST] ${srcDeviceId} sent a DHCP Request. ${packetInfo}`);
                        break;
                    case "4":
                        messageType = 'Decline';
                        dhcpIssues.push(`[DECLINE] ${srcDeviceId} declined an IP address. ${packetInfo}`);
                        break;
                    case "5":
                        messageType = 'Ack';
                        dhcpIssues.push(`[ACK] DHCP Acknowledgment received from ${srcDeviceId}. ${packetInfo}`);
                        break;
                    case "6":
                        messageType = 'Nack';
                        dhcpIssues.push(`[NACK] DHCP Negative Acknowledgment received from ${srcDeviceId}. ${packetInfo}`);
                        break;
                    case "7":
                        messageType = 'Release';
                        dhcpIssues.push(`[RELEASE] ${srcDeviceId} sent a DHCP Release. ${packetInfo}`);
                        break;
                    case "8":
                        messageType = 'Inform';
                        dhcpIssues.push(`[INFORM] ${srcDeviceId} sent a DHCP Inform. ${packetInfo}`);
                        break;
                    default:
                        dhcpIssues.push(`[INFO] DHCP Message Type ${dhcpType} detected from ${srcDeviceId}. ${packetInfo}`);
                }

                // Track DHCP exchanges
                if (!dhcpExchanges[srcDeviceId]) {
                    dhcpExchanges[srcDeviceId] = [];
                }
                dhcpExchanges[srcDeviceId].push({ type: messageType, srcIp, dstIp, index });
            }
        } catch (error) {
            console.error(`Error processing DHCP packet #${index + 1}: ${error.message}`);
        }
    });

    // Generate broad assumptions based on the DHCP exchanges
    const dhcpAssumptions = [];
    try {
        Object.keys(dhcpExchanges).forEach(deviceId => {
            const exchange = dhcpExchanges[deviceId];
            let hasDiscover = false;
            let hasRequest = false;
            let hasAck = false;

            exchange.forEach(msg => {
                if (msg.type === 'Discover') hasDiscover = true;
                if (msg.type === 'Request') hasRequest = true;
                if (msg.type === 'Ack') hasAck = true;
            });

            if (hasDiscover && hasRequest && hasAck) {
                dhcpAssumptions.push(`[ASSUMPTION] ${deviceId} successfully obtained an IP address.`);
            } else if (hasDiscover && !hasAck) {
                dhcpAssumptions.push(`[ASSUMPTION] ${deviceId} encountered issues obtaining an IP address.`);
            } else if (exchange.find(msg => msg.type === 'Offer')) {
                dhcpAssumptions.push(`[ASSUMPTION] ${deviceId} was offered an IP address.`);
            } else {
                dhcpAssumptions.push(`[ASSUMPTION] ${deviceId} performed DHCP activity.`);
            }
        });
    } catch (error) {
        console.error(`Error generating DHCP assumptions: ${error.message}`);
    }

    return { dhcpIssues, dhcpAssumptions };
}


// Function to generate a detailed summary of the network activity based on analysis
function generateSummary(devices, mainDevices, serverDevices, arpIssues, icmpIssues, dhcpIssues, dhcpAssumptions) {
    let summary = "";

    try {
        // Device Overview
        summary += "[SUMMARY OF NETWORK ACTIVITY]\n\n";
        summary += "[DEVICE OVERVIEW]\n";
        Object.keys(devices.Routers).forEach(ip => {
            const device = devices.Routers[ip];
            summary += `Device ${device.id} (${device.name}, MAC: ${device.mac}) is identified as a Router (${device.role}).\n`;
        });
        Object.keys(devices.Terminals).forEach(ip => {
            const device = devices.Terminals[ip];
            summary += `Device ${device.id} (${device.name}, MAC: ${device.mac}) is identified as a Terminal.\n`;
        });

        summary += "\n[MAIN DEVICES]\n";
        Object.keys(mainDevices).forEach(deviceId => {
            const device = mainDevices[deviceId];
            summary += `Device ${device.id} (${device.name}, MAC: ${device.mac}) is recognized as a key device on the network.\n`;
            if (device.activities.length > 0) {
                summary += `  - Activities: ${device.activities.join(', ')}\n`;
            }
        });

        summary += "\n[POTENTIAL SERVERS]\n";
        Object.keys(serverDevices).forEach(deviceId => {
            const device = serverDevices[deviceId];
            summary += `Device ${device.id} (${device.name}, MAC: ${device.mac}) is potentially acting as a server.\n`;
            if (device.websites.size > 0) {
                summary += `  - Websites Served: ${Array.from(device.websites).join(', ')}\n`;
            }
            if (device.activities.length > 0) {
                summary += `  - Activities: ${device.activities.join(', ')}\n`;
            }
        });

        summary += "\n[POTENTIAL ROUTERS]\n";
        Object.keys(devices.Routers).forEach(deviceId => {
            const device = devices.Routers[deviceId];
            summary += `Device ${device.id} (${device.name}, MAC: ${device.mac}) is confirmed to have Router role: ${device.role}.\n`;
        });

        // ARP Issues
        summary += "\n[ARP ISSUES]\n";
        arpIssues.forEach(issue => {
            summary += `${issue}\n`;
        });

        // ICMP Issues
        summary += "\n[ICMP ISSUES]\n";
        icmpIssues.forEach(issue => {
            summary += `${issue}\n`;
        });

        // DHCP Issues and Assumptions
        summary += "\n[DHCP ISSUES AND ASSUMPTIONS]\n";
        dhcpIssues.forEach(issue => {
            summary += `${issue}\n`;
        });
        dhcpAssumptions.forEach(assumption => {
            summary += `${assumption}\n`;
        });

        // High-level Summary
        summary += "\n[HIGH-LEVEL SUMMARY]\n";
        if (dhcpAssumptions.length === 0 && dhcpIssues.length === 0) {
            summary += "No DHCP activity was observed, indicating stable IP address assignments or static IP usage.\n";
        } else {
            summary += "DHCP activity detected, with some devices possibly encountering issues obtaining an IP address.\n";
        }

        if (arpIssues.length > 0) {
            summary += "Multiple ARP requests and responses were observed, indicating active network device communication and possible network reconfiguration.\n";
        } else {
            summary += "Minimal ARP activity suggests a stable network environment without significant reconfiguration.\n";
        }

        if (icmpIssues.length > 0) {
            summary += "Several ICMP messages detected, which could indicate network probing or issues such as unreachable devices or routing problems.\n";
        } else {
            summary += "No significant ICMP issues detected, indicating normal network operations.\n";
        }

        summary += "Overall, the network activity appears to be standard with several key devices acting as routers, terminals, and potentially servers.\n";

    } catch (error) {
        console.error(`Error generating summary: ${error.message}`);
    }

    return summary;
}
function main(option, fileName) {
    try {
        if (!fileName) {
            throw new Error("Please provide a file name as an argument.");
        }

        // Load and parse the JSON file
        const packetData = JSON.parse(fs.readFileSync(fileName, 'utf8'));

        // Categorize devices
        const devices = categorizeDevices(packetData);

        // Analyze ARP requests and issues
        const { arpIssues } = analyzeARP(packetData, devices);

        // Analyze ICMP messages
        const icmpIssues = analyzeICMP(packetData, devices);

        // Analyze DHCP messages
        const { dhcpIssues, dhcpAssumptions } = analyzeDHCP(packetData, devices);

        // Identify main devices (clients), servers, and routers
        const { mainDevices, serverDevices, clientDevices } = identifyMainDevices(packetData, devices);

        // Generate summary
        const summary = generateSummary(devices, mainDevices, serverDevices, arpIssues, icmpIssues, dhcpIssues, dhcpAssumptions);

        // Handle output based on the provided option
        if (option === '-v') {
            // Verbose output: print everything including the summary
            console.log("[DEVICES]");
            Object.keys(devices.Routers).forEach(ip => {
                const device = devices.Routers[ip];
                console.log(`${device.id}: [${device.ip}, ${device.name}, ${device.mac}] (Router, ${device.role})`);
            });
            Object.keys(devices.Terminals).forEach(ip => {
                const device = devices.Terminals[ip];
                console.log(`${device.id}: [${device.ip}, ${device.name}, ${device.mac}] (Terminal)`);
            });

            console.log("\n[MAIN DEVICES]");
            Object.keys(clientDevices).forEach(deviceId => {
                const device = clientDevices[deviceId];
                console.log(`[${device.id}, ${device.name}, ${device.mac}]`);
                console.log("  Activities:", device.activities.join(', '));
            });

            console.log("\n[POTENTIAL SERVERS]");
            Object.keys(serverDevices).forEach(deviceId => {
                const device = serverDevices[deviceId];
                console.log(`[${device.id}, ${device.name}, ${device.mac}]`);
                console.log("  Websites Served:", Array.from(device.websites).join(', '));
                console.log("  Activities:", device.activities.join(', '));
            });

            console.log("\n[POTENTIAL ROUTERS]");
            Object.keys(devices.Routers).forEach(deviceId => {
                const device = devices.Routers[deviceId];
                console.log(`[${device.id}, ${device.name}, ${device.mac}]`);
                console.log("  Role:", device.role);
            });

            console.log("\n[ARP ISSUES]");
            arpIssues.forEach(issue => console.log(issue));

            console.log("\n[ICMP ISSUES]");
            icmpIssues.forEach(issue => console.log(issue));

            console.log("\n[DHCP ISSUES]");
            dhcpIssues.forEach(issue => console.log(issue));

            console.log("\n[DHCP ASSUMPTIONS]");
            dhcpAssumptions.forEach(assumption => console.log(assumption));

            console.log("\n[SUMMARY]");
            console.log(summary);

        } else if (option === '-s') {
            // Print only the summary
            console.log("[SUMMARY]");
            console.log(summary);

        } else if (option === '-o') {
            // Print everything except the summary
            console.log("[DEVICES]");
            Object.keys(devices.Routers).forEach(ip => {
                const device = devices.Routers[ip];
                console.log(`${device.id}: [${device.ip}, ${device.name}, ${device.mac}] (Router, ${device.role})`);
            });
            Object.keys(devices.Terminals).forEach(ip => {
                const device = devices.Terminals[ip];
                console.log(`${device.id}: [${device.ip}, ${device.name}, ${device.mac}] (Terminal)`);
            });

            console.log("\n[MAIN DEVICES]");
            Object.keys(clientDevices).forEach(deviceId => {
                const device = clientDevices[deviceId];
                console.log(`[${device.id}, ${device.name}, ${device.mac}]`);
                console.log("  Activities:", device.activities.join(', '));
            });

            console.log("\n[POTENTIAL SERVERS]");
            Object.keys(serverDevices).forEach(deviceId => {
                const device = serverDevices[deviceId];
                console.log(`[${device.id}, ${device.name}, ${device.mac}]`);
                console.log("  Websites Served:", Array.from(device.websites).join(', '));
                console.log("  Activities:", device.activities.join(', '));
            });

            console.log("\n[POTENTIAL ROUTERS]");
            Object.keys(devices.Routers).forEach(deviceId => {
                const device = devices.Routers[deviceId];
                console.log(`[${device.id}, ${device.name}, ${device.mac}]`);
                console.log("  Role:", device.role);
            });

            console.log("\n[ARP ISSUES]");
            arpIssues.forEach(issue => console.log(issue));

            console.log("\n[ICMP ISSUES]");
            icmpIssues.forEach(issue => console.log(issue));

            console.log("\n[DHCP ISSUES]");
            dhcpIssues.forEach(issue => console.log(issue));

            console.log("\n[DHCP ASSUMPTIONS]");
            dhcpAssumptions.forEach(assumption => console.log(assumption));

        } else {
            // Standard output without summary
            console.log("[DEVICES]");
            Object.keys(devices.Routers).forEach(ip => {
                const device = devices.Routers[ip];
                console.log(`${device.id}: [${device.ip}, ${device.name}, ${device.mac}] (Router, ${device.role})`);
            });
            Object.keys(devices.Terminals).forEach(ip => {
                const device = devices.Terminals[ip];
                console.log(`${device.id}: [${device.ip}, ${device.name}, ${device.mac}] (Terminal)`);
            });

            console.log("\n[MAIN DEVICES]");
            Object.keys(clientDevices).forEach(deviceId => {
                const device = clientDevices[deviceId];
                console.log(`[${device.id}, ${device.name}, ${device.mac}]`);
                console.log("  Activities:", device.activities.join(', '));
            });

            console.log("\n[POTENTIAL SERVERS]");
            Object.keys(serverDevices).forEach(deviceId => {
                const device = serverDevices[deviceId];
                console.log(`[${device.id}, ${device.name}, ${device.mac}]`);
                console.log("  Websites Served:", Array.from(device.websites).join(', '));
                console.log("  Activities:", device.activities.join(', '));
            });

            console.log("\n[POTENTIAL ROUTERS]");
            Object.keys(devices.Routers).forEach(deviceId => {
                const device = devices.Routers[deviceId];
                console.log(`[${device.id}, ${device.name}, ${device.mac}]`);
                console.log("  Role:", device.role);
            });

            console.log("\n[ARP ISSUES]");
            arpIssues.forEach(issue => console.log(issue));

            console.log("\n[ICMP ISSUES]");
            icmpIssues.forEach(issue => console.log(issue));

            console.log("\n[DHCP ISSUES]");
            dhcpIssues.forEach(issue => console.log(issue));

            console.log("\n[DHCP ASSUMPTIONS]");
            dhcpAssumptions.forEach(assumption => console.log(assumption));
        }
    } catch (error) {
        console.error(`Error in main function: ${error.message}`);
    }
}

// Get the command-line arguments
const option = process.argv[2];
const fileName = process.argv[3];

// Call the main function with the option and file name
main(option, fileName);
