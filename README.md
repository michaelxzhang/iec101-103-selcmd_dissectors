# Wireshark_dissectors
By Michael Zhang

Wirtten in Lua.

IEC 60870-5-101/103/SEL cmd are serial protocol, Wireshark doesn't have the dissector for it. This dissector will help you decode them in Wireshark.

1. Before you begin

Download the convert tool Ser2pcap.exe on my github: https://github.com/michaelxzhang/serial_to_pcap

Use the tool to convert your serial communication traffic into pcap or pcapng.

2. Run the Install_Wireshark_Dissectors.exe to install the dissectors.
3. Open the converted file, set the protocol preference if needed. Wireshark menu: Edit -> Preferences -> Protocols -> IEC101 or IEC103
