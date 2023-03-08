# Wireshark_dissectors
By Michael Zhang

Wirtten in Lua.

**The latest Wireshark already come with IEC 60870-5-101 and 103 dissectors. You can comment out these two dissectors in install.bat.**

IEC 60870-5-101/103/SEL cmd are serial protocol, Wireshark doesn't have the dissector for it. This dissector will help you decode them in Wireshark.

1. Before you begin

Download the tool Ser2pcap.exe on my github: https://github.com/michaelxzhang/serial_to_pcap

Use the tool to convert your serial communication traffic into pcap or pcapng.

2. Run the install.bat or Install_Wireshark_Dissectors.exe to install the dissectors.
3. Open the converted file, set the protocol preference if needed. Wireshark menu: Edit -> Preferences -> Protocols -> IEC101 or IEC103
