IF NOT EXIST %appdata%\Wireshark\Plugins mkdir %appdata%\Wireshark\Plugins
copy iec101_dissector.lua %appdata%\Wireshark\Plugins
copy iec103_dissector.lua %appdata%\Wireshark\Plugins
copy selcmd_dissector.lua %appdata%\Wireshark\Plugins
copy extractdata.lua %appdata%\Wireshark\Plugins
copy extract_dnpdata.lua %appdata%\Wireshark\Plugins

mkdir c:\ser2pcap
copy Ser2pcap.exe c:\ser2pcap\
