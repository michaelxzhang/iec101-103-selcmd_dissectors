# Wireshark_dissectors
By Michael Zhang

Wirtten in Lua.

IEC 60870-5-101/103/SEL cmd are serial protocol, Wireshark doesn't have the dissector for it. This dissector will help you decode them in Wireshark.

1. Before you begin
You need convert your serial communication traffic into pcap or pcapng.

You can consider use text2pcap.exe that comes with Wireshark, or use tool serial_to_pcap that on my github: https://github.com/michaelxzhang

2. Put the dissectors and install.bat under same folder, and doulbe click install.bat to install the dissectors. Or if you like you can try below method.
	2.1 Run Lua script in Wireshark
		1) Save the iec101_dissector.lua to any folder, e.g. c:\myproto;
		2) Go to Wireshark installation folder, open init.lua, you need administrator privileges on Windows Vista and Windows 7;
		3) Find and make sure line 
		disable_lua = false
		4) At the very end, add the following lines to init.lua
		IEC101_SCRIPT_PATH= "C:\\myproto\\"
		dofile(IEC101_SCRIPT_PATH.."iec101_dissector.lua")
		5) Save and load the converted serial communication traffic in Wireshark.
		
	2.2 Or copy lua file to Wireshark plugin folder(bat file)
		IF NOT EXIST %appdata%\Wireshark\Plugins mkdir %appdata%\Wireshark\Plugins
		copy iec101_dissector.lua %appdata%\Wireshark\Plugins
