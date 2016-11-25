-- SEL ASCII command protocol analyzer plugin for Wireshark
--[[
Before you use this plugin, please convert you communication traffic into pcap or pcapng format
Wirtten by: Michael Zhang
Contacct: michaelxmail[AT]gmail.com
--]]

-- declare our protocol
selcmd = Proto("selcmd", "SEL command")

local msg_content = ProtoField.string("selcmd.content","content")

selcmd.fields = {msg_content}

selcmd.prefs.masterip = Pref.string("Master IP", "10.1.1.1", "IP address of SEL cmd master")
-- create a function to dissect it
function selcmd.dissector(buffer,pinfo,tree)

	if buffer:len() < 2 then
		local tmpv = buffer(0,1):uint()
		
		if (tmpv >= 32 and tmpv <= 126) then
			pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
		else
			selcmd_do_dissector(buffer,pinfo,tree)
		end
	else
		local startpos = 0
		local endpos = 0
		local msglen = 0
		local bufferlen = buffer:len()
		local masterip = selcmd.prefs.masterip
		
		--Reassemble packet 
		while bufferlen >= (startpos+2) do
			local msgstartbyte1 = buffer(startpos,1):uint()
			local msgstartbyte2 = buffer(startpos+1,1):uint()
			
			local tmpv = pinfo.src
			local tmpstr3 = tostring(tmpv)
		
			--if it's fast message use selfm dissector
			if(msgstartbyte1 == 165) then
				
				if(msgstartbyte2 == 70) then    							--A546
					msglen = buffer(startpos+2,1):uint() 
					Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)

				--it's request, no length field
				elseif (msgstartbyte2 == 192 and tmpstr3 == masterip) then	--A5C0
					msglen = 2
					Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
					
					--local tmpcol = pinfo.cols.info
					--pinfo.cols.info = tostring(tmpcol).." (Request) "
					pinfo.cols.info:append(" (Request) ")
					
				elseif msgstartbyte2 == 192 then							--A5C0
					msglen = buffer(startpos+2,1):uint() 
					--Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
					if msglen > (bufferlen-startpos) then
						pinfo.desegment_len = msglen - bufferlen + startpos
					else
						Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
					end
					
					--local tmpcol = pinfo.cols.info
					--pinfo.cols.info = tostring(tmpcol).." (Response) "
					pinfo.cols.info:append(" (Response) ")
					
				elseif (msgstartbyte2 == 193 and tmpstr3 == masterip) then	--A5C1
					msglen = 2 
					Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
					
					--local tmpcol = pinfo.cols.info
					--pinfo.cols.info = tostring(tmpcol).." (Request) "
					pinfo.cols.info:append(" (Request) ")
					
				elseif msgstartbyte2 == 193 then							--A5C1
					msglen = buffer(startpos+2,1):uint() 
					--Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
					if msglen > (bufferlen-startpos) then
						pinfo.desegment_len = msglen - bufferlen + startpos
					else
						Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
					end
					
					--local tmpcol = pinfo.cols.info
					--pinfo.cols.info = tostring(tmpcol).." (Response) "
					pinfo.cols.info:append(" (Response) ")
					
				elseif (msgstartbyte2 == 194 and tmpstr3 == masterip) then	--A5C2
					msglen = 2 
					Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
					
					--local tmpcol = pinfo.cols.info
					--pinfo.cols.info = tostring(tmpcol).." (Request) "
					pinfo.cols.info:append(" (Request) ")
					
				elseif msgstartbyte2 == 194 then							--A5C2
					msglen = buffer(startpos+2,1):uint() 
					--Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
					if msglen > (bufferlen-startpos) then
						pinfo.desegment_len = msglen - bufferlen + startpos
					else
						Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
					end
					
					--local tmpcol = pinfo.cols.info
					--pinfo.cols.info = tostring(tmpcol).." (Response) "
					pinfo.cols.info:append(" (Response) ")
					
				elseif (msgstartbyte2 == 195 and tmpstr3 == masterip) then	--A5C3
					msglen = 2 
					Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
					
					--local tmpcol = pinfo.cols.info
					--pinfo.cols.info = tostring(tmpcol).." (Request) "
					pinfo.cols.info:append(" (Request) ")
					
				elseif msgstartbyte2 == 195 then							--A5C3
					msglen = buffer(startpos+2,1):uint() 
					
					if msglen > (bufferlen-startpos) then
						pinfo.desegment_len = msglen - bufferlen + startpos
					else
						Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
					end
					
					--local tmpcol = pinfo.cols.info
					--pinfo.cols.info = tostring(tmpcol).." (Response) "
					pinfo.cols.info:append(" (Response) ")
					
				elseif (msgstartbyte2 == 206 and tmpstr3 == masterip) then	--A5CE
					msglen = 2 
					Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
					
					--local tmpcol = pinfo.cols.info
					--pinfo.cols.info = tostring(tmpcol).." (Request) "
					pinfo.cols.info:append(" (Request) ")
					
				elseif msgstartbyte2 == 206 then							--A5CE
					msglen = buffer(startpos+2,1):uint() 
					--Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
					if msglen > (bufferlen-startpos) then
						pinfo.desegment_len = msglen - bufferlen + startpos
					else
						Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
					end
					
					--local tmpcol = pinfo.cols.info
					--pinfo.cols.info = tostring(tmpcol).." (Response) "
					pinfo.cols.info:append(" (Response) ")
					
				elseif (msgstartbyte2 == 209 and tmpstr3 == masterip) then	--A5D1
					msglen = 2 
					Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
					
					--local tmpcol = pinfo.cols.info
					--pinfo.cols.info = tostring(tmpcol).." (Request) "
					pinfo.cols.info:append(" (Request) ")

				elseif msgstartbyte2 == 209 then							--A5D1
					msglen = buffer(startpos+2,1):uint() 
					--Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
					if msglen > (bufferlen-startpos) then
						pinfo.desegment_len = msglen - bufferlen + startpos
					else
						Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
					end
					
					--local tmpcol = pinfo.cols.info
					--pinfo.cols.info = tostring(tmpcol).." (Response) "
					pinfo.cols.info:append(" (Response) ")
					
				elseif (msgstartbyte2 == 210 and tmpstr3 == masterip) then	--A5D2
					msglen = 2 
					Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
					
					--local tmpcol = pinfo.cols.info
					--pinfo.cols.info = tostring(tmpcol).." (Request) "
					pinfo.cols.info:append(" (Request) ")
					
				elseif msgstartbyte2 == 210 then							--A5D2
					msglen = buffer(startpos+2,1):uint() 
					--Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
					if msglen > (bufferlen-startpos) then
						pinfo.desegment_len = msglen - bufferlen + startpos
					else
						Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
					end
					
					--local tmpcol = pinfo.cols.info
					--pinfo.cols.info = tostring(tmpcol).." (Response) "
					pinfo.cols.info:append(" (Response) ")
					
				elseif (msgstartbyte2 == 211 and tmpstr3 == masterip) then	--A5D3
					msglen = 2 
					Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
					
					--local tmpcol = pinfo.cols.info
					--pinfo.cols.info = tostring(tmpcol).." (Request) "
					pinfo.cols.info:append(" (Request) ")
					
				elseif msgstartbyte2 == 211 then							--A5D3
					msglen = buffer(startpos+2,1):uint() 
					--Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
					if msglen > (bufferlen-startpos) then
						pinfo.desegment_len = msglen - bufferlen + startpos
					else
						Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
					end
					
					--local tmpcol = pinfo.cols.info
					--pinfo.cols.info = tostring(tmpcol).." (Response) "
					pinfo.cols.info:append(" (Response) ")
					
				elseif msgstartbyte2 == 224 then							--A5E0
					msglen = buffer(startpos+2,1):uint() 
					Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
				elseif msgstartbyte2 == 227 then							--A5E3
					msglen = buffer(startpos+2,1):uint() 
					Dissector.get("selfm"):call(buffer(startpos,msglen):tvb(), pinfo, tree)
				else
					msglen = bufferlen - startpos 
					selcmd_do_dissector(buffer(startpos,msglen):tvb(),pinfo,tree)
				end
			else
				msglen = bufferlen - startpos 
				selcmd_do_dissector(buffer(startpos,msglen):tvb(),pinfo,tree)
			end
			
			startpos = startpos + msglen
			
		end --while
	end
end

function selcmd_do_dissector(buffer,pinfo,tree)
   
	local cnt
	local endpos = 0
	local range = 0
	local tmpstr = ""
	
	if buffer:len() > 80 then
		range = 80
	else
		range = buffer:len()
	end
	
	for cnt = 0, range-1, 1 do
		local currv = buffer(cnt,1):le_uint()
		--ASCII < 32 or >126 are non-display, replace them with .
		if currv < 32 then
			tmpstr = tmpstr.."."
		elseif currv > 126 then
			tmpstr = tmpstr.."."
		else 
			tmpstr = tmpstr..buffer(cnt,1):string()
		end
	end
	
	
	if (buffer(0,1):int() == 3 and buffer:len() == 1) then
		tmpstr = "ETX"
	elseif (buffer(0,1):int() == 17 and buffer:len() == 1) then
		tmpstr = "XON(Buffer drops below 25% full)"
	elseif (buffer(0,1):int() == 19 and buffer:len() == 1) then
		tmpstr = "XOFF(Buffer over 75% full)"
	elseif (buffer(0,1):int() == 24 and buffer:len() == 1) then
		tmpstr = "CAN(Abort a pending transmission)"
	elseif (buffer(0,1):int() == 17 and buffer(1,1):int() == 24) then
		tmpstr = "Cancel last operation"
	end
	
	local tmpprov = pinfo.cols.protocol
	local tmpprostr = tostring(tmpprov)
	
	local tmpcol = pinfo.cols.info

	local t0 = tree:add(selcmd,buffer(), "SEL CMD")
	
	local bufferlen = buffer:len()
	local tmpline = ""
	local linestart = 0
	local linelen = 0
	
	--Add the content of the SEL CMD
	--display line by line
	for cnt = 0, bufferlen-1, 1 do
		local currv = buffer(cnt,1):le_uint()
		local nextv = 0
		
		--Non display ASCII, display as '.'
		--if it's 0xa, check if there's 0xd before it, if yes 0xa alreay in previous line, don't attach 0xa in current line
		if (currv == 10 and cnt > 0) then
			local prev = buffer(cnt-1,1):uint()
			if  prev ~= 13 then
				tmpline = tmpline.."."
			end
		elseif (currv < 32 or currv > 126) then
			tmpline = tmpline.."."
		else
			tmpline = tmpline..buffer(cnt,1):string()
		end
		
		linelen = linelen + 1
		
		if currv == 13 then
			if cnt < (bufferlen-1) then
				nextv = buffer(cnt+1, 1):uint()
				
				--if 0xd come with 0xa, make 0xd 0xa in same line
				if nextv == 10 then
					tmpline = tmpline.."."
					linelen = linelen + 1
					--tmpline = tmpline..":"..tostring(linestart)..":"..tostring(linelen)
					t0:add(msg_content, buffer(linestart,linelen), tmpline)
					linestart = cnt + 2
					linelen = -1
				
				--then if only found 0xd, make it a line
				else
					--tmpline = tmpline..":"..tostring(linestart)..":"..tostring(linelen)
					t0:add(msg_content, buffer(linestart,linelen), tmpline)
					linestart = cnt + 1
					linelen = 0
				end
				nextv = 0
				
			--then if 0xd is last char, make it a line	
			elseif cnt == (bufferlen-1) then
				t0:add(msg_content, buffer(linestart,linelen), tmpline)
				linestart = 0
				linelen = 0
			end
			
			tmpline = ""

		end
		
	end
	
	--display the remaining string
	if tmpline:len() > 0 then
		--t0:add(msg_content, buffer(linestart,linelen), tmpline)
		--tmpline = tmpline..tostring(linestart)..":"..tostring(linelen)
		t0:add(msg_content, buffer(linestart,linelen), tmpline)
	end
	
	if tmpprostr == "SEL Protocol" then
		--pinfo.cols.info = tostring(tmpcol).." || SEL CMD: "..tmpstr
		pinfo.cols.info:append(" || SEL CMD: "..tmpstr)
	else
		pinfo.cols.protocol = selcmd.name
		pinfo.cols.info = "SEL CMD: "..tmpstr
	end
end

-- load the tcp.port table
tcp_table = DissectorTable.get("tcp.port")
-- register our protocol to handle tcp port 22423
tcp_table:add(22423,selcmd)

