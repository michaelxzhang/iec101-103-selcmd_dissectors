tcplen = Field.new("tcp.len")
local function getTcpLen()
    local tbl = { tcplen() }
    return tbl[#tbl]()
end

local function menuable_tap()
        
		local filename = os.date("extract_dnp3_%Y%m%d%H%M%S.txt")
		local file = io.open(filename, "w")

		-- Declare the window we will use
        local tw = TextWindow.new("Extract DNP3 data to txt file")

        -- This will contain a hash of counters of appearances of a certain address
        --local ips = {}

        --this is our tap, use below example filter to select the frame we need
        --local tap = Listener.new("tcp", "tcp.port == 20000 || tcp.port == 20001");
		local tap = Listener.new("tcp","dnp3");

        function remove()
                -- this way we remove the listener that otherwise will remain running indefinitely
                tap:remove();
				file:close()
        end

        -- we tell the window to call the remove() function when closed
        tw:set_atclose(remove)

        -- this function will be called once for each packet
        function tap.packet(pinfo,tvb,ip)
                
				--extract payload data bytes
				local bufferlen = tvb:len()
				local buftcplen = getTcpLen()
				
				--only do it when have payload data
				if buftcplen > 0 then
				
					local srcstr = tostring(pinfo.src)
					local dststr = tostring(pinfo.dst)
					local srcport = tostring(pinfo.src_port)
					local dstport = tostring(pinfo.dst_port)
					
					tw:append("Extracting row "..pinfo.number.."\n");
					
					--get abs time
					local tmptimestr = tostring(pinfo.abs_ts)
					local tmptime1 = tonumber(tmptimestr) 
					local tmptime = tmptime1*10000
					
					--remove the chars after "."
					tmptime = Int64(tmptime)
					tmptimestr = tostring(tmptime)
					
					--get ms string
					local timestrlen = tmptimestr:len()
					local time_ms = tmptimestr:sub(timestrlen - 3)
					
					--get time string
					local timestr = os.date("%H:%M:%S", tmptime1)
					local tsline = timestr.."."..time_ms
					--local tsline = tmptimestr
				
					tsline = "["..tsline.."]  "..srcstr..":"..srcport.." => "..dststr..":"..dstport.." "
								
					local tvbarray1 = tvb(54,buftcplen):bytes()
					local tvbarray = ByteArray.new(tostring(tvbarray1)," ")
					
					file:write(tsline.."\n")
					--file:write(tsline..":"..start1..":"..start2..":"..start3.."\n")
					
					local start1 = tvb(54,1):uint()
					local start2 = tvb(55,1):uint()
					local start3 = tvb(56,1):uint()
					
					local tvbstr = tvbarray:tohex(False," ")
					local tvbstrleft = tvbstr:len()
					local tvbstrtofile = ""
					local tvbstrstart = 1
					local offsetcnt = 1
					local firstline = 0
					local cutpoint = 0
					
					if (start1 == 5 and start2 == 100 and start3 >= 5) then
					
						while tvbstrleft > 0 do
							
							--file:write(tostring(tvbstrleft)..":"..tostring(tvbstrstart).."\n")
							local offsetstr = string.format("%04d ",offsetcnt)
							local temprem = offsetcnt - 281
							
							--if (offsetcnt == 281 or offsetcnt == 573 or offsetcnt == 865 or offsetcnt == 1157 or offsetcnt == 1449) then
							if(offsetcnt >= 281 and temprem%292 == 0) then
								cutpoint = 1
							else
								cutpoint = 0
							end
							
							if (cutpoint == 1 and tvbstrleft > 35) then
								tvbstrtofile = tvbstr:sub(tvbstrstart,tvbstrstart+35).."\n\n"
								tvbstrstart = tvbstrstart + 36
								tvbstrleft = tvbstrleft - 36
								offsetcnt = offsetcnt + 12
								firstline = 0
							elseif (firstline == 0 and tvbstrleft >= 30) then
								tvbstrtofile = tvbstr:sub(tvbstrstart,tvbstrstart+29).."\n"
								tvbstrstart = tvbstrstart + 30
								tvbstrleft = tvbstrleft - 30
								offsetcnt = offsetcnt + 10
								firstline = 1
							elseif (tvbstrleft >= 54) then
								tvbstrtofile = tvbstr:sub(tvbstrstart,tvbstrstart+53).."\n"
								tvbstrstart = tvbstrstart + 54
								tvbstrleft = tvbstrleft - 54
								offsetcnt = offsetcnt + 18
							else
								tvbstrtofile = tvbstr:sub(tvbstrstart,tvbstrstart+tvbstrleft).."\n\n"
								tvbstrleft = 0
							end
							
							file:write(offsetstr..tvbstrtofile)
							
						end
					end --end if 
				end
        end

        -- this function will be called once every few seconds to update our window
        function tap.draw(t)
                --tw:clear()
                --for ip,num in pairs(ips) do
                --        tw:append(ip .. "\t" .. num .. "\n");
                --end
        end

        -- this function will be called whenever a reset is needed
        -- e.g. when reloading the capture file
        function tap.reset()
                tw:clear()
                --ips = {}
        end
		
		retap_packets()
end

-- using this function we register our function
-- to be called when the user selects the Tools->Extract TCP payload data menu
register_menu("Extract DNP3 data", menuable_tap, MENU_TOOLS_UNSORTED)