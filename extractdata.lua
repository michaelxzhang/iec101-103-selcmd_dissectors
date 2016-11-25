tcplen = Field.new("tcp.len")
local function getTcpLen()
    local tbl = { tcplen() }
    return tbl[#tbl]()
end

local function menuable_tap()
        
		local filename = os.date("extract_%Y%m%d%H%M%S.txt")
		local file = io.open(filename, "w")

		-- Declare the window we will use
        local tw = TextWindow.new("Extract data to txt file")

        -- This will contain a hash of counters of appearances of a certain address
        --local ips = {}

        --this is our tap, use below example filter to select the frame we need
        --local tap = Listener.new("tcp", "tcp.port == 20000 || tcp.port == 20001");
		local tap = Listener.new("tcp");

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
					
					--file:write("Packet "..tostring(pinfo.abs_ts).."\n")
					file:write(tsline.."\n")
					--file:write(tvbarray:tohex(False," ").."\n\n")
					
					local tvbstr = tvbarray:tohex(False," ")
					local tvbstrleft = tvbstr:len()
					local tvbstrtofile = ""
					local tvbstrstart = 1
					local offsetcnt = 0
					
					while tvbstrleft > 0 do
						
						--file:write(tostring(tvbstrleft)..":"..tostring(tvbstrstart).."\n")
						
						if tvbstrleft >= 48 then
							tvbstrtofile = tvbstr:sub(tvbstrstart,tvbstrstart+47).."\n"
							tvbstrstart = tvbstrstart + 48
							tvbstrleft = tvbstrleft - 48
						else
							tvbstrtofile = tvbstr:sub(tvbstrstart,tvbstrstart+tvbstrleft).."\n\n"
							tvbstrleft = 0
						end
						
						local offsetstr = string.format("%04d ",offsetcnt)
						file:write(offsetstr..tvbstrtofile)
						offsetcnt = offsetcnt + 16
						
					end
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
register_menu("Extract TCP payload data", menuable_tap, MENU_TOOLS_UNSORTED)