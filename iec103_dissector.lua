-- IEC 103 protocol analyzer plugin for Wireshark
--[[
Before you use this plugin, please convert you communication traffic into pcap or pcapng format
Wirtten by: Michael Zhang
Contacct: michaelxmail[AT]gmail.com
--]]

--Type id description
iec103_typeid_table = {
[1 ] = "Time-tagged message",
[2 ] = "Time-tagged message with relative time",
[3 ] = "Measurands I",
[4 ] = "Time-tagged measurands with relative time",
[5 ] = "Identification",
[6 ] = "Time synchronization",
[7 ] = "General interrogation",
[8 ] = "General interrogation termination",
[9 ] = "Measurands II",
[10] = "Generic data",
[11] = "Generic identification",
[12] = "Future use",
[13] = "Future use",
[14] = "Future use",
[15] = "Future use",
[16] = "Future use",
[17] = "Future use",
[18] = "Future use",
[19] = "Future use",
[20] = "General command",
[21] = "Generic command",
[22] = "Future use",
[23] = "List of recorded disturbances",
[24] = "Order for disturbance data transmission",
[25] = "Acknowledgement for disturbance data transmission",
[26] = "Ready for transmission of disturbance data",
[27] = "Ready for transmission of a channel",
[28] = "Ready for transmission of tags",
[29] = "Transmission of tags",
[30] = "Transmission of disturbance values",
[31] = "End of transmission",
[32] = "Private use",
[33] = "Private use",
[34] = "Private use",
[35] = "Private use",
[36] = "Private use",
[37] = "Private use",
[38] = "Private use",
[39] = "Private use",
[40] = "Positive acknowledgement of generic write command",
[41] = "Negative acknowledgement of generic write command",
[42] = "Valid data response to generic read command",
[43] = "Invalid data response to generic read command",
[44] = "Generic write confirmation",
[45] = "Private use",
[46] = "Private use",
[47] = "Private use",
[48] = "Private use",
[49] = "Private use",
[50] = "Private use",
[51] = "Private use",
[52] = "Private use",
[53] = "Private use",
[54] = "Private use",
[55] = "Private use",
[56] = "Private use",
[57] = "Private use",
[58] = "Private use",
[59] = "Private use",
[60] = "Private use",
[61] = "Private use",
[62] = "Private use",
[63] = "Private use",
[64] = "Private use",
[65] = "Private use",
[66 ] = "Private use",
[67 ] = "Private use",
[68 ] = "Private use",
[69 ] = "Private use",
[70 ] = "Private use",
[71 ] = "Private use",
[72 ] = "Private use",
[73 ] = "Private use",
[74 ] = "Private use",
[75 ] = "Private use",
[76 ] = "Private use",
[77 ] = "Private use",
[78 ] = "Private use",
[79 ] = "Private use",
[80 ] = "Private use",
[81 ] = "Private use",
[82 ] = "Private use",
[83 ] = "Private use",
[84 ] = "Private use",
[85 ] = "Private use",
[86 ] = "Private use",
[87 ] = "Private use",
[88 ] = "Private use",
[89 ] = "Private use",
[90 ] = "Private use",
[91 ] = "Private use",
[92 ] = "Private use",
[93 ] = "Private use",
[94 ] = "Private use",
[95 ] = "Private use",
[96 ] = "Private use",
[97 ] = "Private use",
[98 ] = "Private use",
[99 ] = "Private use",
[100] = "Private use",
[101] = "Private use",
[102] = "Private use",
[103] = "Private use",
[104] = "Private use",
[105] = "Private use",
[106] = "Private use",
[107] = "Private use",
[108] = "Private use",
[109] = "Private use",
[110] = "Private use",
[111] = "Private use",
[112] = "Private use",
[113] = "Private use",
[114] = "Private use",
[115] = "Private use",
[116] = "Private use",
[117] = "Private use",
[118] = "Private use",
[119] = "Private use",
[120] = "Private use",
[121] = "Private use",
[122] = "Private use",
[123] = "Private use",
[124] = "Private use",
[125] = "Private use",
[126] = "Private use",
[127] = "Private use",
[128] = "Private use",
[129] = "Private use",
[130] = "Private use",
[131] = "Private use",
[132] = "Private use",
[133] = "Private use",
[134] = "Private use",
[135] = "Private use",
[136] = "Private use",
[137] = "Private use",
[138] = "Private use",
[139] = "Private use",
[140] = "Private use",
[141] = "Private use",
[142] = "Private use",
[143] = "Private use",
[144] = "Private use",
[145] = "Private use",
[146] = "Private use",
[147] = "Private use",
[148] = "Private use",
[149] = "Private use",
[150] = "Private use",
[151] = "Private use",
[152] = "Private use",
[153] = "Private use",
[154] = "Private use",
[155] = "Private use",
[156] = "Private use",
[157] = "Private use",
[158] = "Private use",
[159] = "Private use",
[160] = "Private use",
[161] = "Private use",
[162] = "Private use",
[163] = "Private use",
[164] = "Private use",
[165] = "Private use",
[166] = "Private use",
[167] = "Private use",
[168] = "Private use",
[169] = "Private use",
[170] = "Private use",
[171] = "Private use",
[172] = "Private use",
[173] = "Private use",
[174] = "Private use",
[175] = "Private use",
[176] = "Private use",
[177] = "Private use",
[178] = "Private use",
[179] = "Private use",
[180] = "Private use",
[181] = "Private use",
[182] = "Private use",
[183] = "Private use",
[184] = "Private use",
[185] = "Private use",
[186] = "Private use",
[187] = "Private use",
[188] = "Private use",
[189] = "Private use",
[190] = "Private use",
[191] = "Private use",
[192] = "Private use",
[193] = "Private use",
[194] = "Private use",
[195] = "Private use",
[196] = "Private use",
[197] = "Private use",
[198] = "Private use",
[199] = "Private use",
[200] = "Private use",
[201] = "Private use",
[202] = "Private use",
[203] = "Private use",
[204] = "Private use",
[205] = "Private use",
[206] = "Private use",
[207] = "Private use",
[208] = "Private use",
[209] = "Private use",
[210] = "Private use",
[211] = "Private use",
[212] = "Private use",
[213] = "Private use",
[214] = "Private use",
[215] = "Private use",
[216] = "Private use",
[217] = "Private use",
[218] = "Private use",
[219] = "Private use",
[220] = "Private use",
[221] = "Private use",
[222] = "Private use",
[223] = "Private use",
[224] = "Private use",
[225] = "Private use",
[226] = "Private use",
[227] = "Private use",
[228] = "Private use",
[229] = "Private use",
[230] = "Private use",
[231] = "Private use",
[232] = "Private use",
[233] = "Private use",
[234] = "Private use",
[235] = "Private use",
[236] = "Private use",
[237] = "Private use",
[238] = "Private use",
[239] = "Private use",
[240] = "Private use",
[241] = "Private use",
[242] = "Private use",
[243] = "Private use",
[244] = "Private use",
[245] = "Private use",
[246] = "Private use",
[247] = "Private use",
[248] = "Private use",
[249] = "Private use",
[250] = "Private use",
[251] = "Private use",
[252] = "Private use",
[253] = "Private use",
[254] = "Private use",
[255] = "Private use",
}

--Type id description
iec103_kod_table = {
[0]  = "NO KOD SPECIFIED",
[1]  = "ACTUAL VALUE",
[2]  = "DEFAULT VALUE",
[3]  = "RANGE (minimum value, maximum value and step size)",
[4]  = "(reserved)",
[5]  = "PRECISION (n, m)",
[6]  = "FACTOR",
[7]  = "% REFERENCE",
[8]  = "ENUMERATION",
[9]  = "DIMENSION",
[10] = "DESCRIPTION",
[11] = "(reserved)",
[12] = "PASSWORD ENTRY",
[13] = "IS READ ONLY",
[14] = "IS WRITE ONLY",
[15] = "(reserved)",
[16] = "(reserved)",
[17] = "(reserved)",
[18] = "(reserved)",
[19] = "CORRESPONDING FUNCTION TYPE AND INFORMATION NUMBER",
[20] = "CORRESPONDING EVENT",
[21] = "ENUMERATED TEXT ARRAY",
[22] = "ENUMERATED VALUE ARRAY",
[23] = "RELATED ENTRIES",
}

--Cause of transfer
iec103_cot_table = {
[1 ] = "Spontaneous",
[2 ] = "Cyclic",
[3 ] = "Reset frame count bit (FCB)",
[4 ] = "Reset communication unit (CU)",
[5 ] = "Start / restart",
[6 ] = "Power on",
[7 ] = "Test mode",
[8 ] = "Time synchronization",
[9 ] = "General interrogation",
[10] = "Termination of general interrogation",
[11] = "Local operation",
[12] = "Remote operation",
[20] = "Positive acknowledgement of command",
[21] = "Negative acknowledgement of command",
[31] = "Transmission of disturbance data",
[40] = "Positive acknowledgement of generic write command",
[41] = "Negative acknowledgement of generic write command",
[42] = "Valid data response to generic read command",
[43] = "Invalid data response to generic read command",
[44] = "Generic write confirmation",
}

local iec103_func_type_table = {
[128] = "t(z) distance protection ",
[160] = "I>>  overcurrent protection ",
[176] = "DIT  transformer differential protection ",
[192] = "DIL  line differential protection ",
[254] = "GEN  generic function type ",
[255] = "GLB  global function type ",
}

local iec103_data_type_table = {
[0]  = "No data",
[1]  = "OS8ASCII,OS8[1..8][ASCII 8-bit-code>",
[2]  = "PACKEDBITSTRING := BS1",
[3]  = "UI",
[4]  = "I",
[5]  = "UF",
[6]  = "F",
[7]  = "R32.23 := Short real IEEE 754",
[8]  = "R64.53 := Real IEEE 754",
[9]  = "DOUBLE POINT INFORMATION (see 7.2.6.5)",
[10] = "SINGLE POINT INFORMATION",
[11] = "DOUBLE POINT INFORMATION WITH TRANSIENT AND ERROR,UI2[1..2] [0..3>",
[12] = "MEASURAND WITH QUALITY DESCRIPTOR (see 7.2.6.8)",
[13] = "Reserved",
[14] = "BINARY TIME (see 7.2.6.29)",
[15] = "GENERIC IDENTIFICATION NUMBER (see 7.2.6.31)",
[16] = "RELATIVE TIME (see 7.2.6.15)",
[17] = "FUNCTION TYPE AND INFORMATION NUMBER,CP16 {Type, INF}",
[18] = "TIME TAGGED MESSAGE,CP48 {DPI, RES, TIME, SIN}",
[19] = "TIME TAGGED MESSAGE WITH RELATIVE TIME,CP80 {DPI, RES, RET, FAN, TIME, SIN}",
[20] = "TIME TAGGED MEASURAND WITH RELATIVE TIME,CP96 {VAL, RET, FAN, TIME}",
[21] = "EXTERNAL TEXT NUMBER := UIi",
[22] = "GENERIC REPLY CODE (see 7.2.6.36)",
[23] = "DATA STRUCTURE,CPii{(GDD, GID)} (see 7.2.6.32 and 7.2.6.33)",
[24] = "INDEX",
}

iec103_prm1_func_table = {
[0]   = "Rst Remote link. SEND/CFM expt",
[1]   = "Rst user process. SEND/CFM expt",
[2]   = "Reserved. SEND/CFM expt",
[3]   = "User data. SEND/CFM expt",
[4]   = "User data. SEND/NO REPLY expt",
[5]   = "Reserved",
[6]   = "Reserved",
[7]   = "Reserved",
[8]   = "expt response specifies access demand. REQUEST for access demand",
[9]   = "Request status of link. REQUEST/RESPOND expt",
[10]  = "Request class 1. REQUEST/RESPOND expt",
[11]  = "Request class 2. REQUEST/RESPOND expt",
[12]  = "Reserved",
[13]  = "Reserved",
[14]  = "Reserved",
[15]  = "Reserved",
}

iec103_prm0_func_table = {
[0]   = "ACK:positive ack. CFM",
[1]   = "NACK:message not accepted, link busy. CFM",
[2]   = "Reserved",
[3]   = "Reserved",
[4]   = "Reserved",
[5]   = "Reserved",
[6]   = "Reserved",
[7]   = "Reserved",
[8]   = "User data. RESPOND",
[9]   = "NACK:requested data not available. RESPOND",
[10]  = "Reserved",
[11]  = "Status of link or access demand. RESPOND",
[12]  = "Reserved",
[13]  = "Reserved",
[14]  = "Link service not functioning",
[15]  = "Link service not implemented",

}

iec103_dayofweek_table = {
[0]  = "Mon",
[1]  = "Tue",
[2]  = "Wed",
[3]  = "Thu",
[4]  = "Fri",
[5]  = "Sat",
[6]  = "Sun",

}

--iec103_valid_table = {
--[0 ] = "Valid",
--[1 ] = "Invalid"
--}

iec103_spi_str_table = {
[0] = "OFF",
[1] = "ON"
}

iec103_dpi_str_table = {
[0] = "Indeterminate/intermediate",
[1] = "OFF",
[2] = "ON",
[3] = "Indeterminate"
}

iec103_doc_str_table = {
[0] = "not used",
[1] = "OFF",
[2] = "ON",
[3] = "not used"
}

iec103_valid_table = {
[0 ] = "Valid",
[1 ] = "Invalid"
}

iec103_spi_str_table = {
[0] = "OFF",
[1] = "ON"
}

iec103_sof_tp_table = {
[0] = "Recorded fault without trip",
[1] = "Recorded fault with trip"
}

iec103_sof_tm_table = {
[0] = "Disturbance data waiting for transmission",
[1] = "Disturbance data currently being transmitted"
}

iec103_sof_test_table = {
[0] = "Disturbance data recorded during normal operation",
[1] = "Disturbance data recorded during test mode"
}

iec103_sof_otev_table = {
[0] = "Disturbance data recording initiated by start/pick-up",
[1] = "Disturbance data recording initiated by other events"
}

iec103_acc_table = {
[0] = "Global",
[1] = "IL1",
[2] = "IL2",
[3] = "IL3",
[4] = "IN",
[5] = "VL1E",
[6] = "VL2E",
[7] = "VL3E",
[8] = "VEN",
}

iec103_overflow_table = {
[0 ] = "No Overflow",
[1 ] = "Overflow"
}

iec103_too_table = {
[1]  = "Selection of fault",
[2]  = "Request for disturbance data",
[3]  = "Abortion of disturbance data",
[8]  = "Request for channel",
[9]  = "Abortion of channel",
[16] = "Request for tags",
[17] = "Abortion of tags",
[24] = "Request for list of recorded disturbances",
[32] = "End of disturbance data transmission without abortion",
[33] = "End of disturbance data transmission with abortion by control system",
[34] = "End of disturbance data transmission with abortion by the protection equipment",
[35] = "End of channel transmission without abortion",
[36] = "End of channel transmission with abortion by control system",
[37] = "End of channel transmission with abortion by the protection quipment",
[38] = "End of tag transmission without abortion",
[39] = "End of tag transmission with abortion by control system",
[40] = "End of tag transmission with abortion by the protection equipment",
[64] = "Disturbance data transmitted successfully (positive)",
[65] = "Disturbance data transmitted not successfully (negative)",
[66] = "Channel transmitted successfully (positive)",
[67] = "Channel transmitted not successfully (negative)",
[68] = "Tags transmitted successfully (positive)",
[69] = "Tags transmitted not successfully (negative)",
}

iec103_tov_table = {
[1] = "Instantaneous values",
}
-- declare our protocol
iec103 = Proto("iec103", "IEC 60870-5-103")

local msg_start = ProtoField.uint8("iec103.Start_Byte","Start",base.HEX)
local msg_length = ProtoField.uint8("iec103.Msg_Length","Length",base.DEC)
local msg_length_rep = ProtoField.uint8("iec103.Msg_Length_Rep","Length_Repeat",base.DEC)
local msg_start_rep = ProtoField.uint8("iec103.Start_Byte_Rep","Start_Repeat",base.HEX)
local msg_ctrl = ProtoField.uint8("iec103.Control_Field","Control_Field",base.HEX)
local msg_ctrl_prm = ProtoField.string("iec103.PRM","PRM")
local msg_ctrl_fcb_acd = ProtoField.string("iec103.FCB_ACD","FCB/ACD")
local msg_ctrl_fcv_dfc = ProtoField.string("iec103.PRM","FCV/DFC")
local msg_ctrl_func = ProtoField.string("iec103.FUNCTION","Function")

local msg_link_addr = ProtoField.uint16("iec103.Link_Addr","Link_Addr",base.DEC)

--local msg_ASDU = ProtoField.uint8("iec103.ASDU","ASDU",base.HEX)
local msg_ASDU = ProtoField.string("iec103.ASDU","ASDU")

local msg_typeid = ProtoField.uint8("iec103.Type_id","Type_id",base.DEC)
local msg_vsq = ProtoField.uint8("iec103.VSQ","Variable_Structure_Qualifier",base.HEX)
local msg_vsq_sq = ProtoField.string("iec103.VSQ_SQ","SQ = ")
local msg_vsq_obj_num = ProtoField.string("iec103.VSQ_OBJ_NUM","Object number = ")

local msg_cot = ProtoField.uint8("iec103.Cause_of_Trans","Cause of Trans",base.DEC)
local msg_comm_addr = ProtoField.uint8("iec103.Common_Addr","Common_address",base.DEC)
local msg_obj_addr = ProtoField.uint8("iec103.Obj_Addr","Obj_address",base.DEC)
local msg_obj = ProtoField.string("iec103.Objects","Objects")
local msg_obj_single = ProtoField.string("iec103.Object_Single","Object")
local msg_obj_value = ProtoField.string("iec103.Object_Value","Value")

local msg_func_type = ProtoField.string("iec103.Function_Type","Func_Type")
local msg_info_num = ProtoField.string("iec103.Info_Num","Info_Num")

local msg_dpi = ProtoField.string("iec103.DPI","DPI")
local msg_bin_time = ProtoField.string("iec103.BIN_TIME","BIN_Time")
local msg_sin = ProtoField.string("iec103.SIN","Supplementary information")

local msg_ret = ProtoField.string("iec103.Relative_time","Relative time")
local msg_fan = ProtoField.string("iec103.Fault_number","Fault number")

local msg_mea = ProtoField.string("iec103.Measurands_I","Measurands I")
local msg_mea2 = ProtoField.string("iec103.Measurands_II","Measurands II")
local msg_scl = ProtoField.string("iec103.Short_Circuit_Location","Short Circuit Location")

local msg_col = ProtoField.string("iec103.Compatibility_level","Compatibility level")
local msg_asc = ProtoField.string("iec103.Char","Char")
local msg_scn = ProtoField.string("iec103.Scan_number","Scan number")

local msg_dset = ProtoField.string("iec103.Dataset","Data Set")
local msg_rii = ProtoField.string("iec103.RII","Return information identifier")
local msg_ngd = ProtoField.string("iec103.NGD","Number of generic data sets")
local msg_gin = ProtoField.string("iec103.GIN","Generic identification number")
local msg_gdd = ProtoField.string("iec103.GDD","Generic data description")
local msg_gdd_datatype = ProtoField.string("iec103.GDD_Datatype","Data Type")
local msg_gdd_datasize = ProtoField.string("iec103.GDD_Datasize","Data Size")
local msg_gdd_number = ProtoField.string("iec103.GDD_number","Number")
local msg_gdd_continue = ProtoField.string("iec103.GDD_continue","Continue Data")

local msg_gid = ProtoField.string("iec103.GID","Generic identification data")
local msg_kod = ProtoField.string("iec103.KOD","Kind of description")

local msg_sof = ProtoField.string("iec103.SOF","Status of fault")

local msg_gid_data = ProtoField.string("iec103.GID_DATA","Data")

local msg_cp56 = ProtoField.string("iec103.CP56Time2a","CP56Time2a")

local msg_too = ProtoField.string("iec103.TOO","Type of order")
local msg_tov = ProtoField.string("iec103.TOV","Type of disturban values")
local msg_acc = ProtoField.string("iec103.ACC","Actual channel")

local msg_int = ProtoField.string("iec103.INT","Interval between information elements")
local msg_noc = ProtoField.string("iec103.NOC","Number of channels")
local msg_noe = ProtoField.string("iec103.NOE","Number of information elements of a channel")
local msg_nof = ProtoField.string("iec103.NOF","Number of grid faults")

local msg_rpv = ProtoField.string("iec103.RPV","Rated primary value")
local msg_rsv = ProtoField.string("iec103.RSV","Rated secondary value")
local msg_rfa = ProtoField.string("iec103.RFA","Reference factor")

local msg_not = ProtoField.string("iec103.NOT","Number of tags")
local msg_tap = ProtoField.string("iec103.TAP","Tag position")

local msg_nfe = ProtoField.string("iec103.NFE","Number of the ASDU first information element")
local msg_ndv = ProtoField.string("iec103.NDV","Number of relevant disturbance values per ASDU")
local msg_sdv = ProtoField.string("iec103.SDV","Single disturbance value")

local msg_nod = ProtoField.string("iec103.NOD","Number of descriptive elements")

local msg_nog = ProtoField.string("iec103.NOG","Number of generic identifications")

local msg_doc = ProtoField.string("iec103.DCO","Double command")

local msg_spi = ProtoField.string("iec103.SPI","Single point info")

local msg_checksum = ProtoField.uint8("iec103.Check_Sum","Check_Sum",base.HEX)
local msg_end = ProtoField.uint8("iec103.End_Byte","End",base.HEX)

local msg_debug = ProtoField.string("iec103.DebugStr","DebugStr")

iec103.fields = {msg_start,msg_length,msg_length_rep,msg_start_rep,msg_ctrl, msg_link_addr, msg_ASDU, msg_typeid, msg_vsq, msg_checksum, msg_end,msg_vsq_sq,msg_vsq_obj_num, msg_cot , msg_comm_addr, msg_func_type,msg_info_num, msg_dpi, msg_bin_time,msg_sin, msg_ret, msg_fan ,msg_rii, msg_ngd, msg_gin, msg_gdd, msg_gid, msg_gid_data, msg_kod, msg_obj_addr, msg_obj, msg_obj_single, msg_obj_value, msg_debug,msg_mea,msg_mea2,msg_scl,msg_asc,msg_col,msg_scn,msg_dset,msg_cp56, msg_gdd_datatype,msg_gdd_datasize,msg_gdd_number,msg_gdd_continue,msg_ctrl_prm,msg_ctrl_fcb_acd, msg_ctrl_fcv_dfc,msg_ctrl_func, msg_sof, msg_too, msg_tov,msg_acc , msg_int, msg_noc, msg_noe, msg_nof, msg_rpv, msg_rfa,msg_rsv, msg_not, msg_tap, msg_ndv,msg_nfe,msg_sdv, msg_nod,msg_doc,msg_nog,msg_spi}

--protocol parameters in Wiresh preference
local ZEROBYTE   = 0
local ONEBYTE    = 1
local TWOBYTE    = 2
local THREEBYTE  = 3
 
local table_012 = {
        { 0, "Zero Byte"        , ZEROBYTE },
		{ 1, "One Byte"         , ONEBYTE },
        { 2, "Two Bytes"        , TWOBYTE },
}

-- Create enum preference that shows as radio button under
-- iec103 Protocol's preferences
-- Link address width
iec103.prefs.linkaddrbytes = Pref.enum(
        "Link address width:",                 				-- label
        ONEBYTE,                    						-- default value
        "Zero, One or two bytes for link address field",  	-- description
        table_012,                     						-- enum table
        true                           						-- show as radio button
)

local funccount = 0

function Get_gid_data(t_gid,buffer, start_pos, datatype,datasize)
	local valstr = ""
	if datatype == 1 then
		local val = buffer(start_pos,1):uint()
		valstr = tostring(val)
	elseif datatype == 2 then
		
		local cnt = 0
		if datasize > 8 then
			datasize = 8
		end
		
		for cnt = 1, datasize,1 do
			valstr = valstr.."Bit"..tostring(datasize-cnt+1).."-"..iec103_spi_str_table[buffer(start_pos,1):bitfield(7-datasize+cnt, 1)].." "
		end
		--valstr = tostring(datasize)
	elseif datatype == 3 then
		local val = buffer(start_pos,datasize):le_uint()
		valstr = tostring(val)
	elseif datatype == 4 then
		local val = buffer(start_pos,datasize):le_int()
		valstr = tostring(val)
	elseif datatype == 5 then
		local val = buffer(start_pos,1):uint()
		local val_2 = val/256.0
		valstr = string.format("%.4f",val_2)
	elseif datatype == 6 then
		local val = buffer(start_pos,2):le_int()
		local val_2 = val/32767.0
		valstr = string.format("%.4f",val_2)
	elseif datatype == 7 then
		local val = buffer(start_pos,4):le_float()
		valstr = string.format("%.4f",val)
	elseif datatype == 8 then
		local val = buffer(start_pos,8):le_float()
		valstr = string.format("%.4f",val)
	elseif datatype == 18 then
		local dpi = buffer(start_pos,1):bitfield(6,2)
		valstr = "DPI:"..iec103_dpi_str_table[dpi]
	elseif datatype == 19 then
		local dpi = buffer(start_pos,1):bitfield(6,2)
		valstr = "DPI:"..iec103_dpi_str_table[dpi]
	end
	
	return valstr
end

function Get_4_Oct_Bin_Time(buffer, start_pos)

	local tmpstart = start_pos
	local tmsec = (buffer(tmpstart,2):le_uint())/1000.0
	local msec = string.format("%.3f",tmsec)
	tmpstart = tmpstart + 2
	
	local validstr = "Invalid"
	if buffer(tmpstart,1):bitfield(0,1) == 0 then
		validstr = "Valid"
	else
		validstr = "Invalid"
	end
	
	local minute = tostring(buffer(tmpstart,1):bitfield(2,6))
	tmpstart = tmpstart + 1
	
	local summertime = ""
	
	if (buffer(tmpstart,1):bitfield(0,1) == 1) then
		summertime = "Summer Time"
	else
		summertime = "Standard Time"
	end
	
	local hour = tostring(buffer(tmpstart,1):bitfield(3,5))
	
	tmpstart = tmpstart + 1
	
	local valstr = hour..":"..minute..":"..msec.." "..summertime.." -- "..validstr
	
	return valstr

end

function Get_element(t_asdu, msgtypeid, func_type, info_num, buffer,start_pos,msgobjnum)

	if msgtypeid:uint() == 1 then
		t_asdu:add(msg_dpi, buffer(start_pos, 1), iec103_dpi_str_table[buffer(start_pos,1):uint()])
		
		start_pos = start_pos + 1

		local timestr = Get_4_Oct_Bin_Time(buffer,start_pos)
		t_asdu:add(msg_bin_time, buffer(start_pos, 4), timestr)
		start_pos = start_pos + 4
		
		t_asdu:add(msg_sin,buffer(start_pos, 1),buffer(start_pos, 1):uint())
		
	elseif msgtypeid:uint() == 2 then
		t_asdu:add(msg_dpi, buffer(start_pos, 1), iec103_dpi_str_table[buffer(start_pos,1):uint()])
		start_pos = start_pos + 1
		
		t_asdu:add(msg_ret,buffer(start_pos, 2),tostring(buffer(start_pos, 2):le_uint()).."ms")
		start_pos = start_pos + 2
		
		t_asdu:add(msg_fan,buffer(start_pos, 2),buffer(start_pos, 2):le_uint())
		start_pos = start_pos + 2
		
		local timestr = Get_4_Oct_Bin_Time(buffer,start_pos)
		t_asdu:add(msg_bin_time, buffer(start_pos, 4), timestr)
		start_pos = start_pos + 4
		
		t_asdu:add(msg_sin,buffer(start_pos, 1),buffer(start_pos, 1):uint())
	elseif msgtypeid:uint() == 3 then
		
		--[[
		t_asdu:add(msg_mea,buffer(start_pos,2),"current L2 = "..buffer(start_pos,2):tostring())
		
		start_pos = start_pos + 2
		t_asdu:add(msg_mea,buffer(start_pos,2),"voltage L1-L2 = "..buffer(start_pos,2):tostring())
		
		start_pos = start_pos + 2
		t_asdu:add(msg_mea,buffer(start_pos,2),"active power = "..buffer(start_pos,2):tostring())
		
		start_pos = start_pos + 2
		t_asdu:add(msg_mea,buffer(start_pos,2),"reactive power Q = "..buffer(start_pos,2):tostring())
		--]]
		
		local ovstr
		local invalidstr
		local tmp
		local tmpstr
		local icnt=0
		local infocnt = info_num
		
		for icnt = 1,msgobjnum,1 do
		
			ovstr = iec103_overflow_table[buffer(start_pos, 1):bitfield(7,1)]
			invalidstr =  iec103_valid_table[buffer(start_pos, 1):bitfield(6,1)]
			tmp = buffer(start_pos,2):le_int();
			tmp = bit.rshift(tmp,3)
			
			tmpstr = tostring(tmp)
			tmpstr = tmpstr..", "..invalidstr.." "..ovstr
			
			t_asdu:add(msg_mea,buffer(start_pos,2),"Measurands "..tostring(icnt).." [infonum "..tostring(infocnt).."]".." = "..tmpstr)
			infocnt = infocnt + 1
			start_pos = start_pos + 2
		end
		
	elseif msgtypeid:uint() == 4 then
		t_asdu:add(msg_scl,buffer(start_pos,4),tostring(buffer(start_pos,4):le_float()))
		
		start_pos = start_pos + 4
		t_asdu:add(msg_ret,buffer(start_pos, 2),buffer(start_pos, 2):le_uint())
		
		start_pos = start_pos + 2
		t_asdu:add(msg_fan,buffer(start_pos, 2),buffer(start_pos, 2):le_uint())
		
		start_pos = start_pos + 2

		local timestr = Get_4_Oct_Bin_Time(buffer,start_pos)
		t_asdu:add(msg_bin_time, buffer(start_pos, 4), timestr)
		start_pos = start_pos + 4
		
	elseif msgtypeid:uint() == 5 then
		t_asdu:add(msg_col,buffer(start_pos,1),tostring(buffer(start_pos,1):uint()))
		
		start_pos = start_pos + 1
		
		local char1 = string.char(buffer(start_pos,1):uint())
		start_pos = start_pos + 1
		local char2 = string.char(buffer(start_pos,1):uint())
		start_pos = start_pos + 1
		local char3 = string.char(buffer(start_pos,1):uint())
		start_pos = start_pos + 1
		local char4 = string.char(buffer(start_pos,1):uint())
		start_pos = start_pos + 1
		local char5 = string.char(buffer(start_pos,1):uint())
		start_pos = start_pos + 1
		local char6 = string.char(buffer(start_pos,1):uint())
		start_pos = start_pos + 1
		local char7 = string.char(buffer(start_pos,1):uint())
		start_pos = start_pos + 1
		local char8 = string.char(buffer(start_pos,1):uint())
		
		start_pos = start_pos + 1
		local ext1 = string.char(buffer(start_pos,1):uint())
		start_pos = start_pos + 1
		local ext2 = string.char(buffer(start_pos,1):uint())
		start_pos = start_pos + 1
		local ext3 = string.char(buffer(start_pos,1):uint())
		start_pos = start_pos + 1
		local ext4 = string.char(buffer(start_pos,1):uint())
		
		t_asdu:add(msg_asc,buffer(start_pos,1),": "..char1..char2..char3..char4..char5..char6..char7..char8..ext1..ext2..ext3..ext4)
		
	elseif msgtypeid:uint() == 6 then
	
		local tmpstart = start_pos
		local tmsec = (buffer(start_pos,2):le_uint())/1000.0
		local msec = string.format("%.3f",tmsec)
		start_pos = start_pos + 2
		
		local validstr = "Invalid"
		if buffer(start_pos,1):bitfield(0,1) == 0 then
			validstr = "Valid"
		else
			validstr = "Invalid"
		end
		
		local minute = tostring(buffer(start_pos,1):bitfield(2,6))
		start_pos = start_pos + 1
		
		local summertime = ""
		
		if (buffer(start_pos,1):bitfield(0,1) == 1) then
			summertime = "Summer Time"
		else
			summertime = "Standard Time"
		end
		
		local hour = tostring(buffer(start_pos,1):bitfield(3,5))
		start_pos = start_pos + 1
		
		local dayofweek = iec103_dayofweek_table[buffer(start_pos,1):bitfield(0,3)]
		local dayofmonth = tostring(buffer(start_pos,1):bitfield(3,5))
		start_pos = start_pos + 1
		
		local month = tostring(buffer(start_pos,1):bitfield(4,4))
		start_pos = start_pos + 1
		
		local year = tostring(2000+buffer(start_pos,1):bitfield(1,7))
		start_pos = start_pos + 1
		
		t_asdu:add(msg_cp56,buffer(tmpstart,7),year.."/"..month.."/"..dayofmonth.."(Y/M/D) "..dayofweek.." "..hour..":"..minute..":"..msec.." "..summertime.." -- "..validstr)
		
	elseif msgtypeid:uint() == 7 then
		t_asdu:add(msg_scn,buffer(start_pos,1), buffer(start_pos,1):uint())
		
	elseif msgtypeid:uint() == 8 then
		t_asdu:add(msg_scn,buffer(start_pos,1), buffer(start_pos,1):uint())
	elseif msgtypeid:uint() == 9 then
		
		local ovstr
		local invalidstr
		local tmp
		local tmpstr
		local icnt=0
		local infocnt = info_num
		
		for icnt = 1,msgobjnum,1 do
		
			ovstr = iec103_overflow_table[buffer(start_pos, 1):bitfield(7,1)]
			invalidstr =  iec103_valid_table[buffer(start_pos, 1):bitfield(6,1)]
			tmp = buffer(start_pos,2):le_int();
			tmp = bit.rshift(tmp,3)
			
			tmpstr = tostring(tmp)
			tmpstr = tmpstr..", "..invalidstr.." "..ovstr
			
			t_asdu:add(msg_mea2,buffer(start_pos,2),"Measurands "..tostring(icnt).." [infonum "..tostring(infocnt).."]".." = "..tmpstr)
			infocnt = infocnt + 1
			start_pos = start_pos + 2
		end
		--[[
		----------------------
		ovstr = iec103_overflow_table[buffer(start_pos, 1):bitfield(0,1)]
		invalidstr =  iec103_valid_table[buffer(start_pos, 1):bitfield(1,1)]
		tmp = buffer(start_pos,2):le_int();
		tmp = bit.rshift(tmp,3)
		tmp = tmp/4096
		
		tmpstr = string.format("%.5f",tmp)
		tmpstr = tmpstr..", "..invalidstr.." "..ovstr
		
		t_asdu:add(msg_mea2,buffer(start_pos,2),"current L2 = "..tmpstr)
		start_pos = start_pos + 2
		
		----------------------
		ovstr = iec103_overflow_table[buffer(start_pos, 1):bitfield(0,1)]
		invalidstr =  iec103_valid_table[buffer(start_pos, 1):bitfield(1,1)]
		tmp = buffer(start_pos,2):le_int();
		tmp = bit.rshift(tmp,3)
		tmp = tmp/4096
		
		tmpstr = string.format("%.5f",tmp)
		tmpstr = tmpstr..", "..invalidstr.." "..ovstr
		
		t_asdu:add(msg_mea2,buffer(start_pos,2),"current L3 = "..tmpstr)
		start_pos = start_pos + 2
		
		----------------------
		ovstr = iec103_overflow_table[buffer(start_pos, 1):bitfield(0,1)]
		invalidstr =  iec103_valid_table[buffer(start_pos, 1):bitfield(1,1)]
		tmp = buffer(start_pos,2):le_int();
		tmp = bit.rshift(tmp,3)
		tmp = tmp/4096
		
		tmpstr = string.format("%.5f",tmp)
		tmpstr = tmpstr..", "..invalidstr.." "..ovstr
		
		t_asdu:add(msg_mea2,buffer(start_pos,2),"voltage L1-E = "..tmpstr)
		start_pos = start_pos + 2
		
		----------------------
		ovstr = iec103_overflow_table[buffer(start_pos, 1):bitfield(0,1)]
		invalidstr =  iec103_valid_table[buffer(start_pos, 1):bitfield(1,1)]
		tmp = buffer(start_pos,2):le_int();
		tmp = bit.rshift(tmp,3)
		tmp = tmp/4096
		
		tmpstr = string.format("%.5f",tmp)
		tmpstr = tmpstr..", "..invalidstr.." "..ovstr
		
		t_asdu:add(msg_mea2,buffer(start_pos,2),"voltage L2-E = "..tmpstr)
		start_pos = start_pos + 2
		
		----------------------
		ovstr = iec103_overflow_table[buffer(start_pos, 1):bitfield(0,1)]
		invalidstr =  iec103_valid_table[buffer(start_pos, 1):bitfield(1,1)]
		tmp = buffer(start_pos,2):le_int();
		tmp = bit.rshift(tmp,3)
		tmp = tmp/4096
		
		tmpstr = string.format("%.5f",tmp)
		tmpstr = tmpstr..", "..invalidstr.." "..ovstr
		
		t_asdu:add(msg_mea2,buffer(start_pos,2),"voltage L3-E = "..tmpstr)
		start_pos = start_pos + 2
		
		----------------------
		ovstr = iec103_overflow_table[buffer(start_pos, 1):bitfield(0,1)]
		invalidstr =  iec103_valid_table[buffer(start_pos, 1):bitfield(1,1)]
		tmp = buffer(start_pos,2):le_int();
		tmp = bit.rshift(tmp,3)
		tmp = tmp/4096
		
		tmpstr = string.format("%.5f",tmp)
		tmpstr = tmpstr..", "..invalidstr.." "..ovstr
		
		t_asdu:add(msg_mea2,buffer(start_pos,2),"active power P = "..tmpstr)
		start_pos = start_pos + 2
		
		----------------------
		ovstr = iec103_overflow_table[buffer(start_pos, 1):bitfield(0,1)]
		invalidstr =  iec103_valid_table[buffer(start_pos, 1):bitfield(1,1)]
		tmp = buffer(start_pos,2):le_int();
		tmp = bit.rshift(tmp,3)
		tmp = tmp/4096
		
		tmpstr = string.format("%.5f",tmp)
		tmpstr = tmpstr..", "..invalidstr.." "..ovstr
		
		t_asdu:add(msg_mea2,buffer(start_pos,2),"reactive power Q = "..tmpstr)
		start_pos = start_pos + 2
		
		----------------------
		ovstr = iec103_overflow_table[buffer(start_pos, 1):bitfield(0,1)]
		invalidstr =  iec103_valid_table[buffer(start_pos, 1):bitfield(1,1)]
		tmp = buffer(start_pos,2):le_int();
		tmp = bit.rshift(tmp,3)
		tmp = tmp/4096
		
		tmpstr = string.format("%.5f",tmp)
		tmpstr = tmpstr..", "..invalidstr.." "..ovstr
		
		t_asdu:add(msg_mea2,buffer(start_pos,2),"frequency f = "..tmpstr)
		--]]
	elseif msgtypeid:uint() == 10 then
		t_asdu:add(msg_rii, buffer(start_pos, 1), buffer(start_pos, 1):uint())
		
		start_pos = start_pos + 1
		local dNo = buffer(start_pos, 1):bitfield(2,6)
		local dcount = buffer(start_pos, 1):bitfield(1,1)
		local dcont = buffer(start_pos, 1):bitfield(0,1)
		
		t_asdu:add(msg_ngd, buffer(start_pos, 1), tostring(dNo)..",further ASDU with same RII:"..tostring(dcont))
		
		start_pos = start_pos + 1
		
		local maglen = buffer(1,1):uint()
		local dsetcnt = 1
		while start_pos <= maglen do
			local t_dset = t_asdu:add(msg_dset,buffer(start_pos, 2),dsetcnt)
			dsetcnt = dsetcnt + 1
			
			local group_str = tostring(buffer(start_pos, 1):uint())
			local entry_str = tostring(buffer(start_pos+1, 1):uint())
			t_dset:add(msg_gin, buffer(start_pos, 2), "Group:"..group_str..",Entry:"..entry_str)
			
			start_pos = start_pos + 2
			t_dset:add(msg_kod, buffer(start_pos, 1), iec103_kod_table[buffer(start_pos, 1):uint()])
			
			start_pos = start_pos + 1
			local datatype = buffer(start_pos, 1):uint()
			local datasize = buffer(start_pos+1, 1):uint()
			local number = buffer(start_pos+2, 1):bitfield(1,7)
			local cont_d = buffer(start_pos+2, 1):bitfield(0,1)
			
			local datatype_str = tostring(datatype)
			local datasize_str = tostring(datasize)
			local number_str = tostring(number)
			local contdata_str = tostring(cont_d)
			
			local t_gdd = t_dset:add(msg_gdd, buffer(start_pos, 3), iec103_data_type_table[datatype])
			
			t_gdd:add(msg_gdd_datatype,buffer(start_pos,1),datatype_str.."--"..iec103_data_type_table[datatype])
			t_gdd:add(msg_gdd_datasize,buffer(start_pos+1,1),datasize_str)
			t_gdd:add(msg_gdd_number,buffer(start_pos+2,1),number_str)
			t_gdd:add(msg_gdd_continue,buffer(start_pos+2,1),contdata_str)
			
			local tmpsize = 0
			
			if datatype == 2 then  --is BITSTRING
				tmpsize = math.floor((datasize-1)/8 + 1)
				--tmpsize = (datasize/8 + 1)
			else
				tmpsize = datasize
			end
			
			start_pos = start_pos + 3
			t_gid = t_dset:add(msg_gid, buffer(start_pos, tmpsize*number),">>>")
			
			local startdatapos = start_pos
			
			local cnt = 0
			
			for cnt = 1, number, 1 do
				local gid_data_str = Get_gid_data(t_gid, buffer, startdatapos, datatype,datasize)
				t_gid:add(msg_gid_data,buffer(startdatapos, tmpsize), tostring(cnt).."--> "..gid_data_str)
				
				if datatype == 2 then
					startdatapos = startdatapos + 1
					
					if datasize > 8 then
					datasize = datasize - 8
					end
					
					tmpsize = math.floor((datasize-1)/8 + 1)
					
				else
					startdatapos = startdatapos + tmpsize
				end
			end
			
			start_pos = startdatapos
		end
	
	elseif msgtypeid:uint() == 11 then
		
		t_asdu:add(msg_rii, buffer(start_pos, 1), buffer(start_pos, 1):uint())
		start_pos = start_pos + 1
		
		t_dset:add(msg_gin, buffer(start_pos, 2), "Group:"..group_str..",Entry:"..entry_str)
		start_pos = start_pos + 2
		
		local numofdescriptive = buffer(start_pos, 1):bitfield(2,6)
		local count = buffer(start_pos, 1):bitfield(1,1)
		local cont = buffer(start_pos, 1):bitfield(0,1)
		local numofdesstr = "NO: "..tostring(numofdescriptive)
		local countstr = ";COUNT:"..tostring(count)
		local contstr = ";CONT"..tostring(cont)
		t_asdu:add(msg_nde, buffer(start_pos, 1), numofdesstr..countstr..contstr)
		start_pos = start_pos + 1
		
		local cnt = 0
		
		for cnt = 1,numofdescriptive,1 do
			local t_dset = t_asdu:add(buffer(start_pos, 1),"Descriptive Element "..tostring(cnt)..">>>")
			
			t_dset:add(msg_kod, buffer(start_pos, 1), iec103_kod_table[buffer(start_pos, 1):uint()])
			start_pos = start_pos + 1
			
			local datatype = buffer(start_pos, 1):uint()
			local datasize = buffer(start_pos+1, 1):uint()
			local number = buffer(start_pos+2, 1):bitfield(1,7)
			local cont_d = buffer(start_pos+2, 1):bitfield(0,1)
			
			local datatype_str = tostring(datatype)
			local datasize_str = tostring(datasize)
			local number_str = tostring(number)
			local contdata_str = tostring(cont_d)
			
			local t_gdd = t_dset:add(msg_gdd, buffer(start_pos, 3), iec103_data_type_table[datatype])
			
			t_gdd:add(msg_gdd_datatype,buffer(start_pos,1),datatype_str.."--"..iec103_data_type_table[datatype])
			t_gdd:add(msg_gdd_datasize,buffer(start_pos+1,1),datasize_str)
			t_gdd:add(msg_gdd_number,buffer(start_pos+2,1),number_str)
			t_gdd:add(msg_gdd_continue,buffer(start_pos+2,1),contdata_str)
			
			local tmpsize = 0
				
			if datatype == 2 then  --is BITSTRING
				tmpsize = math.floor((datasize-1)/8 + 1)
				--tmpsize = (datasize/8 + 1)
			else
				tmpsize = datasize
			end
			
			start_pos = start_pos + 3
			t_gid = t_dset:add(msg_gid, buffer(start_pos, tmpsize*number),">>>")
			
			local startdatapos = start_pos
			
			local cnt = 0
			
			for cnt = 1, number, 1 do
				local gid_data_str = Get_gid_data(t_gid, buffer, startdatapos, datatype,datasize)
				t_gid:add(msg_gid_data,buffer(startdatapos, tmpsize), tostring(cnt).."--> "..gid_data_str)
				
				if datatype == 2 then
					startdatapos = startdatapos + 1
					
					if datasize > 8 then
					datasize = datasize - 8
					end
					
					tmpsize = math.floor((datasize-1)/8 + 1)
					
				else
					startdatapos = startdatapos + tmpsize
				end
			end
		
		end
		
	elseif msgtypeid:uint() == 20 then
		
		t_asdu:add(msg_doc, buffer(start_pos, 1), iec103_doc_str_table[buffer(start_pos, 1):bitfield(6,2)])
		start_pos = start_pos + 1
		
		t_asdu:add(msg_rii, buffer(start_pos, 1), buffer(start_pos, 1):uint())
		start_pos = start_pos + 1
		
		
	elseif msgtypeid:uint() == 21 then
		t_asdu:add(msg_rii, buffer(start_pos, 1), buffer(start_pos, 1):uint())
		start_pos = start_pos + 1
		
		local numofgid = buffer(start_pos, 1):uint()
		
		t_asdu:add(msg_nog, buffer(start_pos, 1), tostring(numofgid))
		start_pos = start_pos + 1
		
		local cnt = 0
		
		for cnt = 1,numofgid,1 do
			local t_dset = t_asdu:add(buffer(start_pos, 2),"Data set "..tostring(cnt)..">>>")
			
			t_dset:add(msg_gin, buffer(start_pos, 2), "Group:"..group_str..",Entry:"..entry_str)
			start_pos = start_pos + 2
			
			t_dset:add(msg_kod, buffer(start_pos, 1), iec103_kod_table[buffer(start_pos, 1):uint()])
			start_pos = start_pos + 1
		end
		
	elseif msgtypeid:uint() == 23 then
	
		local cnt = 0
		
		for cnt = 1, msgobjnum,1 do
			t_rcd = t_asdu:add(buffer(start_pos, 2),"Disturbance record "..tostring(cnt)..">>>")
			t_rcd:add(msg_fan,buffer(start_pos, 2),buffer(start_pos, 2):le_uint())
			start_pos = start_pos + 2
			
			local tpstr = tostring(buffer(start_pos, 1):bitfield(7,1)).."-"..iec103_sof_tp_table[buffer(start_pos, 1):bitfield(7,1)]
			local tmstr = tostring(buffer(start_pos, 1):bitfield(6,1)).."-"..iec103_sof_tm_table[buffer(start_pos, 1):bitfield(6,1)]
			local teststr = tostring(buffer(start_pos, 1):bitfield(5,1)).."-"..iec103_sof_test_table[buffer(start_pos, 1):bitfield(5,1)]
			local otevstr = tostring(buffer(start_pos, 1):bitfield(4,1)).."-"..iec103_sof_otev_table[buffer(start_pos, 1):bitfield(4,1)]
			
			local t_sof = t_rcd:add(msg_sof,buffer(start_pos, 1),buffer(start_pos, 1):uint())
			t_sof:add(buffer(start_pos, 1),tpstr)
			t_sof:add(buffer(start_pos, 1),tmstr)
			t_sof:add(buffer(start_pos, 1),teststr)
			t_sof:add(buffer(start_pos, 1),otevstr)
			
			start_pos = start_pos + 1
			
			local tmpstart = start_pos
			local tmsec = (buffer(start_pos,2):le_uint())/1000.0
			local msec = string.format("%.3f",tmsec)
			start_pos = start_pos + 2
			
			local validstr = "Invalid"
			if buffer(start_pos,1):bitfield(0,1) == 0 then
				validstr = "Valid"
			else
				validstr = "Invalid"
			end
			
			local minute = tostring(buffer(start_pos,1):bitfield(2,6))
			start_pos = start_pos + 1
			
			local summertime = ""
			
			if (buffer(start_pos,1):bitfield(0,1) == 1) then
				summertime = "Summer Time"
			else
				summertime = "Standard Time"
			end
			
			local hour = tostring(buffer(start_pos,1):bitfield(3,5))
			start_pos = start_pos + 1
			
			local dayofweek = iec103_dayofweek_table[buffer(start_pos,1):bitfield(0,3)]
			local dayofmonth = tostring(buffer(start_pos,1):bitfield(3,5))
			start_pos = start_pos + 1
			
			local month = tostring(buffer(start_pos,1):bitfield(4,4))
			start_pos = start_pos + 1
			
			local year = tostring(2000+buffer(start_pos,1):bitfield(1,7))
			start_pos = start_pos + 1
			
			t_rcd:add(msg_cp56,buffer(tmpstart,7),year.."/"..month.."/"..dayofmonth.."(Y/M/D) "..dayofweek.." "..hour..":"..minute..":"..msec.." "..summertime.." -- "..validstr)
		end
		
		
	elseif msgtypeid:uint() == 24 then
		t_asdu:add(msg_too, buffer(start_pos, 1), iec103_too_table[buffer(start_pos,1):uint()])
		start_pos = start_pos + 1
		t_asdu:add(msg_tov, buffer(start_pos, 1), iec103_tov_table[buffer(start_pos,1):uint()])
		start_pos = start_pos + 1
		t_asdu:add(msg_fan, buffer(start_pos, 2), buffer(start_pos,2):le_uint())
		start_pos = start_pos + 2
		t_asdu:add(msg_acc, buffer(start_pos, 1), iec103_acc_table[buffer(start_pos,1):uint()])
		
	elseif msgtypeid:uint() == 25 then
		t_asdu:add(msg_too, buffer(start_pos, 1), iec103_too_table[buffer(start_pos,1):uint()])
		start_pos = start_pos + 1
		t_asdu:add(msg_tov, buffer(start_pos, 1), iec103_tov_table[buffer(start_pos,1):uint()])
		start_pos = start_pos + 1
		t_asdu:add(msg_fan, buffer(start_pos, 2), buffer(start_pos,2):le_uint())
		start_pos = start_pos + 2
		t_asdu:add(msg_acc, buffer(start_pos, 1), iec103_acc_table[buffer(start_pos,1):uint()])
		
	elseif msgtypeid:uint() == 26 then
	
		start_pos = start_pos + 1
		t_asdu:add(msg_tov, buffer(start_pos, 1), iec103_tov_table[buffer(start_pos,1):uint()])
		start_pos = start_pos + 1
		
		t_asdu:add(msg_fan, buffer(start_pos, 2), buffer(start_pos,2):le_uint())
		start_pos = start_pos + 2
		
		t_asdu:add(msg_nof, buffer(start_pos, 2), buffer(start_pos,2):le_uint())
		start_pos = start_pos + 2
		
		t_asdu:add(msg_noc, buffer(start_pos, 1), buffer(start_pos,1):le_uint())
		start_pos = start_pos + 1

		t_asdu:add(msg_noe, buffer(start_pos, 2), buffer(start_pos,2):le_uint())
		start_pos = start_pos + 2
		
		t_asdu:add(msg_int, buffer(start_pos, 2), tostring(buffer(start_pos,2):le_uint()).."us")
		start_pos = start_pos + 2

		local timestr = Get_4_Oct_Bin_Time(buffer,start_pos)
		t_asdu:add(msg_bin_time, buffer(start_pos, 4), timestr)
		start_pos = start_pos + 4
		
	elseif msgtypeid:uint() == 27 then
		start_pos = start_pos + 1
		t_asdu:add(msg_tov, buffer(start_pos, 1), iec103_tov_table[buffer(start_pos,1):uint()])
		start_pos = start_pos + 1
		
		t_asdu:add(msg_fan, buffer(start_pos, 2), buffer(start_pos,2):le_uint())
		start_pos = start_pos + 2
		
		t_asdu:add(msg_acc, buffer(start_pos, 1), iec103_acc_table[buffer(start_pos,1):uint()])
		start_pos = start_pos + 1
		
		local tmprpv = buffer(start_pos,4):le_float()
		local valstr = string.format("%.4f",tmprpv)
		t_asdu:add(msg_rpv, buffer(start_pos, 4), valstr)
		start_pos = start_pos + 4
		
		local tmprsv = buffer(start_pos,4):le_float()
		valstr = string.format("%.4f",tmprsv)
		t_asdu:add(msg_rsv, buffer(start_pos, 4), valstr)
		start_pos = start_pos + 4
		
		local tmprfa = buffer(start_pos,4):le_float()
		valstr = string.format("%.4f",tmprfa)
		t_asdu:add(msg_rfa, buffer(start_pos, 4), valstr)
		start_pos = start_pos + 4
		
	elseif msgtypeid:uint() == 28 then
		start_pos = start_pos + 2
		t_asdu:add(msg_fan, buffer(start_pos, 2), buffer(start_pos,2):le_uint())
		
	elseif msgtypeid:uint() == 29 then
		
		t_asdu:add(msg_fan, buffer(start_pos, 2), buffer(start_pos,2):le_uint())
		start_pos = start_pos + 2
		
		local numoftags = buffer(start_pos,1):le_uint()
		t_asdu:add(msg_not, buffer(start_pos, 1), buffer(start_pos,1):le_uint())
		start_pos = start_pos + 1
	
		t_asdu:add(msg_tap, buffer(start_pos, 2), buffer(start_pos,2):le_uint())
		start_pos = start_pos + 2
			
		local cnt = 0
		for cnt = 1, numoftags, 1 do
			t_tags = t_asdu:add(buffer(start_pos, 3), "Tag "..tostring(cnt)..">>>")
			
			t_tags:add(msg_func_type,buffer(start_pos, 1), buffer(start_pos,1):le_uint())
			start_pos = start_pos + 1
			
			t_tags:add(msg_info_num,buffer(start_pos, 1), buffer(start_pos,1):le_uint())
			start_pos = start_pos + 1
			
			t_tags:add(msg_dpi,buffer(start_pos, 1), iec103_dpi_str_table[buffer(start_pos,1):le_uint()])
			start_pos = start_pos + 1
		end
	
	elseif msgtypeid:uint() == 30 then
		
		start_pos = start_pos + 1
		
		t_asdu:add(msg_tov, buffer(start_pos, 1), iec103_tov_table[buffer(start_pos,1):uint()])
		start_pos = start_pos + 1
		
		t_asdu:add(msg_fan, buffer(start_pos, 2), buffer(start_pos,2):le_uint())
		start_pos = start_pos + 2
		
		t_asdu:add(msg_acc, buffer(start_pos, 1), iec103_acc_table[buffer(start_pos,1):uint()])
		start_pos = start_pos + 1
		
		local numofdist = buffer(start_pos,1):uint()
		t_asdu:add(msg_ndv, buffer(start_pos, 1), tostring(numofdist))
		start_pos = start_pos + 1
		
		local numoffirst = buffer(start_pos,2):le_uint()
		t_asdu:add(msg_nfe, buffer(start_pos, 2), tostring(numoffirst))
		start_pos = start_pos + 2
		
		local val = 0
		local cnt = 0
		
		for cnt = 1,numofdist,1 do
			local val2 = buffer(start_pos,2):le_int() 
			val = val2/32767.0	
			t_asdu:add(msg_sdv, buffer(start_pos, 2), tostring(numoffirst)..": "..string.format("%.4f",val))
			start_pos = start_pos + 2
			numoffirst = numoffirst + 1
		end
		
		
	elseif msgtypeid:uint() == 31 then
		
		t_asdu:add(msg_too, buffer(start_pos, 1), iec103_too_table[buffer(start_pos,1):uint()])
		start_pos = start_pos + 1
		
		t_asdu:add(msg_tov, buffer(start_pos, 1), iec103_tov_table[buffer(start_pos,1):uint()])
		start_pos = start_pos + 1
		
		t_asdu:add(msg_fan, buffer(start_pos, 2), buffer(start_pos,2):le_uint())
		start_pos = start_pos + 2
		
		t_asdu:add(msg_acc, buffer(start_pos, 1), iec103_acc_table[buffer(start_pos,1):uint()])
		start_pos = start_pos + 1
	
	elseif msgtypeid:uint() == 40 then
		local cnt = 0
		local spival =  iec103_spi_str_table[buffer(start_pos, 1):bitfield(7,1)]
		local invalidstr =  iec103_valid_table[buffer(start_pos, 1):bitfield(0,1)]
		
		for cnt = 1,msgobjnum,1 do	
			t_asdu:add(msg_spi,buffer(start_pos, 1), tostring(cnt)..", "..spival.." "..invalidstr)
			start_pos = start_pos + 1
		end
		
	elseif msgtypeid:uint() == 41 then
		local cnt = 0
		local spival = 0
		local invalidstr = 0
		
		for cnt = 1,msgobjnum,1 do	
			spival =  iec103_spi_str_table[buffer(start_pos, 1):bitfield(7,1)]
			invalidstr =  iec103_valid_table[buffer(start_pos, 1):bitfield(0,1)]
			t_spi = t_asdu:add(msg_spi,buffer(start_pos, 1), tostring(cnt)..", "..spival.." "..invalidstr)
			start_pos = start_pos + 1
			
			local timestr = Get_4_Oct_Bin_Time(buffer,start_pos)

			t_spi:add(msg_bin_time, buffer(start_pos, 4), timestr)
			start_pos = start_pos + 4
			
		end
		
		t_asdu:add(msg_sin,buffer(start_pos, 1), buffer(start_pos,1):uint())
		
	elseif msgtypeid:uint() == 42 then
		
		local cnt = 0
		local dpival =  iec103_dpi_str_table[buffer(start_pos, 1):bitfield(6,1)]
		local invalidstr =  iec103_valid_table[buffer(start_pos, 1):bitfield(0,1)]
		
		for cnt = 1,msgobjnum,1 do	
			t_asdu:add(msg_dpi,buffer(start_pos, 1), tostring(cnt)..", "..dpival.." "..invalidstr)
			start_pos = start_pos + 1
		end
	elseif msgtypeid:uint() == 43 then
		local cnt = 0
		local dpival = 0
		local invalidstr = 0
		local t_dpi = 0
		
		for cnt = 1,msgobjnum,1 do	
			local dpival =  iec103_dpi_str_table[buffer(start_pos, 1):bitfield(6,1)]
			local invalidstr =  iec103_valid_table[buffer(start_pos, 1):bitfield(0,1)]
			t_dpi = t_asdu:add(msg_dpi,buffer(start_pos, 1), tostring(cnt)..", "..dpival.." "..invalidstr)
			start_pos = start_pos + 1
			
			local timestr = Get_4_Oct_Bin_Time(buffer,start_pos)
			
			t_dpi:add(msg_bin_time,buffer(start_pos,4),timestr)
			start_pos = start_pos + 4
		end
		
		t_asdu:add(msg_sin,buffer(start_pos, 1), buffer(start_pos,1):uint())
		
	elseif msgtypeid:uint() == 44 then
	end
end


-- create a function to dissect it
function iec103.dissector(buffer,pinfo,tree)

local msgstartbyte = buffer(0,1):uint()
local iec103_link_addr_bytes = iec103.prefs.linkaddrbytes

if msgstartbyte == 16 then
	--if message in multiple data packet, need to be reassembled
	if (4 + iec103_link_addr_bytes) > buffer:len() then
		pinfo.desegment_len = 4 + iec103_link_addr_bytes - buffer:len()
	else
		iec103_do_dissector(buffer,pinfo,tree)
	end
elseif msgstartbyte == 104 then

	if buffer:len() >= 2 then
		local msglen = buffer(1,1):uint()
		msglen = msglen + 6
		--if message in multiple data packet, need to be reassembled
		if msglen > buffer:len() then
			pinfo.desegment_len = msglen - buffer:len()
		elseif msglen < buffer:len() then
			local tmpmsglen = msglen
			local tmpbufferlen = buffer:len()
			local tmpmsgstartbyte = 0
			local tmppos = 0
			local asducnt = 0
			
			pinfo.cols.info = ""
			
			--handle the following situation:
			--1. TCP frame including multiple completed iec103 data packet
			--2. TCP frame including multiple completed iec103 data packet and one partial data packet
			--3. TCP frame including one completed iec103 data packet and one partial data packet
			while tmpmsglen < tmpbufferlen do
				
				asducnt = asducnt + 1
				
				iec103_do_dissector(buffer(tmppos,tmpmsglen),pinfo,tree)
				
				tmppos = tmppos + tmpmsglen
				tmpbufferlen = tmpbufferlen - tmpmsglen
				tmpmsgstartbyte = buffer(tmppos,1):uint()
				
				if tmpmsgstartbyte == 104 then
					if tmpbufferlen > 1 then        --if the remaining length > 1, then it including length info
						tmpmsglen = buffer(tmppos+1,1):uint()
						tmpmsglen = tmpmsglen + 6
					else                            --otherwise, set value greater than 1
						tmpmsglen = 5
					end
				elseif tmpmsgstartbyte == 16 then
					tmpmsglen = 4 + iec103_link_addr_bytes				
				end
				
				--remaining data not enough for one complete data frame
				if tmpmsglen > tmpbufferlen then
					pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
					pinfo.desegment_offset = tmppos
				end
			
			end
			
			if tmpmsglen == tmpbufferlen then
				asducnt = asducnt + 1
				iec103_do_dissector(buffer(tmppos,tmpmsglen),pinfo,tree)
			end
			
			if asducnt > 1 then
				local tmpstr1 = pinfo.cols.info
				pinfo.cols.info = "(**"..asducnt.." ASDUs)"..tostring(tmpstr1)
			end
				
		else
			pinfo.cols.info = ""
			iec103_do_dissector(buffer,pinfo,tree)
		end
	else 
		pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
	end
else
	iec103_do_dissector(buffer,pinfo,tree)
end

end


function iec103_do_dissector(buffer,pinfo,tree)
   
	pinfo.cols.protocol = iec103.name
	
	local msgstartbyte = buffer(0,1):uint()
	
	local iec103_link_addr_bytes = iec103.prefs.linkaddrbytes
	local iec103_comm_addr_bytes = 1
	local iec103_cot_bytes = 1
	
	if msgstartbyte == 16 then
		local t0 = tree:add(iec103,buffer(), "IEC 60870-5-103 Fixed Length Message")
		t0:add(msg_start, buffer(0,1))
		
		local prm = buffer(1,1):bitfield(1,1)
		local fcb_acd  = buffer(1,1):bitfield(2,1)
		local fcv_dfc  = buffer(1,1):bitfield(3,1)
		local func  = buffer(1,1):bitfield(4,4)
		
		local t1 = t0:add(msg_ctrl, buffer(1,1))
		
		t1:add(msg_ctrl_prm,buffer(1,1),tostring(prm))
		
		if prm == 1 then
			t1:add(msg_ctrl_fcb_acd,buffer(1,1)," FCB = "..tostring(fcb_acd))
			t1:add(msg_ctrl_fcv_dfc,buffer(1,1)," FCV = "..tostring(fcv_dfc))
			if ((fcv_dfc == 0) and (func == 0 or func == 1 or func == 4 or func == 8 or func == 9)) or 
			   ((fcv_dfc == 1) and (func == 3 or func == 10 or func == 11)) or
			   (func == 2 or (func > 5 and func < 7) or (func > 12 and func <15)) then
				--t1:add(msg_ctrl_fcb_acd,buffer(1,1),iec103_prm1_func_table[func])
				t1:add(msg_ctrl_func,buffer(1,1),iec103_prm1_func_table[func])
				pinfo.cols.info = iec103_prm1_func_table[func]
			end
		else
			t1:add(msg_ctrl_fcb_acd,buffer(1,1)," ACD = "..tostring(fcb_acd))
			t1:add(msg_ctrl_fcv_dfc,buffer(1,1)," DFC = "..tostring(fcv_dfc))
			
			--t1:add(msg_ctrl_fcb_acd,buffer(1,1),iec103_prm0_func_table[func])
			t1:add(msg_ctrl_func,buffer(1,1),iec103_prm0_func_table[func])
			
			pinfo.cols.info = iec103_prm0_func_table[func]
		end
		
		--t0:add_le(msg_link_addr,buffer(2,iec103_link_addr_bytes))
		if iec103_link_addr_bytes > 0 then
			t0:add_le(msg_link_addr,buffer(2,iec103_link_addr_bytes))
		else
			t0:add_le(msg_link_addr,0)
		end
				
		t0:add(msg_checksum, buffer(2 + iec103_link_addr_bytes,1))
		t0:add(msg_end, buffer(3 + iec103_link_addr_bytes,1))
		
		t0:add(msg_debug,iec103_link_addr_bytes)
		
	elseif msgstartbyte == 104 then
		local t0 = tree:add(iec103,buffer(), "IEC 60870-5-103 Variable Length Message")
		
		t0:add(msg_start, buffer(0,1))
		t0:add(msg_length,buffer(1,1))
		t0:add(msg_length_rep,buffer(2,1))
		t0:add(msg_start_rep, buffer(3,1))
		--t0:add(msg_ctrl, buffer(4,1))
		
		local prm = buffer(4,1):bitfield(1,1)
		local fcb_acd  = buffer(4,1):bitfield(2,1)
		local fcv_dfc  = buffer(4,1):bitfield(3,1)
		local func  = buffer(4,1):bitfield(4,4)
		
		local t1 = t0:add(msg_ctrl, buffer(4,1))
		
		t1:add(msg_ctrl_prm,buffer(4,1),tostring(prm))
		
		if prm == 1 then
			t1:add(msg_ctrl_fcb_acd,buffer(4,1)," FCB = "..tostring(fcb_acd))
			t1:add(msg_ctrl_fcv_dfc,buffer(4,1)," FCV = "..tostring(fcv_dfc))
			if ((fcv_dfc == 0) and (func == 0 or func == 1 or func == 4 or func == 8 or func == 9)) or 
			   ((fcv_dfc == 1) and (func == 3 or func == 10 or func == 11)) or
			   (func == 2 or (func > 5 and func < 7) or (func > 12 and func <15)) then
				--t1:add(msg_ctrl_fcb_acd,buffer(4,1),iec103_prm1_func_table[func])
				t1:add(msg_ctrl_func,buffer(4,1),iec103_prm1_func_table[func])
				
				--pinfo.cols.info = iec103_prm1_func_table[func]
			end
		else
			
			local tmpclsstr = ""
			if fcb_acd == 1 then
				tmpclsstr = " Class 1 available; "
			end
			
			local tmpdfc = ""
			if fcv_dfc == 1 then
				tmpdfc = " further messages may cause overflow"
			end
			
			t1:add(msg_ctrl_fcb_acd,buffer(4,1)," ACD = "..tostring(fcb_acd)..tmpclsstr)
			t1:add(msg_ctrl_fcv_dfc,buffer(4,1)," DFC = "..tostring(fcv_dfc)..tmpdfc)
			
			--t1:add(msg_ctrl_fcb_acd,buffer(4,1),iec103_prm0_func_table[func])
			t1:add(msg_ctrl_func,buffer(4,1),iec103_prm0_func_table[func])
			--pinfo.cols.info = tmpclsstr..iec103_prm0_func_table[func]
		end
		
		--t0:add_le(msg_link_addr,buffer(5,iec103_link_addr_bytes))
		if iec103_link_addr_bytes > 0 then
			t0:add_le(msg_link_addr,buffer(5,iec103_link_addr_bytes))
		else
			t0:add_le(msg_link_addr,0)
		end
		
		local msglen = buffer(1,1):uint()
		
		local t_asdu = t0:add(msg_ASDU,buffer(5+iec103_link_addr_bytes, msglen-1-iec103_link_addr_bytes), ">>>")
		
		local msgtypeid = buffer(5+iec103_link_addr_bytes, 1)
		local t_typeid = t_asdu:add(msg_typeid, msgtypeid)
		t_typeid:append_text(" ("..iec103_typeid_table[msgtypeid:uint()]..")")
		
		local str1
		local str2
		local tmpstr1 = pinfo.cols.info
		str1 = "ASDU="..tostring(msgtypeid:uint())
		str2 = str1.format("%-9s",str1)
		pinfo.cols.info = str2..iec103_typeid_table[msgtypeid:uint()].."; "..tostring(tmpstr1)
		
		local msgvsq = buffer(6+iec103_link_addr_bytes, 1)
		local t_vsq = t_asdu:add(msg_vsq,msgvsq)
		
		if buffer(6+iec103_link_addr_bytes, 1):bitfield(0,1) == 1 then
			t_vsq:add(msg_vsq_sq, buffer(6+iec103_link_addr_bytes, 1), "1, address included in each object")
		else
			t_vsq:add(msg_vsq_sq, buffer(6+iec103_link_addr_bytes, 1), "0, only one address in the first object")
		end
		
		local msgvsq_sq = buffer(6+iec103_link_addr_bytes, 1):bitfield(0,1)
		local msgobjnum = buffer(6+iec103_link_addr_bytes, 1):bitfield(1,7)
		t_vsq:add(msg_vsq_obj_num, buffer(6+iec103_link_addr_bytes, 1), msgobjnum)
		
		local msgcotid = buffer(7+iec103_link_addr_bytes, iec103_cot_bytes):le_uint()
		local t_cot = t_asdu:add(msg_cot, buffer(7+iec103_link_addr_bytes, iec103_cot_bytes), msgcotid)
		t_cot:append_text(" ("..iec103_cot_table[msgcotid]..")")

		t_asdu:add_le(msg_comm_addr, buffer(8+iec103_link_addr_bytes, iec103_comm_addr_bytes))
		
		local func_type = buffer(9+iec103_link_addr_bytes, 1):uint()

		t_asdu:add(msg_func_type,buffer(9+iec103_link_addr_bytes, 1), tostring(func_type))
		
		local info_num = buffer(10+iec103_link_addr_bytes, 1):uint()
		t_asdu:add(msg_info_num,buffer(10+iec103_link_addr_bytes, 1), info_num)
		
		Get_element(t_asdu, msgtypeid, func_type, info_num, buffer,11+iec103_link_addr_bytes,msgobjnum)
				
		t0:add(msg_checksum, buffer(4 + msglen,1))
		t0:add(msg_end, buffer(5 + msglen,1))
		
		local temp = 100
		t0:add(msg_debug,temp)
		
	elseif msg_start == 229 then
		local t0 = tree:add(iec103,buffer(), "IEC 60870-5-103 Linke layer ACK")
	end
	
end

-- load the tcp.port table
tcp_table = DissectorTable.get("tcp.port")
-- register our protocol to handle tcp port 22403
tcp_table:add(22403,iec103)