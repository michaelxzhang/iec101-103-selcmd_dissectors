-- IEC 101 protocol analyzer plugin for Wireshark
--[[
Before you use this plugin, please convert you communication traffic into pcap or pcapng format
Wirtten by: Michael Zhang
Contacct: michaelxmail[AT]gmail.com
--]]

--define constants
M_SP_NA_1 = 1  
M_DP_NA_1 = 3  
M_ST_NA_1 = 5  
M_BO_NA_1 = 7  
M_ME_NA_1 = 9  
M_ME_NB_1 = 11 
M_ME_NC_1 = 13 
M_IT_NA_1 = 15 
M_PS_NA_1 = 20 
M_ME_ND_1 = 21 
M_SP_TB_1 = 30 
M_DP_TB_1 = 31 
M_ST_TB_1 = 32 
M_BO_TB_1 = 33 
M_ME_TD_1 = 34 
M_ME_TE_1 = 35 
M_ME_TF_1 = 36 
M_IT_TB_1 = 37 
M_EP_TD_1 = 38 
M_EP_TE_1 = 39 
M_EP_TF_1 = 40 
C_SC_NA_1 = 45 
C_DC_NA_1 = 46 
C_RC_NA_1 = 47 
C_SE_NA_1 = 48 
C_SE_NB_1 = 49 
C_SE_NC_1 = 50 
C_BO_NA_1 = 51 
C_SC_TA_1 = 58 
C_DC_TA_1 = 59 
C_RC_TA_1 = 60 
C_SE_TA_1 = 61 
C_SE_TB_1 = 62 
C_SE_TC_1 = 63 
C_BO_TA_1 = 64 
M_EI_NA_1 = 70 
C_IC_NA_1 = 100
C_CI_NA_1 = 101
C_RD_NA_1 = 102
C_CS_NA_1 = 103
C_RP_NA_1 = 105
C_TS_TA_1 = 107
P_ME_NA_1 = 110
P_ME_NB_1 = 111
P_ME_NC_1 = 112
P_AC_NA_1 = 113
F_FR_NA_1 = 120
F_SR_NA_1 = 121
F_SC_NA_1 = 122
F_LS_NA_1 = 123
F_AF_NA_1 = 124
F_SG_NA_1 = 125
F_DR_TA_1 = 126
F_SC_NB_1 = 127

--Type id description
iec101_typeid_table = {
[1  ] = "M_SP_NA_1  single-point information",
[3  ] = "M_DP_NA_1  double-point information",
[5  ] = "M_ST_NA_1  step position information",
[7  ] = "M_BO_NA_1  bitstring of 32 bits",
[9  ] = "M_ME_NA_1  measured value, normalized value",
[11 ] = "M_ME_NB_1  measured value, scaled value",
[13 ] = "M_ME_NC_1  measured value, short floating point",
[15 ] = "M_IT_NA_1  integrated totals",
[20 ] = "M_PS_NA_1  packed single-point information with status change detection",
[21 ] = "M_ME_ND_1  measured value, normalized value without quality descriptor",
[30 ] = "M_SP_TB_1  single-point information with time tag CP56Time2a",
[31 ] = "M_DP_TB_1  double-point information with time tag CP56Time2a",
[32 ] = "M_ST_TB_1  step position information with time tag CP56Time2a",
[33 ] = "M_BO_TB_1  bitstring of 32 bit with time tag CP56Time2a",
[34 ] = "M_ME_TD_1  measured value, normalized value with time tag CP56Time2a",
[35 ] = "M_ME_TE_1  measured value, scaled value with time tag CP56Time2a",
[36 ] = "M_ME_TF_1  measured value, short floating point with time tag CP56Time2a",
[37 ] = "M_IT_TB_1  integrated totals with time tag CP56Time2a",
[38 ] = "M_EP_TD_1  event of protection equipment with time tag CP56Time2a",
[39 ] = "M_EP_TE_1  packed start events of protection equipment with time tag CP56Time2a",
[40 ] = "M_EP_TF_1  packed output circuit information of protection equipment with time tag CP56Time2a",
[45 ] = "C_SC_NA_1  single command",
[46 ] = "C_DC_NA_1  double command",
[47 ] = "C_RC_NA_1  regulating step command",
[48 ] = "C_SE_NA_1  set point command, normalized value",
[49 ] = "C_SE_NB_1  set point command, scaled value",
[50 ] = "C_SE_NC_1  set point command, short floating point number",
[51 ] = "C_BO_NA_1  bitstring of 32 bits",
[58 ] = "C_SC_TA_1  single command with time tag CP56Time2a",
[59 ] = "C_DC_TA_1  double command with time tag CP56Time2a",
[60 ] = "C_RC_TA_1  regulating step command with time tag CP56Time2a",
[61 ] = "C_SE_TA_1  set point command, normalized value with time tag CP56Time2a",
[62 ] = "C_SE_TB_1  set point command, scaled value with time tag CP56Time2a",
[63 ] = "C_SE_TC_1  set point command, short floating-point with time tag CP56Time2a",
[64 ] = "C_BO_TA_1  bitstring of 32 bits with time tag CP56Time2a",
[70 ] = "M_EI_NA_1  end of initialization",
[100] = "C_IC_NA_1  interrogation command",
[101] = "C_CI_NA_1  counter interrogation command",
[102] = "C_RD_NA_1  read command",
[103] = "C_CS_NA_1  clock synchronization command",
[105] = "C_RP_NA_1  reset process command",
[107] = "C_TS_TA_1  test command with time tag CP56Time2a",
[110] = "P_ME_NA_1  parameter of measured value, normalized value",
[111] = "P_ME_NB_1  parameter of measured value, scaled value",
[112] = "P_ME_NC_1  parameter of measured value, short floating-point number",
[113] = "P_AC_NA_1  parameter activation",
[120] = "F_FR_NA_1  file ready",
[121] = "F_SR_NA_1  section ready",
[122] = "F_SC_NA_1  call directory, select file, call file, call section",
[123] = "F_LS_NA_1  last section, last segment",
[124] = "F_AF_NA_1  ack file, ack section",
[125] = "F_SG_NA_1  segment",
[126] = "F_DR_TA_1  directory",
[127] = "F_SC_NB_1  Query Log - Request archive file",

}

iec101_typeid2_table = {
[1  ] = "M_SP_NA_1",
[3  ] = "M_DP_NA_1",
[5  ] = "M_ST_NA_1",
[7  ] = "M_BO_NA_1",
[9  ] = "M_ME_NA_1",
[11 ] = "M_ME_NB_1",
[13 ] = "M_ME_NC_1",
[15 ] = "M_IT_NA_1",
[20 ] = "M_PS_NA_1",
[21 ] = "M_ME_ND_1",
[30 ] = "M_SP_TB_1",
[31 ] = "M_DP_TB_1",
[32 ] = "M_ST_TB_1",
[33 ] = "M_BO_TB_1",
[34 ] = "M_ME_TD_1",
[35 ] = "M_ME_TE_1",
[36 ] = "M_ME_TF_1",
[37 ] = "M_IT_TB_1",
[38 ] = "M_EP_TD_1",
[39 ] = "M_EP_TE_1",
[40 ] = "M_EP_TF_1",
[45 ] = "C_SC_NA_1",
[46 ] = "C_DC_NA_1",
[47 ] = "C_RC_NA_1",
[48 ] = "C_SE_NA_1",
[49 ] = "C_SE_NB_1",
[50 ] = "C_SE_NC_1",
[51 ] = "C_BO_NA_1",
[58 ] = "C_SC_TA_1",
[59 ] = "C_DC_TA_1",
[60 ] = "C_RC_TA_1",
[61 ] = "C_SE_TA_1",
[62 ] = "C_SE_TB_1",
[63 ] = "C_SE_TC_1",
[64 ] = "C_BO_TA_1",
[70 ] = "M_EI_NA_1",
[100] = "C_IC_NA_1",
[101] = "C_CI_NA_1",
[102] = "C_RD_NA_1",
[103] = "C_CS_NA_1",
[105] = "C_RP_NA_1",
[107] = "C_TS_TA_1",
[110] = "P_ME_NA_1",
[111] = "P_ME_NB_1",
[112] = "P_ME_NC_1",
[113] = "P_AC_NA_1",
[120] = "F_FR_NA_1",
[121] = "F_SR_NA_1",
[122] = "F_SC_NA_1",
[123] = "F_LS_NA_1",
[124] = "F_AF_NA_1",
[125] = "F_SG_NA_1",
[126] = "F_DR_TA_1",
[127] = "F_SC_NB_1",

}
--Type id object length
iec101_asdu_obj_len_table = {
[1  ] = 1  ,    --M_SP_NA_1
[3  ] = 1  ,    --M_DP_NA_1
[5  ] = 2  ,    --M_ST_NA_1
[7  ] = 5  ,    --M_BO_NA_1
[9  ] = 3  ,    --M_ME_NA_1
[11 ] = 3  ,    --M_ME_NB_1
[13 ] = 5  ,    --M_ME_NC_1
[15 ] = 5  ,    --M_IT_NA_1
[20 ] = 5  ,    --M_PS_NA_1
[21 ] = 2  ,    --M_ME_ND_1
[30 ] = 8  ,    --M_SP_TB_1
[31 ] = 8  ,    --M_DP_TB_1
[32 ] = 9  ,    --M_ST_TB_1
[33 ] = 12 ,   	--M_BO_TB_1
[34 ] = 10 ,   	--M_ME_TD_1
[35 ] = 10 ,   	--M_ME_TE_1
[36 ] = 12 ,   	--M_ME_TF_1
[37 ] = 12 ,   	--M_IT_TB_1
[38 ] = 10 ,  	--M_EP_TD_1
[39 ] = 11 ,  	--M_EP_TE_1
[40 ] = 11 ,  	--M_EP_TF_1
[45 ] = 1  ,   	--C_SC_NA_1
[46 ] = 1  ,   	--C_DC_NA_1
[47 ] = 1  ,   	--C_RC_NA_1
[48 ] = 3  ,   	--C_SE_NA_1
[49 ] = 3  ,   	--C_SE_NB_1
[50 ] = 5  ,   	--C_SE_NC_1
[51 ] = 4  ,  	--C_BO_NA_1
[58 ] = 8  ,  	--C_SC_TA_1
[59 ] = 8  , 	--C_DC_TA_1
[60 ] = 8  ,  	--C_RC_TA_1
[61 ] = 10 ,  	--C_SE_TA_1
[62 ] = 10 ,  	--C_SE_TB_1
[63 ] = 12 ,  	--C_SE_TC_1
[64 ] = 11 ,  	--C_BO_TA_1
[70 ] = 1  , 	--M_EI_NA_1
[100] = 1  ,  	--C_IC_NA_1
[101] = 1  , 	--C_CI_NA_1
[102] = 0  ,  	--C_RD_NA_1
[103] = 7  , 	--C_CS_NA_1
[105] = 1  ,  	--C_RP_NA_1
[107] = 9  , 	--C_TS_TA_1
[110] = 3  ,  	--P_ME_NA_1
[111] = 3  , 	--P_ME_NB_1
[112] = 5  ,  	--P_ME_NC_1
[113] = 1  , 	--P_AC_NA_1
[120] = 6  ,  	--F_FR_NA_1
[121] = 7  , 	--F_SR_NA_1
[122] = 4  ,  	--F_SC_NA_1
[123] = 5  , 	--F_LS_NA_1
[124] = 4  ,  	--F_AF_NA_1
[125] = 0  , 	--F_SG_NA_1
[126] = 13 ,  	--F_DR_TA_1
[127] = 16 ,  	--F_SC_NB_1
}

--Cause of transfer
iec101_cot_table = {
[1 ] = "Period, Cyclic",
[2 ] = "Backgroud scan",
[3 ] = "Spontaneous",
[4 ] = "Initialised",
[5 ] = "Request or requested",
[6 ] = "Activation",
[7 ] = "Activation confirm",
[8 ] = "Deactivation",
[9 ] = "Deactivation confirm",
[10] = "Activation termination",
[11] = "Return information caused by a remote command",
[12] = "Return information caused by a local command",
[13] = "File transfer",
[20] = "Interrogated by general interrogation",
[21] = "Interrogated by group 1 interrogation",
[22] = "Interrogated by group 2 interrogation",
[23] = "Interrogated by group 3 interrogation",
[24] = "Interrogated by group 4 interrogation",
[25] = "Interrogated by group 5 interrogation",
[26] = "Interrogated by group 6 interrogation",
[27] = "Interrogated by group 7 interrogation",
[28] = "Interrogated by group 8 interrogation",
[29] = "Interrogated by group 9 interrogation",
[30] = "Interrogated by group 10 interrogation",
[31] = "Interrogated by group 11 interrogation",
[32] = "Interrogated by group 12 interrogation",
[33] = "Interrogated by group 13 interrogation",
[34] = "Interrogated by group 14 interrogation",
[35] = "Interrogated by group 15 interrogation",
[36] = "Interrogated by group 16 interrogation",
[37] = "Requested by gener counter request",
[38] = "Requested by group 1 counter request",
[39] = "Requested by group 2 counter request",
[40] = "Requested by group 3 counter request",
[41] = "Requested by group 4 counter request",
}

iec101_prm1_func_table = {
[0]   = "Rst Remote link. SEND/CFM expt",
[1]   = "Rst user process. SEND/CFM expt",
[2]   = "Reserved. SEND/CFM expt",
[3]   = "Class 2 available. SEND/CFM expt",
[4]   = "Class 2 available. SEND/NO REPLY expt",
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

iec101_prm0_func_table = {
[0]   = "ACK:positive ack. CFM",
[1]   = "NACK:message not accepted, link busy. CFM",
[2]   = "Reserved",
[3]   = "Reserved",
[4]   = "Reserved",
[5]   = "Reserved",
[6]   = "Reserved",
[7]   = "Reserved",
[8]   = "Class 2 available. RESPOND",
[9]   = "NACK:requested data not available. RESPOND",
[10]  = "Reserved",
[11]  = "Status of link or access demand. RESPOND",
[12]  = "Reserved",
[13]  = "Reserved",
[14]  = "Link service not functioning",
[15]  = "Link service not implemented",

}
iec101_valid_table = {
[0 ] = "Valid",
[1 ] = "Invalid"
}

iec101_spi_str_table = {
[0] = "OFF",
[1] = "ON"
}

iec101_dpi_str_table = {
[0] = "Indeterminate/intermediate",
[1] = "OFF",
[2] = "ON",
[3] = "Indeterminate"
}

iec101_se_table = {
[0 ] = "Execute",
[1 ] = "Select"
}

iec101_qu_table = {
[0] = "No additional definition",
[1] = "Short pulse duration",
[2] = "Long pulse duration",
[3] = "Persistent"
}

iec101_dco_table = {
[0] = "Not permitted",
[1] = "OFF",
[2] = "ON",
[3] = "Not permitted"
}

iec101_month_table = {
[1] = "Jan",
[2] = "Feb",
[3] = "Mar",
[4] = "Apr",
[5] = "May",
[6] = "Jun",
[7] = "Jul",
[8] = "Aug",
[9] = "Sep",
[10] = "Oct",
[11] = "Nov",
[12] = "Dec",
}

iec101_dayofweek_table = {
[0]  = "Day of Week-ERR",
[1]  = "Mon",
[2]  = "Tue",
[3]  = "Wed",
[4]  = "Thu",
[5]  = "Fri",
[6]  = "Sat",
[7]  = "Sun",

}

iec101_qds_ov_table = {
[0 ] = ".... ...0 Not oeverflow",
[1 ] = ".... ...1 Overflow"
}

iec101_qds_bl_table = {
[0 ] = "...0 .... Not blocked",
[1 ] = "...1 .... Blocked"
}

iec101_qds_sb_table = {
[0 ] = "..0. .... Not substituted",
[1 ] = "..1. .... Substituted"
}

iec101_qds_nt_table = {
[0 ] = ".0.. .... Topical",
[1 ] = ".1.. .... Not topical"
}

iec101_qds_iv_table = {
[0 ] = "0... .... Valid",
[1 ] = "1... .... Invalid"
}

iec101_cot_pos_neg_table = {
[0 ] = "Positive",
[1 ] = "Negative"
}

iec101_cot_test_table = {
[0 ] = "No test",
[1 ] = "Test"
}

iec101_qoi_table = {
[0 ] = "Not used",
[1 ] = "Reserved",
[2 ] = "Reserved",
[3 ] = "Reserved",
[4 ] = "Reserved",
[5 ] = "Reserved",
[6 ] = "Reserved",
[7 ] = "Reserved",
[8 ] = "Reserved",
[9 ] = "Reserved",
[10] = "Reserved",
[11] = "Reserved",
[12] = "Reserved",
[13] = "Reserved",
[14] = "Reserved",
[15] = "Reserved",
[16] = "Reserved",
[17] = "Reserved",
[18] = "Reserved",
[19] = "Reserved",
[20] = "Station interrogation(global)",
[21] = "interrogation of group 1 ",
[22] = "interrogation of group 2 ",
[23] = "interrogation of group 3 ",
[24] = "interrogation of group 4 ",
[25] = "interrogation of group 5 ",
[26] = "interrogation of group 6 ",
[27] = "interrogation of group 7 ",
[28] = "interrogation of group 8 ",
[29] = "interrogation of group 9 ",
[30] = "interrogation of group 10",
[31] = "interrogation of group 11",
[32] = "interrogation of group 12",
[33] = "interrogation of group 13",
[34] = "interrogation of group 14",
[35] = "interrogation of group 15",
[36] = "interrogation of group 16",
[37] = "Reserved",
[38] = "Reserved",
[39] = "Reserved",
[40] = "Reserved",
[41] = "Reserved",
}
-- declare our protocol
iec101 = Proto("iec101", "IEC 60870-5-101")

local msg_start = ProtoField.uint8("iec101.Start_Byte","Start",base.HEX)
local msg_length = ProtoField.uint8("iec101.Msg_Length","Length",base.DEC)
local msg_length_rep = ProtoField.uint8("iec101.Msg_Length_Rep","Length_Repeat",base.DEC)
local msg_start_rep = ProtoField.uint8("iec101.Start_Byte_Rep","Start_Repeat",base.HEX)
local msg_ctrl = ProtoField.uint8("iec101.Control_Field","Control_Field",base.HEX)
local msg_ctrl_prm = ProtoField.string("iec101.PRM","PRM")
local msg_ctrl_fcb_acd = ProtoField.string("iec101.FCB_ACD","FCB/ACD")
local msg_ctrl_fcv_dfc = ProtoField.string("iec101.PRM","FCV/DFC")
local msg_ctrl_func = ProtoField.string("iec101.FUNCTION","Function")

local msg_link_addr = ProtoField.uint16("iec101.Link_Addr","Link_Addr",base.DEC)

--local msg_ASDU = ProtoField.uint8("iec101.ASDU","ASDU",base.HEX)
local msg_ASDU = ProtoField.string("iec101.ASDU","ASDU")

local msg_typeid = ProtoField.uint8("iec101.Type_id","Type_id",base.DEC)
local msg_vsq = ProtoField.uint8("iec101.VSQ","Variable_Structure_Qualifier",base.HEX)
local msg_vsq_sq = ProtoField.string("iec101.VSQ_SQ","SQ = ")
local msg_vsq_obj_num = ProtoField.string("iec101.VSQ_OBJ_NUM","Object number = ")

local msg_cot = ProtoField.uint16("iec101.Cause_of_Trans","Cause of Trans",base.DEC)
local msg_comm_addr = ProtoField.uint16("iec101.Common_Addr","Common_address",base.DEC)
local msg_obj_addr = ProtoField.uint32("iec101.Obj_Addr","Obj_address",base.DEC)
local msg_obj = ProtoField.string("iec101.Objects","Objects")
local msg_obj_single = ProtoField.string("iec101.Object_Single","Object")
local msg_obj_value = ProtoField.string("iec101.Object_Value","Value")

local msg_qds = ProtoField.string("iec101.QDS","QDS")
local msg_qds_ov = ProtoField.string("iec101.QDS_OV","OV")
local msg_qds_bl = ProtoField.string("iec101.QDS_BL","BL")
local msg_qds_sb = ProtoField.string("iec101.QDS_SB","SB")
local msg_qds_nt = ProtoField.string("iec101.QDS_NT","NT")
local msg_qds_iv = ProtoField.string("iec101.QDS_IV","IV")

local msg_cp56 = ProtoField.string("iec101.CP56Time2a","CP56Time2a")

local msg_checksum = ProtoField.uint8("iec101.Check_Sum","Check_Sum",base.HEX)
local msg_end = ProtoField.uint8("iec101.End_Byte","End",base.HEX)

local msg_debug = ProtoField.string("iec101.DebugStr","DebugStr")

iec101.fields = {msg_start,msg_length,msg_length_rep,msg_start_rep,msg_ctrl, msg_link_addr, msg_ASDU, msg_typeid, msg_vsq, msg_checksum, msg_end,msg_vsq_sq,msg_vsq_obj_num, msg_cot , msg_comm_addr, msg_obj_addr, msg_obj, msg_obj_single, msg_obj_value, msg_debug,msg_ctrl_prm,msg_ctrl_fcb_acd, msg_ctrl_fcv_dfc,msg_ctrl_func,msg_qds_bl,msg_qds_iv,msg_qds_nt,msg_qds_ov,msg_qds_sb,msg_qds, msg_cp56 }

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

local table_12 = {
        { 1, "One Byte"         , ONEBYTE },
        { 2, "Two Bytes"        , TWOBYTE },
}

local table_123 = {
        { 1, "One Byte"         , ONEBYTE },
        { 2, "Two Bytes"        , TWOBYTE },
		{ 3, "Three Bytes"      , THREEBYTE }
}



-- Create enum preference that shows as radio button under
-- iec101 Protocol's preferences
-- Link address width
iec101.prefs.linkaddrbytes = Pref.enum(
        "Link address width:",                 				-- label
        ONEBYTE,                    						-- default value
        "Zero, One or two bytes for link address field",  	-- description
        table_012,                     						-- enum table
        true                           						-- show as radio button
)

--Common address width
iec101.prefs.commaddrbytes = Pref.enum(
        "Common address width:",                 		-- label
        ONEBYTE,                    					-- default value
        "One or two bytes for common address field",    -- description
        table_12,                     					-- enum table
        true                           					-- show as radio button
)

--Cause of Transfer width
iec101.prefs.cotbytes = Pref.enum(
        "Cause of transmission width:",                 -- label
        ONEBYTE,                    					-- default value
        "One or two bytes for cuase of trans field",    -- description
        table_12,                     					-- enum table
        true                           					-- show as radio button
)

iec101.prefs.objaddrbytes = Pref.enum(
        "Object address width:",                 			-- label
        TWOBYTE,                    						-- default value
        "One,two or three bytes for object address field",  -- description
        table_123,                     						-- enum table
        true                           						-- show as radio button
)

local funccount = 0

function  Get_CP56Time2a(buffer, start_pos)
	local tmpstart = start_pos
	local tmsec = (buffer(start_pos,2):le_uint())/1000.0
	local msec = string.format("%.6f",tmsec)
	start_pos = start_pos + 2
	
	local validstr = "Invalid"
	if buffer(start_pos,1):bitfield(0,1) == 0 then
		validstr = "Valid"
	else
		validstr = "Invalid"
	end
	
	local minute = string.format("%02d",buffer(start_pos,1):bitfield(2,6))
	start_pos = start_pos + 1
	
	local summertime = ""
	
	if (buffer(start_pos,1):bitfield(0,1) == 1) then
		summertime = "Local Summer Time"
	else
		summertime = "Local Time"
	end
	
	local hour = string.format("%02d",buffer(start_pos,1):bitfield(3,5))
	start_pos = start_pos + 1
	
	local dayofweek = iec101_dayofweek_table[buffer(start_pos,1):bitfield(0,3)]
	local dayofmonth = string.format("%02d",buffer(start_pos,1):bitfield(3,5))
	start_pos = start_pos + 1
	
	local month = iec101_month_table[buffer(start_pos,1):bitfield(4,4)]
	start_pos = start_pos + 1
	
	local year = tostring(2000+buffer(start_pos,1):bitfield(1,7))
	start_pos = start_pos + 1
	
	local valuestr = month.." "..dayofmonth..", "..year.." "..dayofweek.." "..hour..":"..minute..":"..msec.." "..summertime.." -- "..validstr
	
	return valuestr
end

function  Add_Object_Value(pinfo,t_obj_single,msgtypeid, buffer, start_pos)
	
	local pnt_value = 0
	local pnt_valid = 1
	local valuestr = ""
	local pnt_v2 = 0.0
	
	if msgtypeid:uint() == M_SP_NA_1 then
		pnt_value = buffer(start_pos,1):bitfield(7,1)
		pnt_valid = buffer(start_pos,1):bitfield(0,1)
		valuestr = iec101_spi_str_table[pnt_value]
		valuestr = valuestr..", "..iec101_valid_table[pnt_valid]
		t_obj_single:add(msg_obj_value,buffer(start_pos, iec101_asdu_obj_len_table[msgtypeid:uint()]),valuestr)
		
		local t_qds = t_obj_single:add(msg_qds,buffer(start_pos, 1), ">>>")
		t_qds:add(msg_qds_bl,buffer(start_pos, 1),iec101_qds_bl_table[buffer(start_pos,1):bitfield(3,1)])
		t_qds:add(msg_qds_sb,buffer(start_pos, 1),iec101_qds_sb_table[buffer(start_pos,1):bitfield(2,1)])
		t_qds:add(msg_qds_nt,buffer(start_pos, 1),iec101_qds_nt_table[buffer(start_pos,1):bitfield(1,1)])
		t_qds:add(msg_qds_iv,buffer(start_pos, 1),iec101_qds_iv_table[buffer(start_pos,1):bitfield(0,1)])
		
	elseif msgtypeid:uint() == M_DP_NA_1 then
		pnt_value = buffer(start_pos,1):bitfield(6,2)
		pnt_valid = buffer(start_pos,1):bitfield(0,1)
		valuestr = iec101_dpi_str_table[pnt_value]
		valuestr = valuestr..", "..iec101_valid_table[pnt_valid]
		t_obj_single:add(msg_obj_value,buffer(start_pos, iec101_asdu_obj_len_table[msgtypeid:uint()]),valuestr)
		
		local t_qds = t_obj_single:add(msg_qds,buffer(start_pos, 1), ">>>")
		t_qds:add(msg_qds_bl,buffer(start_pos, 1),iec101_qds_bl_table[buffer(start_pos,1):bitfield(3,1)])
		t_qds:add(msg_qds_sb,buffer(start_pos, 1),iec101_qds_sb_table[buffer(start_pos,1):bitfield(2,1)])
		t_qds:add(msg_qds_nt,buffer(start_pos, 1),iec101_qds_nt_table[buffer(start_pos,1):bitfield(1,1)])
		t_qds:add(msg_qds_iv,buffer(start_pos, 1),iec101_qds_iv_table[buffer(start_pos,1):bitfield(0,1)])
		
	elseif msgtypeid:uint() == M_ST_NA_1 then
		pnt_value = buffer(start_pos,1):bitfield(1,7)
		pnt_valid = buffer(start_pos+1,1):bitfield(0,1)
		
		--value range -64 - +63
		if pnt_value > 63 then
			pnt_value = (pnt_value * 2) - 256
			pnt_value = pnt_value / 2
		end
		
		valuestr = tostring(pnt_value)
		valuestr = valuestr..", "..iec101_valid_table[pnt_valid]
		t_obj_single:add(msg_obj_value,buffer(start_pos, iec101_asdu_obj_len_table[msgtypeid:uint()]),valuestr)
		
		start_pos = start_pos + 1
		local t_qds = t_obj_single:add(msg_qds,buffer(start_pos, 1), ">>>")
		t_qds:add(msg_qds_ov,buffer(start_pos, 1),iec101_qds_ov_table[buffer(start_pos,1):bitfield(7,1)])
		t_qds:add(msg_qds_bl,buffer(start_pos, 1),iec101_qds_bl_table[buffer(start_pos,1):bitfield(3,1)])
		t_qds:add(msg_qds_sb,buffer(start_pos, 1),iec101_qds_sb_table[buffer(start_pos,1):bitfield(2,1)])
		t_qds:add(msg_qds_nt,buffer(start_pos, 1),iec101_qds_nt_table[buffer(start_pos,1):bitfield(1,1)])
		t_qds:add(msg_qds_iv,buffer(start_pos, 1),iec101_qds_iv_table[buffer(start_pos,1):bitfield(0,1)])
		
	elseif msgtypeid:uint() == M_ME_NA_1 then
		pnt_value = buffer(start_pos,2):le_int()
		--pnt_value = 1000
		--pnt_v2 = pnt_value/32767.0
		pnt_valid = buffer(start_pos+2,1):bitfield(0,1)
		--valuestr = string.format("%.6f",pnt_v2)
		valuestr = tostring(pnt_value)
		valuestr = valuestr..", "..iec101_valid_table[pnt_valid]
		t_obj_single:add(msg_obj_value,buffer(start_pos, iec101_asdu_obj_len_table[msgtypeid:uint()]),valuestr)
		
		start_pos = start_pos + 2
		local t_qds = t_obj_single:add(msg_qds,buffer(start_pos, 1), ">>>")
		t_qds:add(msg_qds_ov,buffer(start_pos, 1),iec101_qds_ov_table[buffer(start_pos,1):bitfield(7,1)])
		t_qds:add(msg_qds_bl,buffer(start_pos, 1),iec101_qds_bl_table[buffer(start_pos,1):bitfield(3,1)])
		t_qds:add(msg_qds_sb,buffer(start_pos, 1),iec101_qds_sb_table[buffer(start_pos,1):bitfield(2,1)])
		t_qds:add(msg_qds_nt,buffer(start_pos, 1),iec101_qds_nt_table[buffer(start_pos,1):bitfield(1,1)])
		t_qds:add(msg_qds_iv,buffer(start_pos, 1),iec101_qds_iv_table[buffer(start_pos,1):bitfield(0,1)])
		
	elseif msgtypeid:uint() == M_ME_NB_1 then
		pnt_value = buffer(start_pos,2):le_int()
		pnt_valid = buffer(start_pos+2,1):bitfield(0,1)
		valuestr = tostring(pnt_value)
		valuestr = valuestr..", "..iec101_valid_table[pnt_valid]
		t_obj_single:add(msg_obj_value,buffer(start_pos, iec101_asdu_obj_len_table[msgtypeid:uint()]),valuestr)
		
		start_pos = start_pos + 2
		local t_qds = t_obj_single:add(msg_qds,buffer(start_pos, 1), ">>>")
		t_qds:add(msg_qds_ov,buffer(start_pos, 1),iec101_qds_ov_table[buffer(start_pos,1):bitfield(7,1)])
		t_qds:add(msg_qds_bl,buffer(start_pos, 1),iec101_qds_bl_table[buffer(start_pos,1):bitfield(3,1)])
		t_qds:add(msg_qds_sb,buffer(start_pos, 1),iec101_qds_sb_table[buffer(start_pos,1):bitfield(2,1)])
		t_qds:add(msg_qds_nt,buffer(start_pos, 1),iec101_qds_nt_table[buffer(start_pos,1):bitfield(1,1)])
		t_qds:add(msg_qds_iv,buffer(start_pos, 1),iec101_qds_iv_table[buffer(start_pos,1):bitfield(0,1)])
		
	elseif msgtypeid:uint() == M_ME_NC_1 then
		pnt_value = buffer(start_pos,4):le_float()
		pnt_valid = buffer(start_pos+4,1):bitfield(0,1)
		valuestr = string.format("%.6f",pnt_value)
		valuestr = valuestr..", "..iec101_valid_table[pnt_valid]
		t_obj_single:add(msg_obj_value,buffer(start_pos, iec101_asdu_obj_len_table[msgtypeid:uint()]),valuestr)
		
		start_pos = start_pos + 4
		local t_qds = t_obj_single:add(msg_qds,buffer(start_pos, 1), ">>>")
		t_qds:add(msg_qds_ov,buffer(start_pos, 1),iec101_qds_ov_table[buffer(start_pos,1):bitfield(7,1)])
		t_qds:add(msg_qds_bl,buffer(start_pos, 1),iec101_qds_bl_table[buffer(start_pos,1):bitfield(3,1)])
		t_qds:add(msg_qds_sb,buffer(start_pos, 1),iec101_qds_sb_table[buffer(start_pos,1):bitfield(2,1)])
		t_qds:add(msg_qds_nt,buffer(start_pos, 1),iec101_qds_nt_table[buffer(start_pos,1):bitfield(1,1)])
		t_qds:add(msg_qds_iv,buffer(start_pos, 1),iec101_qds_iv_table[buffer(start_pos,1):bitfield(0,1)])
		
	elseif msgtypeid:uint() == M_SP_TB_1 then
		pnt_value = buffer(start_pos,1):bitfield(7,1)
		pnt_valid = buffer(start_pos,1):bitfield(0,1)
		valuestr = iec101_spi_str_table[pnt_value]
		valuestr = valuestr..", "..iec101_valid_table[pnt_valid]
		t_obj_single:add(msg_obj_value,buffer(start_pos, 1),valuestr)
		
		local t_qds = t_obj_single:add(msg_qds,buffer(start_pos, 1), ">>>")
		t_qds:add(msg_qds_bl,buffer(start_pos, 1),iec101_qds_bl_table[buffer(start_pos,1):bitfield(3,1)])
		t_qds:add(msg_qds_sb,buffer(start_pos, 1),iec101_qds_sb_table[buffer(start_pos,1):bitfield(2,1)])
		t_qds:add(msg_qds_nt,buffer(start_pos, 1),iec101_qds_nt_table[buffer(start_pos,1):bitfield(1,1)])
		t_qds:add(msg_qds_iv,buffer(start_pos, 1),iec101_qds_iv_table[buffer(start_pos,1):bitfield(0,1)])
		
		start_pos = start_pos + 1

		t_obj_single:add(msg_cp56,buffer(start_pos,7),Get_CP56Time2a(buffer,start_pos))
		
	elseif msgtypeid:uint() == M_DP_TB_1 then
		pnt_value = buffer(start_pos,1):bitfield(6,2)
		pnt_valid = buffer(start_pos,1):bitfield(0,1)
		valuestr = iec101_dpi_str_table[pnt_value]
		valuestr = valuestr..", "..iec101_valid_table[pnt_valid]
		t_obj_single:add(msg_obj_value,buffer(start_pos, 1),valuestr)
		
		local t_qds = t_obj_single:add(msg_qds,buffer(start_pos, 1), ">>>")
		t_qds:add(msg_qds_bl,buffer(start_pos, 1),iec101_qds_bl_table[buffer(start_pos,1):bitfield(3,1)])
		t_qds:add(msg_qds_sb,buffer(start_pos, 1),iec101_qds_sb_table[buffer(start_pos,1):bitfield(2,1)])
		t_qds:add(msg_qds_nt,buffer(start_pos, 1),iec101_qds_nt_table[buffer(start_pos,1):bitfield(1,1)])
		t_qds:add(msg_qds_iv,buffer(start_pos, 1),iec101_qds_iv_table[buffer(start_pos,1):bitfield(0,1)])
		
		start_pos = start_pos + 1

		t_obj_single:add(msg_cp56,buffer(start_pos,7),Get_CP56Time2a(buffer,start_pos))
		
	elseif msgtypeid:uint() == M_ST_TB_1 then
		pnt_value = buffer(start_pos,1):bitfield(1,7)
		pnt_valid = buffer(start_pos+1,1):bitfield(0,1)
		
		--value range -64 - +63
		if pnt_value > 63 then
			pnt_value = (pnt_value * 2) - 256
			pnt_value = pnt_value / 2
		end
		
		valuestr = tostring(pnt_value)
		valuestr = valuestr..", "..iec101_valid_table[pnt_valid]
		t_obj_single:add(msg_obj_value,buffer(start_pos, 2),valuestr)
		
		start_pos = start_pos + 1
		local t_qds = t_obj_single:add(msg_qds,buffer(start_pos, 1), ">>>")
		t_qds:add(msg_qds_ov,buffer(start_pos, 1),iec101_qds_ov_table[buffer(start_pos,1):bitfield(7,1)])
		t_qds:add(msg_qds_bl,buffer(start_pos, 1),iec101_qds_bl_table[buffer(start_pos,1):bitfield(3,1)])
		t_qds:add(msg_qds_sb,buffer(start_pos, 1),iec101_qds_sb_table[buffer(start_pos,1):bitfield(2,1)])
		t_qds:add(msg_qds_nt,buffer(start_pos, 1),iec101_qds_nt_table[buffer(start_pos,1):bitfield(1,1)])
		t_qds:add(msg_qds_iv,buffer(start_pos, 1),iec101_qds_iv_table[buffer(start_pos,1):bitfield(0,1)])
		
		start_pos = start_pos + 1

		t_obj_single:add(msg_cp56,buffer(start_pos,7),Get_CP56Time2a(buffer,start_pos))
		
	elseif msgtypeid:uint() == M_ME_TE_1 then
		pnt_value = buffer(start_pos,2):le_int()
		--pnt_v2 = pnt_value/32767.0
		pnt_valid = buffer(start_pos+2,1):bitfield(0,1)
		--valuestr = string.format("%.6f",pnt_v2)
		valuestr = tostring(pnt_value)
		valuestr = valuestr..", "..iec101_valid_table[pnt_valid]
		
		t_obj_single:add(msg_obj_value,buffer(start_pos, 2),valuestr)
		
		start_pos = start_pos + 2
		local t_qds = t_obj_single:add(msg_qds,buffer(start_pos, 1), ">>>")
		t_qds:add(msg_qds_ov,buffer(start_pos, 1),iec101_qds_ov_table[buffer(start_pos,1):bitfield(7,1)])
		t_qds:add(msg_qds_bl,buffer(start_pos, 1),iec101_qds_bl_table[buffer(start_pos,1):bitfield(3,1)])
		t_qds:add(msg_qds_sb,buffer(start_pos, 1),iec101_qds_sb_table[buffer(start_pos,1):bitfield(2,1)])
		t_qds:add(msg_qds_nt,buffer(start_pos, 1),iec101_qds_nt_table[buffer(start_pos,1):bitfield(1,1)])
		t_qds:add(msg_qds_iv,buffer(start_pos, 1),iec101_qds_iv_table[buffer(start_pos,1):bitfield(0,1)])
		
		start_pos = start_pos + 1

		t_obj_single:add(msg_cp56,buffer(start_pos,7),Get_CP56Time2a(buffer,start_pos))
		
	elseif msgtypeid:uint() == M_ME_TF_1 then
		
		pnt_value = buffer(start_pos,4):le_float()
		pnt_valid = buffer(start_pos+4,1):bitfield(0,1)
		valuestr = string.format("%.6f",pnt_value)
		valuestr = valuestr..", "..iec101_valid_table[pnt_valid]
		t_obj_single:add(msg_obj_value,buffer(start_pos, 4),valuestr)
		
		start_pos = start_pos + 4
		local t_qds = t_obj_single:add(msg_qds,buffer(start_pos, 1), ">>>")
		t_qds:add(msg_qds_ov,buffer(start_pos, 1),iec101_qds_ov_table[buffer(start_pos,1):bitfield(7,1)])
		t_qds:add(msg_qds_bl,buffer(start_pos, 1),iec101_qds_bl_table[buffer(start_pos,1):bitfield(3,1)])
		t_qds:add(msg_qds_sb,buffer(start_pos, 1),iec101_qds_sb_table[buffer(start_pos,1):bitfield(2,1)])
		t_qds:add(msg_qds_nt,buffer(start_pos, 1),iec101_qds_nt_table[buffer(start_pos,1):bitfield(1,1)])
		t_qds:add(msg_qds_iv,buffer(start_pos, 1),iec101_qds_iv_table[buffer(start_pos,1):bitfield(0,1)])
		
		start_pos = start_pos + 1
		
		t_obj_single:add(msg_cp56,buffer(start_pos,7),Get_CP56Time2a(buffer,start_pos))
	
	elseif msgtypeid:uint() == C_SC_NA_1 then
		pnt_value = buffer(start_pos,1):bitfield(7,1)
		local qu = buffer(start_pos,1):bitfield(1,5)
		local se = buffer(start_pos,1):bitfield(0,1)
		
		valuestr = iec101_se_table[se].." "..iec101_spi_str_table[pnt_value].." "..iec101_qu_table[qu]
		t_obj_single:add(msg_obj_value,buffer(start_pos, iec101_asdu_obj_len_table[msgtypeid:uint()]),valuestr)

        local tmpstr8 = pinfo.cols.info
		pinfo.cols.info = tostring(tmpstr8).."-"..iec101_se_table[se]
		
	elseif msgtypeid:uint() == C_DC_NA_1 then
		pnt_value = buffer(start_pos,1):bitfield(6,2)
		local qu = buffer(start_pos,1):bitfield(1,5)
		local se = buffer(start_pos,1):bitfield(0,1)
		
		valuestr = iec101_se_table[se].." "..iec101_dco_table[pnt_value].." "..iec101_qu_table[qu]
		t_obj_single:add(msg_obj_value,buffer(start_pos, iec101_asdu_obj_len_table[msgtypeid:uint()]),valuestr)
		
        local tmpstr8 = pinfo.cols.info
		pinfo.cols.info = tostring(tmpstr8).."-"..iec101_se_table[se]

	elseif msgtypeid:uint() == C_IC_NA_1 then
		pnt_value = buffer(start_pos,1):uint()
		
		valuestr = iec101_qoi_table[pnt_value]
		--if pnt_value == 20 then
		--	valuestr = "Station interrogation (global)"
		--end
		pnt_valid = 0
		valuestr = valuestr..", "..iec101_valid_table[pnt_valid]
		t_obj_single:add(msg_obj_value,buffer(start_pos, iec101_asdu_obj_len_table[msgtypeid:uint()]),valuestr)
	
	elseif msgtypeid:uint() == C_CS_NA_1 then
		
		t_obj_single:add(msg_cp56,buffer(start_pos,7),Get_CP56Time2a(buffer,start_pos))
		
	end
	
	
end

-- create a function to dissect it
function iec101.dissector(buffer,pinfo,tree)

local msgstartbyte = buffer(0,1):uint()
local iec101_link_addr_bytes = iec101.prefs.linkaddrbytes

if msgstartbyte == 16 then
	--if message in multiple data packet, need to be reassembled
	if (4+iec101_link_addr_bytes) > buffer:len() then
		pinfo.desegment_len = (4+iec101_link_addr_bytes) - buffer:len()
	else
		iec101_do_dissector(buffer,pinfo,tree)
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
			--1. TCP frame including multiple completed iec101 data packet
			--2. TCP frame including multiple completed iec101 data packet and one partial data packet
			--3. TCP frame including one completed iec101 data packet and one partial data packet
			while tmpmsglen < tmpbufferlen do
				
				asducnt = asducnt + 1
				
				iec101_do_dissector(buffer(tmppos,tmpmsglen),pinfo,tree)
				
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
					tmpmsglen = 4 + iec101_link_addr_bytes				
				end
				
				--remaining data not enough for one complete data frame
				if tmpmsglen > tmpbufferlen then
					pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
					pinfo.desegment_offset = tmppos
				end
			
			end
			
			if tmpmsglen == tmpbufferlen then
				asducnt = asducnt + 1
				iec101_do_dissector(buffer(tmppos,tmpmsglen),pinfo,tree)
			end
			
			if asducnt > 1 then
				local tmpstr1 = pinfo.cols.info
				pinfo.cols.info = "(**"..asducnt.." ASDUs)"..tostring(tmpstr1)
			end
			
		else
			pinfo.cols.info = ""
			iec101_do_dissector(buffer,pinfo,tree)
		end
	else 
		pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
	end
else
	iec101_do_dissector(buffer,pinfo,tree)
end

end

function iec101_do_dissector(buffer,pinfo,tree)
   
	pinfo.cols.protocol = iec101.name
	
	local msgstartbyte = buffer(0,1):uint()
	
	local iec101_link_addr_bytes = iec101.prefs.linkaddrbytes
	local iec101_comm_addr_bytes = iec101.prefs.commaddrbytes
	local iec101_cot_bytes = iec101.prefs.cotbytes
	local iec101_obj_addr_bytes = iec101.prefs.objaddrbytes
	
	if msgstartbyte == 16 then
		local t0 = tree:add(iec101,buffer(), "IEC 60870-5-101 Fixed Length Message")
		t0:add(msg_start, buffer(0,1))
		--t0:add(msg_ctrl, buffer(1,1))
		
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
				t1:add(msg_ctrl_fcb_acd,buffer(1,1),iec101_prm1_func_table[func])
				pinfo.cols.info = iec101_prm1_func_table[func]
			end
		else
			t1:add(msg_ctrl_fcb_acd,buffer(1,1)," ACD = "..tostring(fcb_acd))
			t1:add(msg_ctrl_fcv_dfc,buffer(1,1)," DFC = "..tostring(fcv_dfc))
			
			t1:add(msg_ctrl_fcb_acd,buffer(1,1),iec101_prm0_func_table[func])
			pinfo.cols.info = iec101_prm0_func_table[func]
		end		
		
		
		--t0:add_le(msg_link_addr,buffer(2,iec101_link_addr_bytes))
		
		if iec101_link_addr_bytes > 0 then
			t0:add_le(msg_link_addr,buffer(2,iec101_link_addr_bytes))
		else
			t0:add_le(msg_link_addr,0)
		end
		
		t0:add(msg_checksum, buffer(2 + iec101_link_addr_bytes,1))
		t0:add(msg_end, buffer(3 + iec101_link_addr_bytes,1))
		
		--t0:add(msg_debug,iec101_link_addr_bytes)
		
	elseif msgstartbyte == 104 then
		local t0 = tree:add(iec101,buffer(), "IEC 60870-5-101 Variable Length Message")
		
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
				t1:add(msg_ctrl_fcb_acd,buffer(4,1),iec101_prm1_func_table[func])
                --pinfo.cols.info = iec101_prm1_func_table[func]
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
			
			t1:add(msg_ctrl_fcb_acd,buffer(4,1),iec101_prm0_func_table[func])
			--pinfo.cols.info = tmpclsstr..iec101_prm0_func_table[func]
		end		
		
		if iec101_link_addr_bytes > 0 then
			t0:add_le(msg_link_addr,buffer(5,iec101_link_addr_bytes))
		else
			t0:add_le(msg_link_addr,0)
		end
		
		local startpos = 5 + iec101_link_addr_bytes
		
		local msglen = buffer(1,1):uint()
		
		local t_asdu = t0:add(msg_ASDU,buffer(startpos, msglen-1-iec101_link_addr_bytes), ">>>")
		
		local msgtypeid = buffer(startpos, 1)
		local t_typeid = t_asdu:add(msg_typeid, msgtypeid)
		t_typeid:append_text(" ("..iec101_typeid_table[msgtypeid:uint()]..")")
		
		local str1
		local str2
		local tmpstr1 = pinfo.cols.info
		str1 = "ASDU="..tostring(msgtypeid:uint())
		str2 = str1.format("%-9s",str1)
		pinfo.cols.info = str2..iec101_typeid_table[msgtypeid:uint()].."; "..tostring(tmpstr1)
		
		startpos = startpos + 1
		local msgvsq = buffer(startpos, 1)
		local t_vsq = t_asdu:add(msg_vsq,msgvsq)
		
		if buffer(startpos, 1):bitfield(0,1) == 0 then
			t_vsq:add(msg_vsq_sq, buffer(startpos, 1), "0, address included in each object")
		else
			t_vsq:add(msg_vsq_sq, buffer(startpos, 1), "1, only one address in the first object")
		end
		
		local msgvsq_sq = buffer(startpos, 1):bitfield(0,1)
		local msgobjnum = buffer(startpos, 1):bitfield(1,7)
		t_vsq:add(msg_vsq_obj_num, buffer(startpos, 1), msgobjnum)
		
		startpos = startpos + 1
		--local msgcotid = buffer(startpos, iec101_cot_bytes):le_uint()
        local msgcotid = buffer(startpos, iec101_cot_bytes):bitfield(2,6)
        local cot_t = buffer(startpos, iec101_cot_bytes):bitfield(0,1)
        local cot_pn = buffer(startpos, iec101_cot_bytes):bitfield(1,1)
		local t_cot = t_asdu:add(msg_cot, buffer(startpos, iec101_cot_bytes), msgcotid)
		t_cot:append_text(" ("..iec101_cot_pos_neg_table[cot_pn]..","..iec101_cot_test_table[cot_t]..","..iec101_cot_table[msgcotid]..")")
		local tmpstr1 = pinfo.cols.info
		pinfo.cols.info = tostring(tmpstr1)..iec101_cot_table[msgcotid].."("..iec101_cot_pos_neg_table[cot_pn]..")"
		
		startpos = startpos + iec101_cot_bytes
		t_asdu:add_le(msg_comm_addr, buffer(startpos, iec101_comm_addr_bytes))
		
		if msgvsq_sq == 0 then
			objlen_total = msgobjnum * (iec101_obj_addr_bytes + iec101_asdu_obj_len_table[msgtypeid:uint()])
			obj_len_each = iec101_obj_addr_bytes + iec101_asdu_obj_len_table[msgtypeid:uint()]
		else
			objlen_total = iec101_obj_addr_bytes + msgobjnum * iec101_asdu_obj_len_table[msgtypeid:uint()]
			obj_len_each = iec101_asdu_obj_len_table[msgtypeid:uint()]
		end
		
		local obj_start_pos = startpos+iec101_comm_addr_bytes
		local obj_start_addr = buffer(startpos+iec101_comm_addr_bytes, iec101_obj_addr_bytes):le_uint()
		
		local t_objs = t_asdu:add(msg_obj,buffer(obj_start_pos, objlen_total),">>> total "..msgobjnum)
		local obj_addr = 0
		
		local tmpstr1 = pinfo.cols.info
		--if msgobjnum > 1 then
		--	pinfo.cols.info = tostring(tmpstr1).." IOA:"
		--end
		
		for cnt = 1, msgobjnum, 1 do
			
			--if VSQ SQ = 0, get the address from each object 
		    if msgvsq_sq == 0 then
				local t_obj_single = t_objs:add(msg_obj_single,buffer(obj_start_pos, obj_len_each), cnt)
				obj_addr = buffer(obj_start_pos, iec101_obj_addr_bytes):le_uint()
				t_obj_single:append_text(" , address: "..obj_addr)
				
				t_obj_single:add_le(msg_obj_addr, buffer(obj_start_pos, iec101_obj_addr_bytes))
				--t_obj_single:add(msg_obj_value,buffer(obj_start_pos+iec101_obj_addr_bytes, iec101_asdu_obj_len_table[msgtypeid:uint()]),"TRUE")
				Add_Object_Value(pinfo,t_obj_single,msgtypeid, buffer, obj_start_pos+iec101_obj_addr_bytes)
			
                --if msgobjnum > 1 then
                    if cnt == 1 then
                        tmpstr1 = pinfo.cols.info
						pinfo.cols.info = tostring(tmpstr1)..",IOA:"..tostring(obj_addr)
                    elseif cnt < 3 then
						tmpstr1 = pinfo.cols.info
						pinfo.cols.info = tostring(tmpstr1).." "..tostring(obj_addr)
					elseif cnt == 3 then
						tmpstr1 = pinfo.cols.info
						pinfo.cols.info = tostring(tmpstr1).." "..tostring(obj_addr).."..."
					end
				--end
                
			else
				
				--if VSQ SQ = 1, get the address from the first object
				if cnt == 1 then
					local t_obj_single = t_objs:add(msg_obj_single,buffer(obj_start_pos, obj_len_each+iec101_obj_addr_bytes), cnt)
					obj_addr = buffer(obj_start_pos, iec101_obj_addr_bytes):le_uint()
					t_obj_single:append_text(" , address: "..obj_addr)
					
					t_obj_single:add_le(msg_obj_addr, buffer(obj_start_pos, iec101_obj_addr_bytes))
					--t_obj_single:add(msg_obj_value,buffer(obj_start_pos+iec101_obj_addr_bytes, iec101_asdu_obj_len_table[msgtypeid:uint()]),"TRUE")
					Add_Object_Value(pinfo,t_obj_single,msgtypeid, buffer, obj_start_pos+iec101_obj_addr_bytes)
					
                    --if msgobjnum > 1 then
						tmpstr1 = pinfo.cols.info
						pinfo.cols.info = tostring(tmpstr1).." "..tostring(obj_addr)
					--end
                    
				--update the following object address 
				else
					local t_obj_single = t_objs:add(msg_obj_single,buffer(obj_start_pos, obj_len_each), cnt)
					obj_addr = obj_addr + 1
					t_obj_single:append_text(" , address: "..obj_addr)
				
					t_obj_single:add(msg_obj_addr, buffer(obj_start_pos, iec101_asdu_obj_len_table[msgtypeid:uint()]),obj_addr)
					--t_obj_single:add(msg_obj_value,buffer(obj_start_pos, iec101_asdu_obj_len_table[msgtypeid:uint()]),"TRUE")
					Add_Object_Value(pinfo,t_obj_single,msgtypeid, buffer, obj_start_pos)
					
                    --if msgobjnum > 1 then
                        if cnt == 1 then
                            tmpstr1 = pinfo.cols.info
						    pinfo.cols.info = tostring(tmpstr1)..",IOA:"..tostring(obj_addr)
                        elseif cnt < 3 then
							tmpstr1 = pinfo.cols.info
							pinfo.cols.info = tostring(tmpstr1).." "..tostring(obj_addr)
						elseif cnt == 3 then
							tmpstr1 = pinfo.cols.info
							pinfo.cols.info = tostring(tmpstr1).." "..tostring(obj_addr).."..."
						end
					--end

				end
			end
			
			--if VSQ SQ = 1, the object address included in the first object
			--increasement also need including the object address width
			if msgvsq_sq == 1 and cnt == 1 then
				obj_start_pos = obj_start_pos + iec101_obj_addr_bytes + iec101_asdu_obj_len_table[msgtypeid:uint()]
			else
				obj_start_pos = obj_start_pos + obj_len_each
			end
		
		end
		
		t0:add(msg_checksum, buffer(4 + msglen,1))
		t0:add(msg_end, buffer(5 + msglen,1))
		
		--local temp = 100
		--t0:add(msg_debug,temp)
		
	elseif msgstartbyte == 229 then
		local t0 = tree:add(iec101,buffer(), "IEC 60870-5-101 Linke layer ACK")
		pinfo.cols.info = "IEC 60870-5-101 Linke layer ACK"
	end
	
end

-- load the tcp.port table
tcp_table = DissectorTable.get("tcp.port")
-- register our protocol to handle tcp port 22401
tcp_table:add(22401,iec101)
