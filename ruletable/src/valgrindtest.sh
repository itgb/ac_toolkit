valgrind --tool=memcheck --leak-check=full --show-reachable=yes --show-reachable=yes ./ruletable -t '{
	"ControlRule":[
		{"Id":1,"SrcZoneIds":[1,2],"SrcIpgrpIds":[3,4],"DstZoneIds":[5,6],"DstIpgrpIds":[7,8],"ProtoIds":[0,9],"Action":["AC_ACCEPT","AC_AUDIT"]},
		{"Id":2,"SrcZoneIds":[2,2],"SrcIpgrpIds":[2,4],"DstZoneIds":[2,6],"DstIpgrpIds":[2,8],"ProtoIds":[2,9],"Action":["AC_AUDIT"]}
	],
	"ControlSet":{
		"MacWhiteListSetName":"macwhite",
		"IpWhiteListSetName":"ipwhite",
		"MacBlackListSetName":"macblack",
		"IpBlackListSetName":"ipblack"
	},
	"AuditRule":[
		{"Id":1,"SrcZoneIds":[1,2],"SrcIpgrpIds":[3,4],"DstZoneIds":[5,6],"DstIpgrpIds":[7,8],"ProtoIds":[0,9],"Action":["AC_ACCEPT","AC_AUDIT"]},
		{"Id":2,"SrcZoneIds":[2,2],"SrcIpgrpIds":[2,4],"DstZoneIds":[2,6],"DstIpgrpIds":[2,8],"ProtoIds":[2,9],"Action":["AC_AUDIT"]}
	],
	"AuditSet":{
		"MacWhiteListSetName":"macwhite",
		"IpWhiteListSetName":"ipwhite",
		"MacBlackListSetName":"macblack",
		"IpBlackListSetName":"ipblack"
	}
	}'


