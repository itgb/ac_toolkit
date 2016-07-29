gdb --args ./ruletable -s '{
	"ControlRule":[
		{"Id":1,"SrcZoneIds":[101,2011],"SrcIpgrpIds":[3011,4011],"DstZoneIds":[501,601],"DstIpgrpIds":[701,801],"ProtoIds":[1000,999,888],"Action":["ACCEPT","AUDIT"]}
	]
	}'


