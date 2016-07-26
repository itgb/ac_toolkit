./ruletable '{
	"ControlRule":[
		{"Id":1,"SrcZoneIds":[1,2,3],"SrcIpgrpIds":[3,4,5],"DstZoneIds":[5,6,7],"DstIpgrpIds":[7,8,9,10],"ProtoIds":[9,10,11,12],"Action":["ACCEPT","AUDIT"]},
		{"Id":2,"SrcZoneIds":[2,2],"SrcIpgrpIds":[2,4,5],"DstZoneIds":[2,6,9],"DstIpgrpIds":[2,8,111],"ProtoIds":[2,9,99],"Action":["REJECT"]}
	]}'


