/*	
	Description of basic data structures which are used in both userspace and kernel space.
*/

#ifndef _RULE_TABLE_H
#define _RULE_TABLE_H

#include <linux/types.h>
#include <linux/kernel.h>
typedef unsigned short u_int16_t;
//typedef unsigned int   u_int32_t;

#define AC_FLOWID_DATA_TYPE u_int16_t
#define AC_PROTOID_DATA_TYPE u_int32_t

/*
 * 'kernel.h' contains some often-used function prototypes etc
 */
#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
/* this is a dummy structure to find out the alignment requirement for a struct
 * containing all the fundamental data types that are used in ipt_entry,
 * ip6t_entry and arpt_entry.  This sucks, and it is a hack.  It will be my
 * personal pleasure to remove it -HW
 */
struct _ac_align {
	__u8 u8;
	__u16 u16;
	__u32 u32;
	__u64 u64;
};

#define AC_ALIGN(s) __ALIGN_KERNEL((s), __alignof__(struct _ac_align))



#define AC_IPSET_MAXNAMELEN 32
#define AC_IPGRP_MAXID  	63
#define AC_IPGRP_MINID		0
#define AC_ZONE_MAXID		255
#define AC_ZONE_MINID		0
#define AC_RULE_MAXID       65535
#define AC_RULE_MINID		0
/*protoid sorted style, we will make proto ids sorted in desc or asc for searching fast*/
enum ac_protoid_sort {
	AC_PROTOID_SORT_DESC,
	AC_PROTOID_SORT_ASC,
	AC_PROTOID_SORT_MAX
};

/*type of flow config*/
enum ac_flow_type {
	AC_FLOW_TYPE_SRCZONEID = 0,
	AC_FLOW_TYPE_SRCIPGRPID,
	AC_FLOW_TYPE_DSTZONEID,
	AC_FLOW_TYPE_DSTIPGRPID,
	/*new type add here*/
	AC_FLOW_TYPE_MAX,
};


/*ip group*/
struct ipgrp {
	u_int16_t id;
};

/*zone*/
struct zone {
	u_int16_t id;
};


/*infomation of traffic flow match, its elems contains four part:
partA:source zone id
partB:source ipgroup id
partC:dest zone id
partD:dest ipgroup id
*/
struct ac_flow_match {
	u_int16_t	number[AC_FLOW_TYPE_MAX];	/*number of every type elements*/
	u_int16_t	match_size;	/*total size of this match*/
	unsigned char elems[0] __attribute__((aligned(8))); 	/*(maybe) contains several elements(zoneid,ipgrpid)*/
};

/*information of time group match*/
// struct ac_tm_match {	
	// u_int16_t number;		/*number of elements*/
	// u_int16_t match_size;	/*total size of this match*/
	// unsigned char elems[0];	/*(maybe) contains several elements*/
// };

/*information of proto match*/
struct ac_proto_match {
	u_int16_t	number;			/*number of elements*/
	u_int16_t	match_size;		/*total size of this match*/
	u_int16_t	protoid_sort;	/*sorted type:asc or desc*/
	unsigned char elems[0] __attribute__((aligned(8)));		/*(maybe) contains several elements(protoid)*/
};

/*Action of access control.
we can combine them in code, eg, AC_REJECT|AC_AUDIT;
But AC_REJECT | AC_ACCEPT is invalid;
Please don't change the postion of these types*/
enum ac_action_type {
	AC_ACTION_ACCEPT = 0,
	AC_ACTION_AUDIT,
	AC_ACTION_REJECT ,
	/*new type add here*/
	AC_ACTION_MAX
};

#define AC_ACCEPT		(1 << AC_ACTION_ACCEPT) /*permitted*/
#define AC_AUDIT		(1 << AC_ACTION_AUDIT)	/*log a record*/
#define AC_REJECT		(1 << AC_ACTION_REJECT)	/*forbidden*/

/*information of target*/
struct ac_target {
	unsigned int size;	/*total size of target*/
	unsigned int flags; /*tell code what do to when matched:AC_REJECT, AC_ACCEPT, AC_AUDIT*/
};

/*A entire rule entry.It contains three parts.
PartA:flow_match;
PartB:proto_match 
PartC:target perform if rules match
notice:when multiple entries contained in ac_table_info, the next_offset will change accordingly
*/
struct ac_entry
{
	u_int16_t entry_id;
	u_int16_t proto_match_offset;	/* Size of ac_entry  + flow_match */
	u_int16_t target_offset;		/* Size of ac_entry  + flow_match + proto_match */
	u_int16_t next_offset;			/* Size of ac_entry + (flow & proto)matches + target*/
	unsigned char elems[0] __attribute__((aligned(8)));			/* The matches (if any), then the target. */
};


/* The table itself.
In user space, this is just one table in ac_table_info;
However, in kernel space, We should care about Per-cpu, maybe there several repeated instances
*/
struct ac_table_info
{
	unsigned int size;		/*total size of entries*/
	unsigned int number;	/* Number of entries of per table*/
	char entries[0];		/* ipt_entry tables*/
};


/*
white/black ip/mac set name, which should be create with ipset
*/
struct ac_set_info 
{
	unsigned int size;		/*total size of entries*/
	unsigned int updated;	/*bitmap:every bit represets a set;if bit set, set name need been updated*/
	char entries[0];
};


/*
get info of entries, then, we can use this to fetch details of entries
*/
struct ac_get_entries_info {
	unsigned int number;	/*number of entries*/
	unsigned int size;		/*total size of all entries*/
};


struct ac_get_sets_info {
	unsigned int updated; 	/*bitmap*/
	unsigned int size;		/*total size of all sets*/
};

// struct ac_get_entries {
// 	unsigned int number;	/*number of entries*/
// 	unsigned int size;		/*total size of all entries*/
// 	char entries[0];		/* entries*/
// };

// struct ac_get_sets {
// 	unsigned int size;		/*total size of all entries*/
// 	unsigned int updated;	/*bitmap*/
// 	char entries[0];		/*set_name entries*/
// };

#endif