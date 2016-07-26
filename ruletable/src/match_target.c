#include <stdlib.h>
#include <strings.h>
#include "rule_parse.h"
#include "rule_table.h"
#include "rule_print.h"

static char flow_match_map[AC_FLOW_TYPE_MAX][AC_FLOW_MATCH_KEY_MAXLEN]= {
	AC_RULE_SRC_ZONEIDS_KEY, AC_RULE_SRC_IPGRPIDS_KEY,
	AC_RULE_DST_ZONEIDS_KEY, AC_RULE_DST_IPGRPIDS_KEY
};

/*target_map and target_flag_map have consistent order,
eg,ACCEPT, AUDIT, REJECT*/
static char target_map[AC_ACTION_MAX][AC_ACTION_MAXNAMELEN] = {
	AC_ACTION_ACCEPT_KEY, AC_ACTION_AUDIT_KEY, AC_ACTION_REJECT_KEY
};

static char target_flag_map[AC_ACTION_MAX] = {
	AC_ACCEPT, AC_AUDIT, AC_REJECT
};


void display_ac_flow_match(const struct ac_flow_match *flow_match) 
{
	int idx_offset = 0;
	if (flow_match == NULL) {
		AC_ERROR("invalid parameter: flow_match is NULL\n");
		return;
	}
	AC_DEBUG("---------FLOW_MATCH START---------\n");
	AC_PRINT("Total size of match:%d\n", flow_match->match_size);

	for (int i = 0; i < AC_FLOW_TYPE_MAX; ++i) {
		AC_PRINT("Number of %s is %d:[", flow_match_map[i], flow_match->number[i]);

		for (int j = 0; j < flow_match->number[i]; ++j) {
				AC_PRINT("%d, ", flow_match->elems[idx_offset + j]);
		}
		AC_PRINT("]\n");
		idx_offset += flow_match->number[i];
	}
	AC_DEBUG("---------FLOW_MATCH END---------\n\n");
}


struct ac_flow_match* generate_flow_match(
	unsigned int *src_zone_ids, unsigned int src_zone_num,
	unsigned int *src_ipgrp_ids, unsigned int src_ipgrp_num,
	unsigned int *dst_zone_ids, unsigned int dst_zone_num,
	unsigned int *dst_ipgrp_ids, unsigned int dst_ipgrp_num)
{
	struct ac_flow_match *flow_match = NULL;
	int elems_num = 0, match_size = 0, idx_offset = 0;

	if (src_zone_ids == NULL || src_zone_num == 0 ||
		src_ipgrp_ids == NULL || src_ipgrp_num == 0 ||
		dst_zone_ids == NULL || dst_zone_num == 0 ||
		dst_ipgrp_ids == NULL || dst_ipgrp_num == 0) {
		AC_ERROR("invalid parameters\n");
		return NULL;
	}

	elems_num = src_zone_num + src_ipgrp_num + dst_zone_num + dst_ipgrp_num;
	match_size = elems_num * sizeof(u_int16_t) + sizeof(struct ac_flow_match);
	flow_match = (struct ac_flow_match*)malloc(match_size);
	if (flow_match == NULL) {
		AC_ERROR("Out of memory\n");
		return NULL;
	}
	bzero(flow_match, match_size);
	flow_match->match_size = match_size;
	flow_match->number[AC_FLOW_TYPE_SRCZONEID] = src_zone_num;
	flow_match->number[AC_FLOW_TYPE_SRCIPGRPID] = src_ipgrp_num;
	flow_match->number[AC_FLOW_TYPE_DSTZONEID] = dst_zone_num;
	flow_match->number[AC_FLOW_TYPE_DSTIPGRPID] = dst_ipgrp_num;
	for (int i = 0; i < AC_FLOW_TYPE_MAX; ++i) {
		unsigned int *ids = NULL;
		switch(i) {
			case AC_FLOW_TYPE_SRCZONEID:	
				ids = src_zone_ids;
				break;

			case AC_FLOW_TYPE_SRCIPGRPID:	
				ids = src_ipgrp_ids;
				break;

			case AC_FLOW_TYPE_DSTZONEID:	
				ids = dst_zone_ids;
				break;

			case AC_FLOW_TYPE_DSTIPGRPID:	
				ids = dst_ipgrp_ids;
				break;

			default:
				ids = NULL;
				AC_INFO("unknown flow type:%d\n", i);
				break;
		}

		for (int j = 0; ids && j < flow_match->number[i]; ++j) {
			flow_match->elems[idx_offset + j] = ids[j];
		}
		idx_offset += flow_match->number[i];
	}
	return flow_match;
}


void display_ac_proto_match(const struct ac_proto_match* proto_match) 
{
	#define IDS_NUM_PER_ROW 6
	if (proto_match == NULL) {
		AC_ERROR("invalid parameter: proto_match is NULL\n");
		return;
	}
	AC_DEBUG("---------PROTO_MATCH START---------\n");
	AC_PRINT("The total size of match:%d\n", proto_match->match_size);
	AC_PRINT("Number of ids is %d:[", proto_match->number);

	for (int i = 0; i < proto_match->number; ++i) {
		AC_PRINT("%d, ", proto_match->elems[i]);
		if (i && (i % IDS_NUM_PER_ROW) == 0) {
			AC_PRINT("\n");
		}
	}

	AC_PRINT("]\n");
	AC_DEBUG("---------PROTO_MATCH END---------\n\n");
	#undef IDS_NUM_PER_ROW 
}


struct ac_proto_match* generate_proto_match(
	unsigned int *proto_ids, 
	unsigned int proto_num)
{
	struct ac_proto_match *proto_match = NULL;
	int match_size = 0;
	if (proto_ids == NULL || proto_num == 0) {
		AC_ERROR("invalid parameters\n");
		return NULL;
	}

	match_size = proto_num * sizeof(u_int16_t) + sizeof(struct ac_proto_match);
	proto_match = (struct ac_proto_match*)malloc(match_size);
	if (proto_match == NULL) {
		AC_ERROR("Out of memory\n");
		return NULL;
	}

	bzero(proto_match, match_size);
	proto_match->number = proto_num;
	proto_match->match_size = match_size;
	proto_match->protoid_sort = AC_PROTOID_SORT_ASC; /*fixme: we assume it sorted in asc*/
	for (int i = 0; i < proto_match->number; ++i) {
		proto_match->elems[i] = proto_ids[i];
	}
	return proto_match;
}


void display_ac_target(const struct ac_target *target)
{
	if (target == NULL) {
		AC_ERROR("invalid parameter: target is NULL\n");
		return;
	}
	AC_DEBUG("--------TARGET START------\n");
	AC_PRINT("The value of flags is %u:[", target->flags);

	for (int i = 0; i < AC_ACTION_MAX; ++i) {
		if (target->flags & target_flag_map[i]) {
			AC_PRINT("%s, ", target_map[i]);
		}
	}

	AC_PRINT("]\n");
	AC_DEBUG("---------TARGET END-------\n\n");
}


struct ac_target *generate_target(const char *action[], unsigned int action_num)
{
	struct ac_target *target = NULL;
	unsigned int flags = 0;
	if (action == NULL || action_num == 0) {
		AC_ERROR("invalid parameters\n");
		return NULL;
	} 
	
	target = (struct ac_target*)malloc(sizeof(struct ac_target));
	if (target == NULL) {
		AC_ERROR("Out of memory\n");
		return NULL;
	}
	bzero(target, sizeof(struct ac_target));
	for (int i = 0; i < action_num; ++i) {
		for (int j = 0; j < AC_ACTION_MAX; ++j) {
			if (strcasecmp(action[i], target_map[j]) == 0) {
				target->flags |= target_flag_map[j];
			}
		}
	}
	return target;
}