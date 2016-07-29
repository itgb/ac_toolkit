#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include "rule_print.h"
#include "rule_table.h"
#include "rule_parse.h"
#include "match_target.h"
#include "rule_ipc.h"

static void display_ac_entry(struct ac_entry *entry)
{
	struct ac_flow_match *flow_match = NULL;
	struct ac_proto_match *proto_match = NULL;
	struct ac_target *target = NULL;

	if (entry == NULL) {
		AC_ERROR("invalid parameter:entry is NULL\n");
		return;
	}
	AC_DEBUG("**************ENTRY START**************\n");
	AC_PRINT("entry id:%u\n", entry->entry_id);
	AC_PRINT("proto match offset:%u\n", entry->proto_match_offset);
	AC_PRINT("target offset:%u\n", entry->target_offset);
	AC_PRINT("netxt offset:%u\n", entry->next_offset);
	flow_match = (struct ac_flow_match*)((void*)entry + sizeof(struct ac_entry));
	proto_match = (struct ac_proto_match*)((void*)entry + entry->proto_match_offset);
	target = (struct ac_target*)((void*)entry + entry->target_offset);
	display_ac_flow_match(flow_match);
	display_ac_proto_match(proto_match);
	display_ac_target(target);
	AC_DEBUG("**************ENTRY END**************\n\n");
}


static struct ac_entry *generate_ac_entry(struct ac_rule_item *rule_item)
{
	struct ac_entry *entry = NULL;
	struct ac_flow_match *flow_match = NULL;
	struct ac_proto_match *proto_match = NULL;
	struct ac_target *target = NULL;
	int entry_size = 0;

	if (rule_item == NULL) {
		AC_ERROR("invalid parameter:rule_item is NULL\n");
		return NULL;
	}

	flow_match = generate_flow_match(rule_item->src_zone_ids, rule_item->src_zone_num,
									rule_item->src_ipgrp_ids, rule_item->src_ipgrp_num,
									rule_item->dst_zone_ids, rule_item->dst_zone_num,
									rule_item->dst_ipgrp_ids, rule_item->dst_ipgrp_num);
	if (flow_match == NULL) {
		
		goto out;
	}

	proto_match = generate_proto_match(rule_item->proto_ids, rule_item->proto_num);
	if (proto_match == NULL) {
		goto out;
	}

	target = generate_target(rule_item->action, rule_item->action_num);
	if (target == NULL) {
		goto out;
	}

	entry_size += AC_ALIGN(sizeof(struct ac_entry));
	entry_size += flow_match->match_size;
	entry_size += proto_match->match_size;
	entry_size += AC_ALIGN(sizeof(struct ac_target));
	entry = (struct ac_entry*)malloc(entry_size);

	if (entry == NULL) {
		goto out;
	}
	/*fixme:we are not align*/
	bzero(entry, entry_size);
	entry->entry_id = rule_item->id;
	entry->proto_match_offset = AC_ALIGN(sizeof(struct ac_entry)) + flow_match->match_size;
	entry->target_offset = entry->proto_match_offset + proto_match->match_size;
	entry->next_offset = entry->target_offset + AC_ALIGN(sizeof(struct ac_target));
	memcpy((void*)entry + AC_ALIGN(sizeof(struct ac_entry)), flow_match, flow_match->match_size);
	memcpy((void*)entry + entry->proto_match_offset, proto_match, proto_match->match_size);
	memcpy((void*)entry + entry->target_offset, target, AC_ALIGN(sizeof(struct ac_target)));

out:
	
	if (flow_match) {
		free(flow_match);
	}

	if (proto_match) {
		free(proto_match);
	}

	if (target) {
		free(target);
	}
	return entry;
}


void display_ac_table(const struct ac_table_info *table)
{
	void *table_base = NULL;
	unsigned int offset = 0;
	struct ac_entry *entry = NULL;
	
	if (table == NULL) {
		AC_ERROR("invalid parameter: table is NULL\n");
		return;
	}

	table_base = (void*) table->entries;
	for (unsigned int i = 0; i < table->size; i += entry->next_offset) {
		entry = (struct ac_entry*)((void*)table_base + i);
		display_ac_entry(entry);
	}
}


struct ac_table_info *generate_empty_ac_table()
{
	struct ac_table_info *table = NULL;
	table = (struct ac_table_info*)malloc(sizeof(struct ac_table_info));
	if (table) {
		bzero(table, sizeof(struct ac_table_info));
		return table;
	}	
	AC_ERROR("out of memory\n");
	return NULL;
}


struct ac_table_info *glue_entries_to_table(struct ac_entry **entries, unsigned int number)
{
	struct ac_table_info *table = NULL;
	void *table_base = NULL;
	int entry_size = 0, entry_num = 0, next_offset = 0, cpy_offset = 0;

	if (entries == NULL || number == 0) {
		AC_ERROR("invalid pramater\n");
		return NULL;
	}
	for (int i = 0; i < number; ++i) {
		if (entries[i]) {
			entry_size += entries[i]->next_offset;
			entry_num++;
		}
	}

	if (entry_num != number) {
		AC_ERROR("invalid pramater: entries contains NULL");
		return NULL;
	}

	table = (struct ac_table_info*)malloc(sizeof(struct ac_table_info) + entry_size);
	if (table == NULL) {
		AC_ERROR("out of memory\n");
		goto out;
	}

	bzero(table, (sizeof(struct ac_table_info) +  entry_size));
	table->size = entry_size;
	table->number = entry_num;
	table_base = table->entries;
	for (int i = 0; i < table->number; ++i) {
		entry_size = entries[i]->next_offset;
		cpy_offset = next_offset;
		next_offset += entry_size;
		entries[i]->next_offset = next_offset;
		memcpy((void*)table_base + cpy_offset , entries[i], entry_size);
	}
out:
	return table;
}


struct ac_table_info *generate_ac_table(struct ac_rule *rules)
{
	struct ac_entry **entries = NULL;
	struct ac_table_info *table = NULL;
	int entries_size = 0;
	if (rules == NULL) {
		AC_ERROR("invalid pramater:config is NULL\n");
		return NULL;
	}

	if (rules->updated == 0) {
		AC_INFO("no need update rule\n");
		return NULL;
	}

	if (rules->number == 0) {
		return generate_empty_ac_table();
	}

	entries = (struct ac_entry**)malloc(sizeof(struct ac_entry*) * rules->number);
	if (entries == NULL) {
		goto out;
	}

	for (int i = 0; i < rules->number; ++i) {
		entries[i] = generate_ac_entry(&rules->items[i]);
		if (entries[i] == NULL) {
			goto out;
		}
	}

	table = glue_entries_to_table(entries, rules->number);
	if (table == NULL) {
		AC_ERROR("gule entries to table failed\n");
	}

out:
	if (entries == NULL) {
		return table;
	}

	for (int j = 0; j < rules->number; ++j) {
		if (entries[j] == NULL) {
			break;
		}
		free(entries[j]);
	}
	free(entries);

	return table;

}


void display_ac_set(struct ac_set_info *set_info) 
{
	#define BITS_OF_INT  32
	int number = 0, offset = 0;
	void *entry_base = NULL;

	if (set_info == NULL) {
		AC_ERROR("invalid parameter: set_info is NULL\n");
		return;
	}

	entry_base = set_info->entries;
	AC_DEBUG("***************AC_SET START*******************\n");
	AC_PRINT("the total size of entries:%u\n", set_info->size);
	AC_PRINT("the updated flag :%u\n", set_info->updated);
	for (int i = 0; i < BITS_OF_INT; ++i) {
		if (set_info->updated & (1 << i)) {
			AC_PRINT("set name:%s\n", (char*)(entry_base + offset));
			offset += AC_IPSET_MAXNAMELEN;
		}
	}
	AC_DEBUG("***************AC_SET END*******************\n\n");
	#undef BITS_OF_INT  
}


struct ac_set_info *generate_ac_set(struct ac_set *set) 
{

	int number = 0, offset = 1, entry_size = 0, entry_offset = 0;
	void *entry_base = NULL;
	struct ac_set_info *set_info = NULL;
	int  *idx_arr = NULL;

	if (set == NULL) {
		AC_ERROR("invalid parameter: set is NULL\n");
		return NULL;
	}

	idx_arr = (int*)malloc(sizeof(int) * set->number);
	if (idx_arr == NULL) {
		AC_ERROR("Out of memory\n");
		goto out;
	}
	bzero(idx_arr, sizeof(int) * set->number);

	for (int i = 0; i < set->number; ++i) {
		if (set->updated & (1 << i)) {
			number++;
		}
	}
	
	entry_size = number * AC_IPSET_MAXNAMELEN;
	set_info = (struct ac_set_info*)malloc(entry_size + sizeof(struct ac_set_info));
	if (set_info == NULL) {
		AC_ERROR("Out of memory\n");
		goto out;
	}
	
	bzero(set_info, entry_size + sizeof(struct ac_set_info));
	set_info->size = entry_size;
	set_info->updated = set->updated;
	entry_base = set_info->entries;
	for (int i = 0; i < set->number; ++i) {
		if (set->updated & (1 << i)) {
			memcpy((void*)entry_base + entry_offset, set->ipsets[i], AC_IPSET_MAXNAMELEN);
			entry_offset += AC_IPSET_MAXNAMELEN;
		} 
	}
	display_ac_set(set_info);
out:
	return set_info;
}


struct ac_table_info *fetch_ac_table(unsigned int info_cmd, unsigned int detail_cmd)
{
	int total_size = 0;
	struct ac_get_entries_info entries_info;
	struct ac_table_info *table = NULL;

	total_size = sizeof(struct ac_get_entries_info);
	bzero(&entries_info, total_size);
	if (do_rule_ipc_get(info_cmd, &entries_info, total_size) != 0) {
		AC_ERROR("get entries_info failed\n");
		goto failed;
	} 

	total_size = sizeof(struct ac_table_info) + entries_info.size;
	table = (struct ac_table_info*)malloc(total_size);
	if (table == NULL) {
		AC_ERROR("Out of memory\n");
		goto failed;
	}
	bzero(table, total_size);
	table->number = entries_info.number;
	table->size = entries_info.size;

	if (do_rule_ipc_get(detail_cmd, &table, total_size) != 0) {
		AC_ERROR("get entries failed\n");
		goto failed;
	}

	return table;
failed:
	if (table) {
		free(table);
	}
	return NULL;
}


struct ac_set_info *fetch_ac_set(unsigned int info_cmd, unsigned int detail_cmd)
{
	int total_size = 0;
	struct ac_get_sets_info sets_info;
	struct ac_set_info *sets = NULL;

	total_size = sizeof(struct ac_get_sets_info);
	bzero(&sets_info, total_size);
	if (do_rule_ipc_get(info_cmd, &sets_info, total_size) != 0) {
		AC_ERROR("get sets_info failed\n");
		goto failed;
	} 

	total_size = sizeof(struct ac_set_info) + sets_info.size;
	sets = (struct ac_set_info*)malloc(total_size);
	if (sets == NULL) {
		AC_ERROR("Out of memory\n");
		goto failed;
	}
	bzero(sets, total_size);
	sets->updated = sets_info.updated;
	sets->size = sets_info.size;

	if (do_rule_ipc_get(detail_cmd, &sets, total_size) != 0) {
		AC_ERROR("get sets failed\n");
		goto failed;
	}

	return sets;
failed:
	if (sets) {
		free(sets);
	}
	return NULL;
}