#ifndef _RULE_ENTRY_H
#define _RULE_ENTRY_H
struct ac_table_info *generate_ac_table(struct ac_rule *rules);
struct ac_set_info *generate_ac_set(struct ac_set *set);
struct ac_table_info *fetch_ac_table(unsigned int info_cmd, unsigned int detail_cmd);
struct ac_set_info *fetch_ac_set(unsigned int info_cmd, unsigned int detail_cmd);
void display_ac_set(struct ac_set_info *set_info);
void display_ac_table(const struct ac_table_info *table);
#endif