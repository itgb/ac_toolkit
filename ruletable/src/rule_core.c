#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "rule_print.h"
#include "rule_table.h"
#include "rule_parse.h"
#include "audit_control.h"
#include "rule_entry.h"
#include "json_utility.h"

struct ac_global_config {
	struct ac_config *control;
	struct ac_config *audit;
};

static struct ac_global_config s_config;


static int init_global_config()
{
	bzero(&s_config, sizeof(struct ac_global_config));
	s_config.control = (struct ac_config*)malloc(sizeof(struct ac_config));
	if (s_config.control == NULL) {
		goto fail;
	}	

	s_config.audit = (struct ac_config*)malloc(sizeof(struct ac_config));
	if (s_config.audit == NULL) {
		goto fail;
	}

	bzero(s_config.control, sizeof(struct ac_config));
	bzero(s_config.audit, sizeof(struct ac_config));
	return 0;
fail:
	if (s_config.control) {
		free(s_config.control);
		s_config.control = NULL;
	}
	return -1;
}


static void free_global_config()
{
	free_ac_config(s_config.control);
	s_config.control = NULL;
	free_ac_config(s_config.audit);
	s_config.audit = NULL;
}


int do_parse_config(const char *json_str, unsigned int size)
{
	int ret = -1;
	char *json_str_cpy = NULL;
	const nx_json *js = NULL, *js_elem = NULL;
	
	if (json_str == NULL || size <= 0) {
		AC_ERROR("invalid parameters.");
		return -1;
	}

	json_str_cpy = malloc(sizeof(char) * (size + 1));
	if (json_str_cpy == NULL) {
		goto out;
	}
	bzero(json_str_cpy, size + 1);
	memcpy(json_str_cpy, json_str, size);
	js = nx_json_parse_utf8(json_str_cpy);
	if (js == NULL) {
		AC_ERROR("config parse failed.\n");
		goto out;
	}

	if (nx_json_verify(js) != 0) {
		AC_ERROR("nxjson verify failed.\n");
		goto out;
	}

	init_global_config();
	
	/*parse control set*/
	js_elem = nx_json_get(js, CONTROL_SET_KEY);
	if (js_elem->type != NX_JSON_NULL) {
		if (do_parse_control_set(js_elem, &s_config.control->set) == 0) {
			display_control_set(&s_config.control->set);
		}
	}

	/*parse audit set*/
	js_elem = nx_json_get(js, AUDIT_SET_KEY);
	if (js_elem->type != NX_JSON_NULL) {
		if (do_parse_audit_set(js_elem, &s_config.audit->set) == 0) {
			display_audit_set(&s_config.audit->set);
		}
	}

	/*parse control rule*/
	js_elem = nx_json_get(js, CONTROL_RULE_KEY);
	if (js_elem->type != NX_JSON_NULL) {
		if (do_parse_control_rule(js_elem, &s_config.control->rule) == 0) {
			display_control_rule(&s_config.control->rule);
		}
		else {
			goto out;
		}
	}
	
	/*parse audit rule*/
	js_elem = nx_json_get(js, AUDIT_RULE_KEY);
	if (js_elem->type != NX_JSON_NULL) {
		if (do_parse_audit_rule(js_elem, &s_config.audit->rule) == 0) {
			display_audit_rule(&s_config.audit->rule);
		}
		else {
			goto out;
		}
	}

	ret = 0;
out:
	if (js != NULL) {
		nx_json_free(js);
	}
	if (json_str_cpy) {
		free(json_str_cpy);
	}
	if (ret != 0) {
		free_global_config();
	}
	return ret;
}


int main(int argc, char **argv)
{
	if (do_parse_config(argv[1], strlen(argv[1])) != 0) {
		return -1;
	}
	struct ac_table_info *table = generate_ac_table(&s_config.control->rule);
	free_global_config();
	return 0;
}