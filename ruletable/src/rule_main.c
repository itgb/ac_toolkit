/*
	Administration tool of Acess control in userspace.
	It contains three functions:
	1.Parse config string which is json 
	2.Commit config to kernel
	3.Fetch config from kernel for checking whether config is right in kernel
*/
#include <unistd.h>
#include "rule_table.h"
#include "rule_print.h"

static const char *version = "v1.0";		/*tool version*/
static const char *opt_string = "s:gt:h?";	/*support -s -g -t -h -? */

/*parse config, and then, commit to kernel*/
int commit_config(const char *config_str)
{
	AC_DEBUG("commit_config\n");
	return 0;
}


/*fetch config from kernel, and then, print config*/
int fetch_config()
{
	AC_DEBUG("fetch_config\n");
	return 0;
}


/*parse config, and then, print config*/
int parse_config(const char *config_str)
{
	AC_DEBUG("parse_config\n");
	return 0;
}

/**/
void display_version()
{
	AC_PRINT("ruletable: %s\n", version);
}

/**/
void display_usage()
{
	AC_PRINT("Usage: /usr/sbin/ruletable <option> <parameter>\n");
	AC_PRINT("Option:\n");
	AC_PRINT("		-s config_string Parse and commit config to kernel\n");
	AC_PRINT("		-g 				 Fetch config from kernel\n");
	AC_PRINT("		-t config_string Parse config, but don't commit to kernel\n");
	AC_PRINT("		-v 				 Print version\n");
	AC_PRINT("		-h 				 Display this help\n");
}


// int main(int argc, char **argv)
// {
// 	int opt = 0, res = 0;

// 	opt = getopt(argc, argv, opt_string);
// 	while(opt != -1) {
// 		switch(opt) {
// 			case 's':
// 				res = commit_config(optarg);
// 				break;
				
// 			case 'g':
// 				res = fetch_config();
// 				break;
				
// 			case 't':
// 				res = parse_config(optarg);
// 				break;
			
// 			case 'v':
// 				res = display_version();
// 				break;

// 			case 'h':	
// 				display_usage();
// 				break;
				
// 			default:
// 				break;
// 		}
// 		opt = getopt(argc, argv, opt_string);
// 	}
// 	return 0;
// }