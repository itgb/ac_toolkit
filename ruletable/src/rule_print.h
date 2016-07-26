/**/
#ifndef _RULE_PRINT_H
#define _RULE_PRINT_H
#include <stdio.h>
#define AC_PRINT(format,...)	do { fprintf(stdout, format, ##__VA_ARGS__); } while(0)
#define AC_DEBUG(format,...)	do { fprintf(stdout, "%s "format, __func__, ##__VA_ARGS__); } while(0)
#define AC_INFO(format,...)		do { fprintf(stdout, "%s "format, __func__, ##__VA_ARGS__); } while(0)
#define AC_ERROR(format,...)	do { fprintf(stderr, "%s "format, __func__, ##__VA_ARGS__); } while(0)
#endif