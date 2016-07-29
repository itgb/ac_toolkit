
#ifndef _RULE_IPC_H
#define _RULE_IPC_H

#define AC_SO_BASE_CTL 4096
#define AC_SO_SET_REPLACE_CONTROL		(AC_SO_BASE_CTL)
#define AC_SO_SET_REPLACE_AUDIT			(AC_SO_BASE_CTL + 1)
#define AC_SO_SET_REPLACE_CONTROL_SET	(AC_SO_BASE_CTL + 2)
#define AC_SO_SET_REPLACE_AUDIT_SET		(AC_SO_BASE_CTL + 3)
#define AC_SO_SET_MAX					AC_SO_SET_REPLACE_AUDIT_SET

#define AC_SO_GET_CONTROL_INFO			(AC_SO_BASE_CTL)
#define AC_SO_GET_CONTROL_ENTRIES		(AC_SO_BASE_CTL	+ 1)
#define AC_SO_GET_CONTROL_SET_INFO		(AC_SO_BASE_CTL + 2)
#define AC_SO_GET_CONTROL_SETS			(AC_SO_BASE_CTL + 3)

#define AC_SO_GET_AUDIT_INFO			(AC_SO_BASE_CTL + 4)
#define AC_SO_GET_AUDIT_ENTRIES			(AC_SO_BASE_CTL + 5)
#define AC_SO_GET_AUDIT_SET_INFO		(AC_SO_BASE_CTL + 6)
#define AC_SO_GET_AUDIT_SETS			(AC_SO_BASE_CTL + 7)
#define AC_SO_GET_MAX					AC_SO_GET_AUDIT_SETS

int do_rule_ipc_set(int cmd, void *data, unsigned int len);
int do_rule_ipc_get(int cmd, void *data, unsigned int len);
#endif