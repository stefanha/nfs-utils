/* 
 * Copyright (C) 1995, 1997-1999 Jeffrey A. Uphoff
 * Major rewrite by Olaf Kirch, Dec. 1996.
 *
 * NSM for Linux.
 */

#include <netinet/in.h>

/*
 * Primary information structure.
 */
struct notify_list {
  mon			mon;	/* Big honkin' NSM structure. */
  struct in_addr	addr;	/* IP address for callback. */
  unsigned short	port;	/* port number for callback */
  short int		times;	/* Counter used for various things. */
  int			state;	/* For storing notified state for callbacks. */
  struct notify_list	*next;	/* Linked list forward pointer. */
  struct notify_list	*prev;	/* Linked list backward pointer. */
  u_int32_t		xid;	/* XID of MS_NOTIFY RPC call */
  time_t		when;	/* notify: timeout for re-xmit */
  int			type;	/* type of notify (REBOOT/CALLBACK) */
};

typedef struct notify_list notify_list;

#define NOTIFY_REBOOT	0	/* notify remote of our reboot */
#define NOTIFY_CALLBACK	1	/* notify client of remote reboot */

/*
 * Global Variables
 */
extern notify_list *	rtnl;	/* Run-time notify list */
extern notify_list *	notify;	/* Pending RPC calls */

/*
 * List-handling functions
 */
extern notify_list *	nlist_new(char *, char *, int);
extern void		nlist_insert(notify_list **, notify_list *);
extern void		nlist_remove(notify_list **, notify_list *);
extern void		nlist_insert_timer(notify_list **, notify_list *);
extern notify_list *	nlist_clone(notify_list *);
extern void		nlist_free(notify_list **, notify_list *);
extern void		nlist_kill(notify_list **);
extern notify_list *	nlist_gethost(notify_list *, char *, int);

/* 
 * List-handling macros.
 * THESE INHERIT INFORMATION FROM PREVIOUSLY-DEFINED MACROS.
 * (So don't change their order unless you study them first!)
 */
#define NL_NEXT(L)	((L)->next)
#define NL_FIRST	NL_NEXT
#define NL_PREV(L)	((L)->prev)
#define NL_DATA(L)	((L)->mon)
#define NL_ADDR(L)	((L)->addr)
#define NL_STATE(L)	((L)->state)
#define NL_TIMES(L)	((L)->times)
#define NL_MON_ID(L)	(NL_DATA((L)).mon_id)
#define NL_PRIV(L)	(NL_DATA((L)).priv)
#define NL_MON_NAME(L)	(NL_MON_ID((L)).mon_name)
#define NL_MY_ID(L)	(NL_MON_ID((L)).my_id)
#define NL_MY_NAME(L)	(NL_MY_ID((L)).my_name)
#define NL_MY_PROC(L)	(NL_MY_ID((L)).my_proc)
#define NL_MY_PROG(L)	(NL_MY_ID((L)).my_prog)
#define NL_MY_VERS(L)	(NL_MY_ID((L)).my_vers)
#define NL_WHEN(L)	((L)->when)
#define NL_TYPE(L)	((L)->type)

#if 0
#define NL_ADD_NO_ZERO(LIST, ITEM)\
  NL_PREV(NL_FIRST((LIST))) = (ITEM);\
  NL_NEXT((ITEM)) = NL_FIRST((LIST));\
  NL_FIRST((LIST)) = (ITEM);\
  NL_PREV((ITEM)) = (LIST);\
  NL_TIMES((ITEM)) = 0;

#define NL_ADD(LIST, ITEM)\
  NL_ADD_NO_ZERO((LIST), (ITEM));\
  NL_ADDR((ITEM)) = 0;\
  NL_STATE((ITEM)) = 0;

#define NL_DEL(ITEM)\
  NL_NEXT(NL_PREV((ITEM))) = NL_NEXT((ITEM));\
  NL_PREV(NL_NEXT((ITEM))) = NL_PREV((ITEM));

#define NL_FREE(ITEM)\
  if (NL_MY_NAME ((ITEM)))\
    free (NL_MY_NAME ((ITEM)));\
  if (NL_MON_NAME ((ITEM)))\
    free (NL_MON_NAME((ITEM)));\
  free ((ITEM));

#define NL_DEL_FREE(ITEM)\
  NL_DEL((ITEM))\
  NL_FREE((ITEM))

/* Yuck.  Kludge. */
#define NL_COPY(SRC, DEST)\
  NL_TIMES((DEST)) = NL_TIMES((SRC));\
  NL_STATE((DEST)) = NL_TIMES((SRC));\
  NL_MY_PROC((DEST)) = NL_MY_PROC((SRC));\
  NL_MY_PROG((DEST)) = NL_MY_PROG((SRC));\
  NL_MY_VERS((DEST)) = NL_MY_VERS((SRC));\
  NL_MON_NAME((DEST)) = xstrdup (NL_MON_NAME((SRC)));\
  NL_MY_NAME((DEST)) = xstrdup (NL_MY_NAME((SRC)));\
  memcpy (&NL_ADDR((DEST)), &NL_ADDR((SRC)), sizeof (u_long));\
  memcpy (NL_PRIV((DEST)), NL_PRIV((SRC)), SM_PRIV_SIZE);
#endif
