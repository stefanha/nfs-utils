/*
 * Copyright (C) 1995, 1997-1999 Jeffrey A. Uphoff
 * Modified by Olaf Kirch, 1996.
 * Modified by H.J. Lu, 1998.
 *
 * NSM for Linux.
 */

/*
 * Simple list management for notify list
 */

#include "config.h"

#include <string.h>
#include "misc.h"
#include "statd.h"
#include "notlist.h"

notify_list *
nlist_new(char *my_name, char *mon_name, int state)
{
	notify_list	*new;

	if (!(new = (notify_list *) xmalloc(sizeof(notify_list))))
		return NULL;
	memset(new, 0, sizeof(*new));

	NL_TIMES(new) = MAX_TRIES;
	NL_STATE(new) = state;
	if (!(NL_MY_NAME(new) = xstrdup(my_name))
	 || !(NL_MON_NAME(new) = xstrdup(mon_name)))
		return NULL;

	return new;
}

void
nlist_insert(notify_list **head, notify_list *entry)
{
	notify_list	*next = *head, *tail = entry;

	/* Find end of list to be inserted */
	while (tail->next)
		tail = tail->next;

	if (next)
		next->prev = tail;
	tail->next = next;
	*head = entry;
}

void
nlist_insert_timer(notify_list **head, notify_list *entry)
{
	/* Find first entry with higher timeout value */
	while (*head && NL_WHEN(*head) <= NL_WHEN(entry))
		head = &(*head)->next;
	nlist_insert(head, entry);
}

void
nlist_remove(notify_list **head, notify_list *entry)
{
	notify_list	*prev = entry->prev,
			*next = entry->next;

	if (next)
		next->prev = prev;
	if (prev)
		prev->next = next;
	else
		*head = next;
	entry->next = entry->prev = NULL;
}

notify_list *
nlist_clone(notify_list *entry)
{
	notify_list	*new;

	new = nlist_new(NL_MY_NAME(entry), NL_MON_NAME(entry), NL_STATE(entry));
	NL_MY_PROG(new) = NL_MY_PROG(entry);
	NL_MY_VERS(new) = NL_MY_VERS(entry);
	NL_MY_PROC(new) = NL_MY_PROC(entry);
	NL_ADDR(new)    = NL_ADDR(entry);
	memcpy(NL_PRIV(new), NL_PRIV(entry), SM_PRIV_SIZE);

	return new;
}

void
nlist_free(notify_list **head, notify_list *entry)
{
	if (head)
		nlist_remove(head, entry);
	if (NL_MY_NAME(entry))
		free(NL_MY_NAME(entry));
	if (NL_MON_NAME(entry))
		free(NL_MON_NAME(entry));
	free(entry);
}

void
nlist_kill(notify_list **head)
{
	while (*head)
		nlist_free(head, *head);
}

/*
 * Walk a list looking for a matching name in the NL_MON_NAME field.
 */
notify_list *
nlist_gethost(notify_list *list, char *host, int myname)
{
	notify_list	*lp;

	for (lp = list; lp; lp = lp->next) {
		if (matchhostname(host, myname? NL_MY_NAME(lp) : NL_MON_NAME(lp)))
			return lp;
	}

	return (notify_list *) NULL;
}
