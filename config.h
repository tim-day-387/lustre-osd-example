// SPDX-License-Identifier: GPL-2.0

/*
 * This is a temporary hack! Configuration could
 * be done a lot better. For now, define a few things
 * here.
 *
 * Author: Timothy Day <tday141@gmail.com>
 */

#include <linux/list.h>

#define HAVE_SERVER_SUPPORT 1

/**
 * list_is_head - tests whether @list is the list @head
 * @list: the entry to test
 * @head: the head of the list
 */
static inline int list_is_head(const struct list_head *list, const struct list_head *head)
{
	return list == head;
}
