/*
 * Copyright (c) 2009-2014, Salvatore Sanfilippo <antirez at gmail dot com>
 * Copyright (c) 2009-2014, Pieter Noordhuis <pcnoordhuis at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * revised by wb, xiaoyem
 */

#include <stdlib.h>
#include <string.h>
#include "macros.h"
#include "mem.h"
#include "sklist.h"

/* FIXME */
#define SKLIST_MAX_LEVEL 32
#define SKLIST_P         0.25

/* FIXME */
struct sklist_t {
	unsigned long	length;
	sklist_node_t	head, tail;
	int		level;
	int		(*cmp)(const void *x, const void *y);
	void		(*kfree)(const void *key);
	void		(*vfree)(void *value);
};
struct sklist_node_t {
	const void	*key;
	void		*value;
	sklist_node_t	prev;
	struct sklist_level {
		sklist_node_t	next;
		unsigned	span;
	}		level[0];
};

static sklist_node_t sklist_node_new(int level, const void *key, void *value) {
	sklist_node_t node;

	if ((node = CALLOC(1, sizeof *node + level * sizeof (struct sklist_level))) == NULL)
		return NULL;
	node->key   = key;
	node->value = value;
	return node;
}

static int cmpdefault(const void *x, const void *y) {
	return strcmp((char *)x, (char *)y);
}

static int sklist_random_level(void) {
	int level = 1;

	while ((random() & 0xFFFF) < SKLIST_P * 0xFFFF)
		level += 1;
	return level < SKLIST_MAX_LEVEL ? level : SKLIST_MAX_LEVEL;
}

sklist_t sklist_new(int cmp(const void *x, const void *y),
	void kfree(const void *key), void vfree(void *value)) {
	sklist_t sklist;
	int i;

	if (unlikely(NEW(sklist) == NULL))
		return NULL;
	sklist->length = 0;
	if ((sklist->head = sklist_node_new(SKLIST_MAX_LEVEL, NULL, NULL)) == NULL) {
		FREE(sklist);
		return NULL;
	}
	sklist->head->prev = NULL;
	for (i = 0; i < SKLIST_MAX_LEVEL; ++i) {
		sklist->head->level[i].next = NULL;
		sklist->head->level[i].span = 0;
	}
	sklist->tail   = NULL;
	sklist->level  = 1;
	sklist->cmp    = cmp ? cmp : cmpdefault;
	sklist->kfree  = kfree;
	sklist->vfree  = vfree;
	return sklist;
}

void sklist_free(sklist_t *sp) {
	sklist_node_t node, next;

	if (unlikely(sp == NULL || *sp == NULL))
		return;
	node = (*sp)->head->level[0].next;
	FREE((*sp)->head);
	while (node) {
		next = node->level[0].next;
		if ((*sp)->kfree)
			(*sp)->kfree(node->key);
		if ((*sp)->vfree)
			(*sp)->vfree(node->value);
		FREE(node);
		node = next;
	}
	FREE(*sp);
}

unsigned long sklist_length(sklist_t sklist) {
	if (unlikely(sklist == NULL))
		return 0;
	return sklist->length;
}

const void *sklist_node_key(sklist_node_t node) {
	if (unlikely(node == NULL))
		return NULL;
	return node->key;
}

void *sklist_node_value(sklist_node_t node) {
	if (unlikely(node == NULL))
		return NULL;
	return node->value;
}

void *sklist_insert(sklist_t sklist, const void *key, void *value) {
	sklist_node_t node, update[SKLIST_MAX_LEVEL];
	int i, level;
	unsigned int rank[SKLIST_MAX_LEVEL];

	if (unlikely(sklist == NULL || key == NULL))
		return NULL;
	node = sklist->head;
	for (i = sklist->level - 1; i >= 0; --i) {
		rank[i] = i == sklist->level - 1 ? 0 : rank[i + 1];
		while (node->level[i].next && sklist->cmp(node->level[i].next->key, key) < 0) {
			rank[i] += node->level[i].span;
			node = node->level[i].next;
		}
		update[i] = node;
	}
	node = node->level[0].next;
	if (node && sklist->cmp(node->key, key) == 0) {
		void *prev = node->value;

		node->value = value;
		return prev;
	}
	level = sklist_random_level();
	if ((node = sklist_node_new(level, key, value)) == NULL)
		return NULL;
	if (level > sklist->level) {
		for (i = sklist->level; i < level; ++i) {
			rank[i] = 0;
			update[i] = sklist->head;
			update[i]->level[i].span = sklist->length;
		}
		sklist->level = level;
	}
	node->prev = update[0] == sklist->head ? NULL : update[0];
	for (i = 0; i < level; ++i) {
		node->level[i].next = update[i]->level[i].next;
		update[i]->level[i].next = node;
		node->level[i].span = update[i]->level[i].span - (rank[0] - rank[i]);
		update[i]->level[i].span = rank[0] - rank[i] + 1;
	}
	for (i = level; i < sklist->level; ++i)
		++update[i]->level[i].span;
	if (node->level[0].next)
		node->level[0].next->prev = node;
	else
		sklist->tail = node;
	++sklist->length;
	return NULL;
}

sklist_node_t sklist_find(sklist_t sklist, const void *key) {
	sklist_node_t node;
	int i;

	if (unlikely(sklist == NULL || key == NULL))
		return NULL;
	node = sklist->head;
	for (i = sklist->level - 1; i >= 0; --i)
		while (node->level[i].next && sklist->cmp(node->level[i].next->key, key) < 0)
			node = node->level[i].next;
	node = node->level[0].next;
	if (node && sklist->cmp(node->key, key) == 0)
		return node;
	return NULL;
}

void *sklist_remove(sklist_t sklist, const void *key) {
	sklist_node_t node, update[SKLIST_MAX_LEVEL];
	int i;

	if (unlikely(sklist == NULL || key == NULL))
		return NULL;
	node = sklist->head;
	for (i = sklist->level - 1; i >= 0; --i) {
		while (node->level[i].next && sklist->cmp(node->level[i].next->key, key) < 0)
			node = node->level[i].next;
		update[i] = node;
	}
	node = node->level[0].next;
	if (node && sklist->cmp(node->key, key) == 0) {
		void *value = node->value;

		for (i = 0; i < sklist->level; ++i)
			if (update[i]->level[i].next == node) {
				update[i]->level[i].next = node->level[i].next;
				update[i]->level[i].span += node->level[i].span - 1;
			} else
				update[i]->level[i].span -= 1;
		if (node->level[0].next)
			node->level[0].next->prev = node->prev;
		else
			sklist->tail = node->prev;
		while (sklist->level > 1 && sklist->head->level[sklist->level - 1].next == NULL)
			--sklist->level;
		if (sklist->kfree)
			sklist->kfree(node->key);
		FREE(node);
		--sklist->length;
		return value;
	}
	return NULL;
}

