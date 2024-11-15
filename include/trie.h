#ifndef _TRIE_H_
#define _TRIE_H_

#include "lib.h"

struct trie_node {
    struct trie_node *child[2];
    struct route_table_entry *route;
};

/* Create an empty node */
struct trie_node* create_trie_node();

/* Insert entries in trie based on route prefix and mask*/
void insert_trie_entry(struct trie_node *root, struct route_table_entry *route);

/* Populate and allocated a trie based on a routing table */
struct trie_node* create_trie_from_rtable(struct route_table_entry *rtable, int rtable_len);

#endif