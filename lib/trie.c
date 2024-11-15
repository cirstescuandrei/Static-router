#include "trie.h"

#include <arpa/inet.h>

struct trie_node* create_trie_node() {
    struct trie_node *node = malloc(sizeof(struct trie_node));

    node->child[0] = NULL;
    node->child[1] = NULL;
    node->route = NULL;

    return node;
}

void insert_trie_entry(struct trie_node *root, struct route_table_entry *route) {
    uint32_t prefix = ntohl(route->prefix & route->mask);
    uint32_t network_mask = ntohl(route->mask);

    uint8_t position = 31;
    uint32_t bitmask = 1 << position;
    
    /* Go down the trie to child[current bit in prefix]
     * Stop when the network mask is 0
     */ 
    while (bitmask & network_mask) {
        uint8_t current_bit = (bitmask & prefix) >> position;

        /* If entry doesn't exist yet, create it */
        if (root->child[current_bit] == NULL) {
            root->child[current_bit] = create_trie_node(route);
        }

        root = root->child[current_bit];
        bitmask >>= 1;
        position--;
    }

    /* The node at the end of the ones and zeros chain
     * of the prefix contains the route table entry
     * The depth at which the route is located is equal
     * to the number of ones in the network mask
     */
    root->route = route;
}

struct trie_node* create_trie_from_rtable(struct route_table_entry *rtable, int rtable_len) {
    struct trie_node *root = create_trie_node();

    for (int i = 0; i < rtable_len; i++) {
        insert_trie_entry(root, &rtable[i]);
    }

    return root;
}
