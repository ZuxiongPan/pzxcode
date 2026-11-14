#ifndef _DEXTENSION_H_
#define _DEXTENSION_H_

#include <stddef.h>

#define UNUSED(x) (void)(x)

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define container_of(ptr, type, member) ({ \
    const typeof(((type *)0)->member) *__mptr = (ptr); \
    (type *)((char *)__mptr - offsetof(type, member)); })

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

// this is a double-linked list node definition
struct lnode {
    struct lnode *next;
    struct lnode *prev;
};

static inline void lnode_init(struct lnode *node)
{
    node->next = node;
    node->prev = node;
}

static inline void list_add_head(struct lnode *new_node, struct lnode *head)
{
    new_node->next = head->next;
    new_node->prev = head;
    head->next->prev = new_node;
    head->next = new_node;
}

static inline void list_add_after(struct lnode *new_node, struct lnode *node)
{
    new_node->next = node->next;
    new_node->prev = node;
    node->next->prev = new_node;
    node->next = new_node;
}

static inline void list_add_tail(struct lnode *new_node, struct lnode *head)
{
    new_node->next = head;
    new_node->prev = head->prev;
    head->prev->next = new_node;
    head->prev = new_node;
}

static inline void list_del(struct lnode *node)
{
    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->next = node;
    node->prev = node;
}

#endif
