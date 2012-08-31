/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Copyright [2012] [Erik Nordström <erik.nordstrom@gmail.com>]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __LIST_H__
#define __LIST_H__

/*
  Double linked list implementation.
 */
struct list_node {
    struct list_node *prev, *next;
};

#define LIST(name)                              \
    struct list_node name =                     \
    { &name, &name }

#define INIT_LIST_NODE(node)                    \
    (*(node) = (struct list_node){ node, node } )

#define list_is_empty(list) ((list)->next == (list))

#define list_first(list) (list)->next

#define list_insert(head, node) ({              \
            (node)->next = (head)->next;        \
            (node)->prev = (head);              \
            (head)->next->prev = (node);        \
            (head)->next = (node);              \
        })

#define list_insert_tail(head, node) ({   \
            (node)->next = (head);        \
            (node)->prev = (head)->prev;  \
            (head)->prev->next = (node);  \
            (head)->prev = (node);        \
        })

#define list_remove(node) ({                    \
            (node)->prev->next = (node)->next;  \
            (node)->next->prev = (node)->prev;  \
            (node)->next = (node);              \
            (node)->prev = (node);              \
        })

#define list_type(ptr, type, field) ({                              \
            const typeof( ((type *)NULL)->field ) *__ptr = (ptr);	\
            (type *)( (char *)__ptr - offsetof(type, field) );      \
        })

#define list_first_type(head, type, field)      \
    list_type((head)->next, type, field)

#define list_foreach_type(ptr, head, field)                         \
    for (ptr = list_type((head)->next, typeof(*(ptr)), field);      \
         &(ptr)->field != (head);                                   \
         ptr = list_type((ptr)->field.next, typeof(*(ptr)), field))

#endif /* __LIST_H__ */
