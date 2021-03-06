/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*
 * This defines a mappings database (mdb) that relies on patricia tries and hash tables
 * to store IP and LCAF based EIDs. Among the supported LCAFs are multicast of type (S,G) and IID.
 * It is used to implement both the mappings cache and the local mapping db.
 */

#ifndef LISPD_MDB_H_
#define LISPD_MDB_H_

#include "../elibs/patricia/patricia.h"
#include "../liblisp/lisp_address.h"

#define NOT_EXACT 0
#define EXACT 1

/*
 *  Patricia tree based databases
 *  for IP/IP-prefix and multicast addresses
 */
typedef struct {
    patricia_tree_t *AF4_ip_db;
    patricia_tree_t *AF6_ip_db;
    patricia_tree_t *AF4_mc_db;
    patricia_tree_t *AF6_mc_db;
    int n_entries;
} mdb_t;

typedef void (*mdb_del_fct)(void *);

mdb_t *mdb_new();
void mdb_del(mdb_t *db, mdb_del_fct del_fct);
int mdb_add_entry(mdb_t *db, lisp_addr_t *addr, void *data);
void *mdb_remove_entry(mdb_t *db, lisp_addr_t *laddr);
void *mdb_lookup_entry(mdb_t *db, lisp_addr_t *laddr);
void *mdb_lookup_entry_exact(mdb_t *db, lisp_addr_t *laddr);
inline int mdb_n_entries(mdb_t *);

patricia_tree_t *_get_local_db_for_lcaf_addr(mdb_t *db, lcaf_addr_t *lcaf);
patricia_tree_t *_get_local_db_for_addr(mdb_t *db, lisp_addr_t *addr);


#define mdb_foreach_entry(_mdb, _it) \
    do { \
        patricia_tree_t *_ptstack[4] = {(_mdb)->AF4_ip_db, (_mdb)->AF6_ip_db, (_mdb)->AF4_mc_db, (_mdb)->AF6_mc_db}; \
        patricia_node_t *_node, *_nodein;                                       \
        int _i;                                                                 \
        for (_i=0; _i < 4; _i++) {                                              \
            PATRICIA_WALK(_ptstack[_i]->head, _node) {                          \
                PATRICIA_WALK(((patricia_tree_t *)(_node->data))->head, _nodein) {      \
                    if ((_it = _nodein->data))

#define mdb_foreach_entry_end \
                } PATRICIA_WALK_END;    \
            } PATRICIA_WALK_END;        \
        }                               \
    } while (0)


#define mdb_foreach_ip_entry(_mdb, _it)     \
    do {                                    \
        patricia_tree_t *_ptstack[2] = {(_mdb)->AF4_ip_db->head->data, (_mdb)->AF6_ip_db->head->data}; \
        patricia_node_t *_node;                         \
        int _i;                                         \
        for (_i=0; _i < 2; _i++) {                      \
            PATRICIA_WALK(_ptstack[_i]->head, _node) {  \
                if ((_it = _node->data))

#define mdb_foreach_ip_entry_end            \
            } PATRICIA_WALK_END;            \
        }                                   \
    } while (0)

#define mdb_foreach_mc_entry(_mdb, _it) \
    do { \
        patricia_tree_t *_ptstack[2] = {(_mdb)->AF4_mc_db, (_mdb)->AF6_mc_db};  \
        patricia_node_t *_node, *_nodemc;                                       \
        int _i;                                                                 \
        for (_i=0; _i < 2; _i++) {                                              \
            PATRICIA_WALK(_ptstack[_i]->head, _node) {                          \
                PATRICIA_WALK(((patricia_tree_t *)(_node->data))->head, _nodemc) {      \
                    if ((_it = _nodemc->data))

#define mdb_foreach_mc_entry_end \
                } PATRICIA_WALK_END;    \
            } PATRICIA_WALK_END;        \
        }                               \
    } while (0)


#define mdb_foreach_entry_in_ip_eid_db(_mdb, _eid, _it) \
    do { \
        patricia_tree_t *_eid_db = _get_local_db_for_addr(_mdb, (_eid)); \
        patricia_node_t *_node = NULL;  \
        PATRICIA_WALK(_eid_db->head, _node){ \
            if (((_it) = _node->data))
#define mdb_foreach_entry_in_ip_eid_db_end \
        }PATRICIA_WALK_END; \
    } while(0)




#endif /* LISPD_MDB_H_ */
