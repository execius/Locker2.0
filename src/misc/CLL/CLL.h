#ifndef LList_t_H
#define LList_t_H
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include "errorhandling.h"

typedef struct node_s node_t ;
typedef node_t* NodePtr_t;
typedef struct LList_s LList_t;

/*the ownership model is that node_ts arer allocated with Initnode_t and destroyed with only y:
 *  Destroynode_t
 *  DestroyList  
 *  ClearList*/
int InitNode(NodePtr_t *node_t,
             void *(*constructor)(void *data),
             void (*destructor)(void *data),
             void *data,
             NodePtr_t next);

/*this expects a node_t that was initialized 
 * with Initnode_t
 * it will optionally free memory and destroy data using a destructor function 
 * if it's not null*/
int DestroyNode(NodePtr_t node_t);

/*this will replace the head with the node_t right after , it will put the head in the 
 * node_t parameter to preserve it for freeing using Destroynode_t
 * if the next node_t is NULL head will be set to NULL*/
int DetachHead( LList_t *list,NodePtr_t *node_t);

/*this duplicates a node_t to another , the other should be passes to Destroynode_t
 * to be freed*/
int DupNode(NodePtr_t *node_tdst,
            NodePtr_t node_tsrc);

/*deletes a single node_t if the data matches the data in the node_t
 * it will put the node_t in the node_t parameter for finalizing*/
int DetachNode(LList_t *list,NodePtr_t *node_t,void *key);

int AddNode(LList_t *list,NodePtr_t node_t);

/*allcates the list and sets the compare , any list made with this should
 * be passes to DestroyList*/
int InitList(LList_t **list,
             int (*compare)(void *, void *));


/*clears the list , it destroys all the node_ts but keeps the list intact*/
int ClearList(LList_t *list);
/*frees all the node_ts and the list itself , no need todo any 
 * other finalizing operation if a list after this*/
int DestroyList(LList_t **list);


/*iterates on all the node_ts in the list with the func functions*/
int ForEach(LList_t *list, void (*func)(void *data));


/*finds a node_t whose data matchces key , using the user-set compare functioni
 * in the list structure*/
int FindNode(LList_t *list, void *key, NodePtr_t *result);

/*will return  0 on NULL list;*/
size_t GetSize(LList_t *list);

/*initialize both before passing them to this , assuming you did the right thing
 * and set the constructor to deep-copy , this will construct a list with duplicate
 * but separate  node_ts that should be freed independently (DestroyList)*/
int CopyList(LList_t *src, LList_t *dst);

int InsertHead(LList_t *list, NodePtr_t node_t);

int InsertAfter(LList_t *list,NodePtr_t prev, NodePtr_t node_t);

enum LL_ErrorCodes {
  LL_SUCCESS = 0,
  LL_ERROR_MEMORY_ALLOCATION = -2,
  LL_ERROR_NULL_VALUE_GIVEN = -6,
  LL_ERROR_NODE_INIT=-36,
  LL_ERROR_NODE_ADD=-50,
  LL_ERROR_NODE_DUPLICATION= -48,
  LL_ERROR_LIST_EMPTYLIST=-39,
  LL_ERROR_LIST_NODENOTFOUND=-40,
  LL_ERROR_LIST_DELETE=-38,
  LL_ERROR_LIST_INIT=-41,
  LL_ERROR_LIST_DELETENODE=-42,
  LL_ERROR_LIST_DESTROY_NODE=-43,
  LL_ERROR_LIST_CONSTRUCTOR = -44,
  LL_ERROR_LIST_CLEAR = -45,
  LL_ERROR_LIST_COPY = -46,
  LL_ERROR_LIST_INSERTHEAD = -47,
  LL_ERROR_LIST_DETACH_HEAD = -49
};
#endif
