#include "CLL.h"
#include <pthread.h>


typedef struct node_s {
  void *data;
  /*should make a copy of the data 
   *deep copy no shared data unless you want some headache*/
  void *(*constructor)(void *data);
  void (*destructor)(void *data);
  //should return 0 if equal 1 if not
  struct node_s *next;
} node_t;

/*see NOMUTEX section below for explanation*/
int DetachHead_NoMutex( LList_t *list,NodePtr_t *Node);
int AddNode_NoMutex(LList_t *list,NodePtr_t Node);
typedef struct LList_s {
  int (*compare)(void *, void *);
  NodePtr_t head;
  NodePtr_t tail;
  size_t elements_count;
  pthread_mutex_t list_mutex;
}LList_t;
int InitNode(NodePtr_t *Node,
             void *(*constructor)(void *data),
             void (*destructor)(void *data),
             void *data,
             NodePtr_t next)
{
  ERROR_CHECK_NULL_RET(destructor,LL_ERROR_NULL_VALUE_GIVEN);
  ERROR_CHECK_NULL_RET(constructor,LL_ERROR_NULL_VALUE_GIVEN);
  MALLOC_CHECK_NULL_RET(*Node,sizeof(node_t),LL_ERROR_MEMORY_ALLOCATION);

  int error_;
  if (NULL == ((*Node)->data = constructor(data))){
    error_ = LL_ERROR_LIST_CONSTRUCTOR;
    goto exiterror_;
  } 
  (*Node)->next = next;
  (*Node)->constructor = constructor;
  (*Node)->destructor = destructor;
  return LL_SUCCESS;
exiterror_ :
  free(*Node);
  *Node = NULL;
  return error_;
}
int DestroyNode(NodePtr_t Node){
  ERROR_CHECK_NULL_RET(Node,LL_ERROR_NULL_VALUE_GIVEN);

  if(NULL != (Node)->destructor){
    (Node)->destructor((Node)->data);
    Node->data = NULL;
  }
  free(Node);
  return LL_SUCCESS;
}

int DupNode(NodePtr_t *Nodedst,
            NodePtr_t Nodesrc)
{
  ERROR_CHECK_NULL_RET(Nodesrc,LL_ERROR_NULL_VALUE_GIVEN);
  ERROR_CHECK_SUCCESS_RET( 
    InitNode(Nodedst,
             (Nodesrc)->constructor,
             (Nodesrc)->destructor,
             (Nodesrc)->data,
             NULL),
    LL_SUCCESS,
    LL_ERROR_LIST_INIT);
  return LL_SUCCESS;
}
int InitList(LList_t **list,
             int (*compare)(void *, void *)
             ){
  ERROR_CHECK_NULL_RET(compare,LL_ERROR_NULL_VALUE_GIVEN);
  MALLOC_CHECK_NULL_RET(*list,sizeof(LList_t),LL_ERROR_MEMORY_ALLOCATION);
  pthread_mutex_init(&(*list)->list_mutex, NULL);
  pthread_mutex_lock(&(*list)->list_mutex);
  (*list)->elements_count=0;
  (*list)->head  = NULL;
  (*list)->tail  = NULL;
  (*list)->compare  = compare;
  pthread_mutex_unlock(&(*list)->list_mutex);

  return LL_SUCCESS;
}

int DetachHead( LList_t *list,NodePtr_t *Node)
{
  int error_;

  ERROR_CHECK_NULL_RET(list,LL_ERROR_NULL_VALUE_GIVEN);
  ERROR_CHECK_NULL_RET(Node,LL_ERROR_NULL_VALUE_GIVEN);
  pthread_mutex_lock(&list->list_mutex);
  
  if(0 == list->elements_count){
    error_ = LL_ERROR_LIST_EMPTYLIST;
    goto exit_;
  }

  *Node = (list->head);
  list->head=(*Node)->next;
  if(!list->head){
    list->tail = NULL;
  }
  --list->elements_count;
  (*Node)->next = NULL;
  error_ = LL_SUCCESS;
  goto exit_;
exit_:
  pthread_mutex_unlock(&list->list_mutex);
  return error_;
}

int AddNode(LList_t *list,NodePtr_t Node){ ERROR_CHECK_NULL_RET(list,LL_ERROR_NULL_VALUE_GIVEN);
  ERROR_CHECK_NULL_RET(Node,LL_ERROR_NULL_VALUE_GIVEN);
  Node->next =NULL;
  pthread_mutex_lock(&list->list_mutex);

  if(NULL == list->head){
    list->head = Node;
    list->tail = Node;
    ++list->elements_count;
    goto exit_;
  }
  (list->tail)->next = Node;
  list->tail = Node;
  ++list->elements_count;
  
exit_:
  pthread_mutex_unlock(&list->list_mutex);
  return LL_SUCCESS;
}
int FindNode(LList_t *list, void *key, NodePtr_t *result){
  pthread_mutex_lock(&list->list_mutex);
  ERROR_CHECK_NULL_RET(list,LL_ERROR_NULL_VALUE_GIVEN);
  ERROR_CHECK_NULL_RET(list->compare,LL_ERROR_NULL_VALUE_GIVEN);
  ERROR_CHECK_NULL_RET(list->head,LL_ERROR_LIST_NODENOTFOUND);
  int error_ ;
  NodePtr_t temp ;
  for(temp = list->head ;
  NULL != temp ;
  temp = temp->next)
  {
    if(!((list)->compare)(key,(temp)->data)){
      *result = temp; 
      error_ = LL_SUCCESS;
      goto exit_;
    }
  }
  error_ = LL_ERROR_LIST_NODENOTFOUND;
exit_:
  pthread_mutex_unlock(&list->list_mutex);
  return error_;

}
int DetachNode(LList_t *list,NodePtr_t *Node,void *key){
  ERROR_CHECK_NULL_RET(list,LL_ERROR_NULL_VALUE_GIVEN);
  ERROR_CHECK_NULL_RET(list->head,LL_ERROR_NULL_VALUE_GIVEN);
  ERROR_CHECK_NULL_RET(list->compare,LL_ERROR_NULL_VALUE_GIVEN);
  NodePtr_t temp ;
  if(!((list)->compare)(key,(list->head)->data)){
    ERROR_CHECK_SUCCESS_RET(DetachHead(list,Node),
                            LL_SUCCESS,
                            LL_ERROR_LIST_DETACH_HEAD);
    return LL_SUCCESS;
  }
  pthread_mutex_lock(&list->list_mutex);
  for(temp = list->head ;
  NULL != temp->next ;
  temp = temp->next)
  {
    if(!((list)->compare)(key,(temp->next)->data)){
      *Node = temp->next; 
      if (temp->next == list->tail){
        list->tail = temp;
      }
      temp->next = (temp->next)->next;
      --list->elements_count;
      pthread_mutex_unlock(&list->list_mutex);
      return LL_SUCCESS;
    }
  }
  pthread_mutex_unlock(&list->list_mutex);
  return LL_ERROR_LIST_NODENOTFOUND;
}
int ClearList(LList_t *list){
  ERROR_CHECK_NULL_RET(list,LL_ERROR_NULL_VALUE_GIVEN);
  NodePtr_t temp;
  pthread_mutex_lock(&list->list_mutex);
  while ( (list)->head != NULL) {

    ERROR_CHECK_SUCCESS_RET(DetachHead_NoMutex((list),&temp),
                            LL_SUCCESS,
                            LL_ERROR_LIST_DETACH_HEAD);
    ERROR_CHECK_SUCCESS_RET(DestroyNode(temp),
                            LL_SUCCESS,
                            LL_ERROR_LIST_DESTROY_NODE);
  }
  list->elements_count = 0;
  pthread_mutex_unlock(&list->list_mutex);
  return LL_SUCCESS;
}
int DestroyList(LList_t **list){
  ERROR_CHECK_SUCCESS_RET(ClearList(*list),
                          LL_SUCCESS,
                          LL_ERROR_LIST_CLEAR);
  pthread_mutex_destroy(&(*list)->list_mutex);
  free(*list);
  *list = NULL;
  return LL_SUCCESS;
}
int ForEach(LList_t *list, void (*func)(void *data)){
  ERROR_CHECK_NULL_RET(list,LL_ERROR_NULL_VALUE_GIVEN);
  ERROR_CHECK_NULL_RET(func,LL_ERROR_NULL_VALUE_GIVEN);
  NodePtr_t temp; 
  pthread_mutex_lock(&list->list_mutex);
  for (temp = list->head;NULL != temp;temp=temp->next){
    func(temp->data);
  }
  pthread_mutex_unlock(&list->list_mutex);
  return LL_SUCCESS;
}

int CopyList(LList_t *src, LList_t *dst){
  ERROR_CHECK_NULL_RET(src,LL_ERROR_NULL_VALUE_GIVEN);
  ERROR_CHECK_NULL_RET(src->head,LL_ERROR_NULL_VALUE_GIVEN);
  ERROR_CHECK_NULL_RET(dst,LL_ERROR_NULL_VALUE_GIVEN);
  if (0 == GetSize(src)){
    return  LL_ERROR_LIST_EMPTYLIST;
  }
  ERROR_CHECK_SUCCESS_RET(ClearList(dst),
                          LL_SUCCESS,
                          LL_ERROR_LIST_CLEAR);
  NodePtr_t temp,temp_;
  pthread_mutex_lock(&src->list_mutex);
  for (temp_ = (src->head); NULL != temp_ ; temp_ = temp_->next)
  {
  ERROR_CHECK_SUCCESS_RET(DupNode(&temp,temp_),
                          LL_SUCCESS,
                          LL_ERROR_NODE_DUPLICATION);
    if (LL_SUCCESS !=AddNode(dst,temp)){
      DestroyNode(temp);
      ClearList(dst);
      return LL_ERROR_NODE_ADD;
    }
  }
  pthread_mutex_unlock(&src->list_mutex);
  return LL_SUCCESS;
}
size_t GetSize(LList_t *list){
  ERROR_CHECK_NULL_RET(list,0);
  pthread_mutex_lock(&list->list_mutex);
  size_t elemntcnt = list->elements_count;
  pthread_mutex_unlock(&list->list_mutex);
  return elemntcnt;
}

int InsertHead(LList_t *list, NodePtr_t Node)
{
  ERROR_CHECK_NULL_RET(list,LL_ERROR_NULL_VALUE_GIVEN);
  ERROR_CHECK_NULL_RET(Node,LL_ERROR_NULL_VALUE_GIVEN);
  pthread_mutex_lock(&list->list_mutex);
  if (NULL == list->head ){
  ERROR_CHECK_SUCCESS_RET(AddNode_NoMutex(list,Node),
                          LL_SUCCESS,
                          LL_ERROR_NODE_ADD);
    goto exit_;
  }
  Node->next = list->head; 
  list->head = Node;
  ++list->elements_count;
exit_:
  pthread_mutex_unlock(&list->list_mutex);
  return LL_SUCCESS;
}

int InsertAfter(LList_t *list,NodePtr_t prev, NodePtr_t Node)
{
  ERROR_CHECK_NULL_RET(list,LL_ERROR_NULL_VALUE_GIVEN);
  ERROR_CHECK_NULL_RET(prev,LL_ERROR_NULL_VALUE_GIVEN);
  ERROR_CHECK_NULL_RET(Node,LL_ERROR_NULL_VALUE_GIVEN);
  pthread_mutex_lock(&list->list_mutex);
  Node->next =prev->next; 
  prev->next = Node;
  ++list->elements_count;
  if (list-> tail == prev){
    list->tail = Node;
  }
  pthread_mutex_unlock(&list->list_mutex);
  return LL_SUCCESS;
}
void printlist(LList_t *list){
  if (LL_SUCCESS != ForEach(list,(void (*)(void *))puts))
  {
    return ;
  }
}


/*no mutex funcions , ONLY ALLOWED INSIDE WITH_MUTEX 
 * FUNCIONS FOR CONVENIENCE NOT ALLOWED FOR USERS , 
 * INTERNAL USE ONLY*/

int DetachHead_NoMutex( LList_t *list,NodePtr_t *Node)
{
  int error_;

  ERROR_CHECK_NULL_RET(list,LL_ERROR_NULL_VALUE_GIVEN);
  ERROR_CHECK_NULL_RET(Node,LL_ERROR_NULL_VALUE_GIVEN);
  
  if(0 == list->elements_count){
    error_ = LL_ERROR_LIST_EMPTYLIST;
    goto exit_;
  }

  *Node = (list->head);
  list->head=(*Node)->next;
  if(!list->head){
    list->tail = NULL;
  }
  --list->elements_count;
  (*Node)->next = NULL;
  error_ = LL_SUCCESS;
  goto exit_;
exit_:
  return error_;
}
int AddNode_NoMutex(LList_t *list,NodePtr_t Node)
{ 
  ERROR_CHECK_NULL_RET(list,LL_ERROR_NULL_VALUE_GIVEN);
  ERROR_CHECK_NULL_RET(Node,LL_ERROR_NULL_VALUE_GIVEN);
  Node->next =NULL;

  if(NULL == list->head){
    list->head = Node;
    list->tail = Node;
    ++list->elements_count;
    return LL_SUCCESS;
  }
  (list->tail)->next = Node;
  list->tail = Node;
  ++list->elements_count;
  return LL_SUCCESS;
}
