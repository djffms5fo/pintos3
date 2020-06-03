#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "vm/page.h"
#include "threads/palloc.h"
#include "threads/synch.h"

struct list lru_list;               // list of pages
struct lock lru_list_lock;          // lock for the list of pages
struct list_elem *lru_clock;        // used for clock algorithm


void lru_list_init(void);
void add_page_to_lru_list(struct page* page);
void del_page_from_lru_list(struct page* page);
struct page* alloc_page(enum palloc_flags flags);
void free_page(void *kaddr);
void __free_page(struct page* page);
void *try_to_free_pages(enum palloc_flags flags);


#endif