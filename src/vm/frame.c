#include "vm/frame.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "vm/swap.h"



static struct list_elem *get_next_lru_clock(void);


void lru_list_init(void){
	list_init(&lru_list);
	lock_init(&lru_list_lock);
	lru_clock = NULL;
}

void add_page_to_lru_list(struct page *page){
	if(!lock_held_by_current_thread(&lru_list_lock))
		lock_acquire(&lru_list_lock);
	list_push_back(&lru_list, &page->lru);
	lock_release(&lru_list_lock);
}

void del_page_from_lru_list(struct page *page){
	if(&page->lru == lru_clock)
		lru_clock = list_remove(lru_clock);
	else
		list_remove(&page->lru);
}

struct page* alloc_page(enum palloc_flags flags){
	if(!lock_held_by_current_thread(&lru_list_lock))
		lock_acquire(&lru_list_lock);
	struct page *page = (struct page*)malloc(sizeof(struct page));
	if(!page){
		lock_release(&lru_list_lock);
		return NULL;
	}

	memset(page, 0, sizeof(struct page));
	page->thread = thread_current();
	while((page->kaddr = palloc_get_page(flags)) == NULL){
		try_to_free_pages(flags);
	}

	list_push_back(&lru_list, &page->lru);
	lock_release(&lru_list_lock);
	return page;
}

void free_page(void *kaddr){
	lock_acquire(&lru_list_lock);
	struct page *page;
	struct list_elem *e = list_begin(&lru_list);
	for(e; e != list_end(&lru_list); e = list_next(e)){
		page = list_entry(e, struct page, lru);
		if(page->kaddr == kaddr){
			__free_page(page);
			break;
		}
	}
	lock_release(&lru_list_lock);
}

void __free_page(struct page* page){
	pagedir_clear_page(page->thread->pagedir, page->vme->vaddr);
	del_page_from_lru_list(page);
	palloc_free_page(page->kaddr);
	free(page);
}

static struct list_elem *get_next_lru_clock(void){
	if(lru_clock == list_end(&lru_list) || !lru_clock){
		if(list_empty(&lru_list))
			return NULL;
		lru_clock = list_begin(&lru_list);
		return lru_clock;
	}
	lru_clock = list_next(lru_clock);
	if(lru_clock == list_end(&lru_list))
		return get_next_lru_clock();
	return lru_clock;
}

void *try_to_free_pages(enum palloc_flags flags){
	struct page *victim;
	struct list_elem *e;
	int dirty;
	e = get_next_lru_clock();
	victim = list_entry(e, struct page, lru);
	while(pagedir_is_accessed(victim->thread->pagedir, victim->vme->vaddr)){
		pagedir_set_accessed(victim->thread->pagedir, victim->vme->vaddr, false);
		e = get_next_lru_clock();
		victim = list_entry(e, struct page, lru);
	}

	dirty = pagedir_is_dirty(victim->thread->pagedir, victim->vme->vaddr);
	struct vm_entry *v = victim->vme;

	switch(v->type){
		case VM_BIN:
			if(dirty){
				v->swap_slot = swap_out(victim->kaddr);
				v->type = VM_ANON;
			}
			break;
		case VM_FILE:
			if(dirty){
				if(file_write_at(v->file, v->vaddr, v->read_bytes, v->offset)
					!= (int)v->read_bytes)
					exit(-1);
			}
			break;
		case VM_ANON:
			v->swap_slot = swap_out(victim->kaddr);
			break;
		default:
			exit(-1);
	}
	v->is_loaded =  false;
	__free_page(victim);
}