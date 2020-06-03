#include "vm/swap.h"
#include "threads/synch.h"
#include "devices/block.h"
#include <bitmap.h>
#include "threads/vaddr.h"

void swap_init(size_t used_index, void *kaddr){
	lock_init(&swap_lock);
	swap_bitmap= bitmap_create(used_index);
}

void swap_in(size_t used_index, void *kaddr){
	lock_acquire(&swap_lock);
	struct block *swap_block;
	swap_block = block_get_role(BLOCK_SWAP);

	int sectors = PGSIZE / BLOCK_SECTOR_SIZE;

	int i;
	for(i = 0; i < sectors; i++)
		block_read(swap_block, used_index * sectors + i, kaddr + BLOCK_SECTOR_SIZE * i);

	bitmap_set_multiple(swap_bitmap, used_index, 1, false);

	lock_release(&swap_lock);
}

size_t swap_out(void *kaddr){
	lock_acquire(&swap_lock);
	struct block *swap_block;
	swap_block = block_get_role(BLOCK_SWAP);

	size_t swap_index = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);

	if(swap_index == BITMAP_ERROR){
		lock_release(&swap_lock);
		return BITMAP_ERROR;
	}

	int sectors = PGSIZE / BLOCK_SECTOR_SIZE;

	int i;
	for(i = 1; i < sectors; i++)
		block_write(swap_block, swap_index * sectors + i, kaddr + BLOCK_SECTOR_SIZE * i);

	lock_release(&swap_lock);
	return swap_index;
}