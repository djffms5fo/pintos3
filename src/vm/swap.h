#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stddef.h>

struct lock swap_lock;           // lock for swapping memory
struct bitmap *swap_bitmap;      // bitmap for swapping

void swap_init(size_t used_index, void* kaddr);
void swap_in(size_t used_index, void* kaddr);
size_t swap_out(void* kaddr);

#endif