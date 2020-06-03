#include "vm/page.h"
#include "threads/vaddr.h"

static unsigned vm_hash_func(const struct hash_elem *e, void *aux);
static bool vm_less_func(const struct hash_elem *a,
	                     const struct hash_elem *b, void *aux);
static void vm_destroy_func(struct hash_elem *e, void *aux);





void vm_init(struct hash *vm){
	hash_init(vm, vm_hash_func, vm_less_func, NULL);
}

static unsigned vm_hash_func(const struct hash_elem *e, void *aux){
	struct vm_entry *v = hash_entry(e, struct vm_entry, elem);
	return hash_int(v->vaddr);
}

static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux){
	struct vm_entry *va = hash_entry(a, struct vm_entry, elem);
	struct vm_entry *vb = hash_entry(b, struct vm_entry, elem);
	return va->vaddr < vb->vaddr;
}

static void vm_destroy_func(struct hash_elem *e, void *aux){
	struct vm_entry *v = hash_entry(e, struct vm_entry, elem);
	free(v);
}

bool insert_vme(struct hash *vm, struct vm_entry *vme){
	return hash_insert(vm, &vme->elem) == NULL;
}

bool delete_vme(struct hash *vm, struct vm_entry *vme){
	return hash_delete(vm, &vme->elem);
}

struct vm_entry *find_vme(void *vaddr){
	struct vm_entry v;

	v.vaddr = pg_round_down(vaddr);
	struct hash_elem *e = hash_find(&thread_current()->vm, &v.elem);
	if(!e){
		return NULL;
	}
	return hash_entry(e, struct vm_entry, elem);
}

void vm_destroy(struct hash *vm){
	hash_destroy(vm, vm_destroy_func);
}


bool load_file(void* kaddr, struct vm_entry *vme){
	int read_bytes = file_read_at(vme->file,kaddr, vme->read_bytes, vme->offset);
	if (read_bytes != (int)vme->read_bytes)
		return false;
	memset(kaddr + vme->read_bytes, 0, vme->zero_bytes);
	vme->is_loaded = true;
	return true;
}