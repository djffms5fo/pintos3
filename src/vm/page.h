#include <hash.h>
#include <stdbool.h>
#include "threads/thread.h"



#define VM_BIN        0
#define VM_FILE       1
#define VM_ANON       2


struct vm_entry{
	uint8_t type;                // one of VM_BIN, VM_FILE, VM_ANON
	void *vaddr;                 // virtual page number that vm_entry manage
	bool writable;               // true if the address is writable
	bool is_loaded;              // flag that physical memory loaded
	struct file* file;           // file that mapped with virtual address

	struct list_elem mmap_elem;  // mmap list element

	size_t offset;               // offset of the file that has to read
	size_t read_bytes;           // size of data that wrote at virtual page
	size_t zero_bytes;           // remain page that has to filled with 0

	size_t swap_slot;            // swap slot

	struct hash_elem elem;       // hash table element
};

struct mmap_file{
	int mapid;
	struct file *file;
	struct list_elem elem;
	struct list vme_list;
};


struct page{
	void *kaddr;
	struct vm_entry *vme;
	struct thread *thread;
	struct list_elem lru;
};




void vm_init(struct hash *vm);
bool insert_vme(struct hash *vm, struct vm_entry *vme);
bool delete_vme(struct hash *vm, struct vm_entry *vme);
struct vm_entry *find_vme(void *vaddr);
void vm_destroy(struct hash *vm);
bool load_file(void* kaddr, struct vm_entry *vme);