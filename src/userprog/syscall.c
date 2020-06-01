#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"
#include "vm/page.h"


static void syscall_handler (struct intr_frame *);

static void halt(void);
static tid_t exec(const char *cmd_line);
static int wait(tid_t tid);
static bool create(const char *file, unsigned initial_size);
static bool remove(const char *file);
static int open(const char *file);
static int filesize(int fd);
static int read(int fd, void *buffer, unsigned size);
static int write(int fd, void *buffer, unsigned size);
static void seek(int fd, unsigned position);
static unsigned tell(int fd);
static void close(int fd);
static int mmap(int fd, void *addr);
static void do_munmap(struct mmap_file *mf);

void
syscall_init (void) 
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	int arg[4];
	uint32_t *sp = (uint32_t)f->esp;
	check_address((void*)sp, (void*)sp);
	int number = *sp;
	switch (number){
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			get_argument((void*)sp, arg, 1);
			exit((int)arg[0]);
			break;
		case SYS_EXEC:
			get_argument((void*)sp, arg, 1);
			check_valid_string((const void*)arg[0], (void*)sp);
			f->eax = exec((const char*)arg[0]);
			break;
		case SYS_WAIT:
			get_argument((void*)sp, arg, 1);
			f->eax = wait((tid_t)arg[0]);
			break;
		case SYS_CREATE:
			get_argument((void*)sp, arg, 2);
			f->eax = create((const char*)arg[0], (unsigned)arg[1]);
			break;
		case SYS_REMOVE:
			get_argument((void*)sp, arg, 1);
			f->eax = remove((const char*)arg[0]);
			break;
		case SYS_OPEN:
			get_argument((void*)sp, arg, 1);
			check_valid_string((const void*)arg[0], (void*)sp);
			f->eax = open((const char*)arg[0]);
			break;
		case SYS_FILESIZE:
			get_argument((void*)sp, arg, 1);
			f->eax = filesize((int)arg[0]);
			break;
		case SYS_READ:
			get_argument((void*)sp, arg, 3);
			check_valid_buffer((const char*)arg[1], (unsigned)arg[2], (void*)sp, false);
			f->eax = read((int)arg[0], (void*)arg[1], (unsigned)arg[2]);
			break;
		case SYS_WRITE:
			get_argument((void*)sp, arg, 3);
			check_valid_buffer((const void*)arg[1], (unsigned)arg[2], (void*)sp, true);
			f->eax = write((int)arg[0], (void*)arg[1], (unsigned)arg[2]);
			break;
		case SYS_SEEK:
			get_argument((void*)sp, arg, 2);
			seek((int)arg[0], (unsigned)arg[1]);
			break;
		case SYS_TELL:
			get_argument((void*)sp, arg, 1);
			f->eax = tell((int)arg[0]);
			break;
		case SYS_CLOSE:
			get_argument((void*)sp, arg, 1);
			close((int)arg[0]);
			break;
		case SYS_MMAP:
			get_argument((void*)sp, arg, 2);
			f->eax = mmap((int)arg[0], (void*)arg[1]);
			break;
		case SYS_MUNMAP:
			get_argument((void*)sp, arg, 1);
			munmap((int)arg[0]);
			break;
		default:
			exit(-1);
	}
}

struct vm_entry* check_address(void *addr, void* esp){
	if(!is_user_vaddr(addr) && addr >= ((void*) 0x8048000)){
		exit(-1);
	}
	return find_vme(addr);
}

void get_argument(void *esp, int *arg, int count){
	int i;
	for (i = 0; i < count; i++){
		esp += 4;
		arg[i] = *(int32_t*)esp;
		check_address((void*)arg[i], esp);
	}
}

static void halt(void){
	shutdown_power_off();
}

void exit(int status){
	struct thread* cur = thread_current();
	cur->exit_status = status;
	printf("%s: exit(%d)\n", cur->name, status);
	thread_exit();
}

static tid_t exec(const char *cmd_line){
	tid_t tid = process_execute(cmd_line);
	struct thread *child = get_child_process(tid);
	sema_down(&child->load);
	if(child->success == 0)
		return -1;
	return tid;
}

static int wait(tid_t tid){
	return process_wait(tid);
}

static bool create(const char *file, unsigned initial_size){
	if (file == NULL)
		exit(-1);
	return filesys_create(file, initial_size);
}

static bool remove(const char *file){
	if (file == NULL)
		exit(-1);
	return filesys_remove(file);
}

static int open(const char *file){
	if (file == NULL)
		exit(-1);
	lock_acquire(&filesys_lock);
	struct file *f = filesys_open(file);
	if(f != NULL){
		lock_release(&filesys_lock);
		return process_add_file(f);
	}
	lock_release(&filesys_lock);
	return -1;
}

static int filesize(int fd){
	struct file *f = process_get_file(fd);
	if (f != NULL)
		return file_length(f);
	return -1;
}

static int read(int fd, void *buffer, unsigned size){
	lock_acquire(&filesys_lock);
	struct file *f = process_get_file(fd);
	if(fd == 0){
		int i;
		for(i = 0; i < size; i++)
			*((char*)buffer+i) = input_getc();
		lock_release(&filesys_lock);
		return size;
	}
	if(f !=NULL){
		unsigned byte = file_read(f, buffer, size);
		lock_release(&filesys_lock);
		return byte;
	}
	lock_release(&filesys_lock);
	return -1;
}

static int write(int fd, void *buffer, unsigned size){
	lock_acquire(&filesys_lock);
	struct file *f = process_get_file(fd);
	if(fd == 1){
		putbuf(buffer, size);
		lock_release(&filesys_lock);
		return size;
	}
	if(f != NULL){
		unsigned byte = file_write(f, buffer, size);
		lock_release(&filesys_lock);
		return byte;
	}
	lock_release(&filesys_lock);
	return -1;
}

static void seek(int fd, unsigned position){
	struct file *f = process_get_file(fd);
	if(f != NULL)
		file_seek(f, position);
}

static unsigned tell(int fd){
	struct file *f = process_get_file(fd);
	return file_tell(f);
}

static void close(int fd){
	process_close_file(fd);
}

static int mmap(int fd, void *addr){
	if(fd == 1 || fd == 0)
		return -1;
	if(pg_ofs(addr))
		return -1;
	if(!addr)
		return -1;
	if(!is_user_vaddr(addr))
		return -1;

	struct mmap_file *mf;
	size_t offset = 0;
	struct thread *cur = thread_current();

	mf = (struct mmap_file*)malloc(sizeof(struct mmap_file));
	if(!mf)
		return -1;
	memset(mf, 0, sizeof(struct mmap_file));
	list_init(&mf->vme_list);

	lock_acquire(&filesys_lock);

	mf->file = process_get_file(fd);
	if(!mf->file){
		lock_release(&filesys_lock);
		return -1;
	}
	int len = file_length(mf->file);
	if(!len){
		lock_release(&filesys_lock);
		return -1;
	}
	mf->file = file_reopen(mf->file);
	
	lock_release(&filesys_lock);

	mf->mapid = cur->next_mapid;
	cur->next_mapid++;
	list_push_back(&cur->mmap_list, &mf->elem);

	while(len>0){
		if(find_vme(addr)){
			return -1;
		}
		struct vm_entry *v = (struct vm_entry*)malloc(sizeof(struct vm_entry));
		memset(v, 0, sizeof(struct vm_entry));
		v->type = VM_FILE;
		v->vaddr = addr;
		v->writable = true;
		v->file = mf->file;
		v->offset = offset;
		if(len < PGSIZE){
			v->read_bytes = len;
			v->zero_bytes = PGSIZE - len;
		}
		else{
			v->read_bytes = PGSIZE;
			v->zero_bytes = 0;
		}

		list_push_back(&mf->vme_list, &v->mmap_elem);
		insert_vme(&cur->vm, v);
		addr += PGSIZE;
		offset += PGSIZE;
		len -= PGSIZE;
	}
	return mf->mapid;
}

void munmap(int mapid){
	struct mmap_file *mf = NULL;
	struct thread *cur = thread_current();
	struct list_elem *e = list_begin(&cur->mmap_list);
	for(e; e != list_end(&cur->mmap_list); e = list_next(e)){
		mf = list_entry(e, struct mmap_file, elem);
		if(mf->mapid == mapid){
			do_munmap(mf);
			break;
		}
	}
}


void check_valid_buffer(void* buffer, unsigned size, void* esp, bool to_write){
	struct vm_entry *v;
	for(size; size > 0; size--){
		v = check_address(buffer + size, esp);
		if(!v && (!v->writable && to_write))
			exit(-1);
	}
	v = check_address(buffer, esp);
	if(!v && (!v->writable && to_write))
		exit(-1);
}

void check_valid_string(const void *str, void *esp){
	struct vm_entry *v;
	while(*(char*)str){
		v = check_address((void*)str, esp);
		str++;
	}
}

void do_munmap(struct mmap_file *mf){
	if(!mf)
		exit(-1);

	struct list_elem *e = list_begin(&mf->vme_list);
	struct vm_entry *v;
	struct thread *cur = thread_current();
	for(e; e != list_end(&mf->vme_list);){
		v = list_entry(e, struct vm_entry, mmap_elem);
		if(v->is_loaded){
			if(pagedir_is_dirty(cur->pagedir, v->vaddr)){
				lock_acquire(&filesys_lock);
				if(file_write_at(v->file, v->vaddr, v->read_bytes, v->offset)
					!= (int)v->read_bytes){
					lock_release(&filesys_lock);
					exit(-1);
				}
				lock_release(&filesys_lock);
			}
			pagedir_clear_page(cur->pagedir, v->vaddr);
		}
		v->is_loaded = false;
		e = list_remove(e);
		delete_vme(&cur->vm, v);
		free(v);
	}
	list_remove(&mf->elem);
	free(mf);
}