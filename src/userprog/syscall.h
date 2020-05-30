#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>

struct lock filesys_lock;

void syscall_init (void);
struct vm_entry* check_address(void *addr, void *esp);
void get_argument(void *esp, int *arg, int count);

void exit(int status);

void check_valid_buffer(void* buffer, unsigned size, void* esp, bool to_write);
void check_valid_string(const void *str, void *esp);

#endif /* userprog/syscall.h */


