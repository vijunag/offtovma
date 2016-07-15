/*
 * Author: Vijay Nag
 * Date: 13/07/2016
 * Output the vma range for a given
 * file offset
 */

#define _GNU_SOURCE 1 //memmem
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <bits/siginfo.h>

#ifndef IS_ELF
#define IS_ELF(ehdr)  ((ehdr).e_ident[EI_MAG0] == ELFMAG0 && \
       (ehdr).e_ident[EI_MAG1] == ELFMAG1 && \
       (ehdr).e_ident[EI_MAG2] == ELFMAG2 && \
       (ehdr).e_ident[EI_MAG3] == ELFMAG3)
#endif /*IS_ELF*/

#define SYSCALL_EXIT_ON_ERR(syscall)                          \
({                                                            \
 int ret = syscall;                                           \
 if (ret < 0) {                                               \
   fprintf(stderr, "%s error at %s:%d, errno(%d) = %s\n",     \
      #syscall, __func__, __LINE__,errno, strerror(errno));   \
    exit(ret);                                                \
 }                                                            \
 ret;                                                         \
 })

#define LOGERR_EXIT(msg) \
do {                     \
  fprintf(stderr, msg);  \
  exit(-1);              \
} while(0);

#define LOG_MSG(msg) \
  fprintf(stderr, msg);

typedef struct Elf_ctxt {
  union {
   Elf32_Ehdr elf32_ehdr;
   Elf64_Ehdr elf64_ehdr;
   unsigned char e_ident[EI_NIDENT];
  } elf_ehdr;
#define elf32_ehdr elf_ehdr.elf32_ehdr
#define elf64_ehdr elf_ehdr.elf64_ehdr
#define e_ident    elf_ehdr.e_ident

  void *mmap_addr;
  uint8_t is32; /* is it 32 bit elf ? */
} Elf_ctxt;

#define GET_PHDR_COUNT(elf_type, e) \
({                                  \
  elf_type* _e = (e);               \
  _e->e_phnum;                      \
})

struct load_list {
	struct load_list *next;
	int idx;
	off_t offset;
	unsigned long lowaddr;
	unsigned long hiaddr;
	unsigned long f_sz;
};
typedef struct load_list load_list;
struct list_head {
	load_list *head;
	load_list *tail;
} g_list;

#define APPEND_LIST(_l, i)                                       \
do {                                                             \
	load_list *nlist = (load_list*)malloc(sizeof(load_list));\
	nlist->next = NULL;                                      \
	nlist->idx = i;                                          \
	nlist->offset =(_l)->p_offset;                           \
	nlist->lowaddr=(_l)->p_vaddr;                            \
	nlist->hiaddr=nlist->lowaddr+(_l)->p_memsz;              \
	nlist->f_sz = (_l)->p_filesz;                            \
	if (!g_list.head) {                                      \
		g_list.head = nlist;                             \
	}                                                        \
	if (!g_list.tail) {                                      \
		g_list.tail = nlist;                             \
	} else {                                                 \
	  g_list.tail->next = nlist;                             \
		g_list.tail = nlist;                             \
	}                                                        \
} while (0);

static void* Elf_find_phdr_by_type(Elf_ctxt *elf, int type, int *idx)
{
   void *res = NULL;
   int i = 0;
   int found = 0;
/*
 * Evil macro substition.
 * not meant for anything else.
 */
#define ITER_AND_GET_ELF_PHDR(elf_type, phdr_type, e, _p) \
    elf_type* _e = (e);\
   _p = (phdr_type *)((char *)_e + _e->e_phoff); \
   for (i = *idx; i < _e->e_phnum; ++i) { \
       if (type == _p[i].p_type) { \
				 *idx = i;  \
         found = 1; \
         break; \
       } \
   }

   if (elf->is32) {
     Elf32_Phdr *p = NULL;
     ITER_AND_GET_ELF_PHDR(Elf32_Ehdr, Elf32_Phdr, elf->mmap_addr, p);
     res = found ? &p[i] : NULL;
   } else {
     Elf64_Phdr *p = NULL;
     ITER_AND_GET_ELF_PHDR(Elf64_Ehdr, Elf64_Phdr, elf->mmap_addr, p);
     res = found ? &p[i] : NULL;
   }
   return res;
#undef ITER_AND_GET_ELF_PHDR
}

static void load_the_load_section(Elf_ctxt *elf)
{
   int idx = 0;
	 int count = 0;
	 if (elf->is32) {
		 count = GET_PHDR_COUNT(Elf32_Ehdr, elf->mmap_addr);
	 } else {
		 count = GET_PHDR_COUNT(Elf64_Ehdr, elf->mmap_addr);
	 }
   while (idx < count) {
		 void *phdr = Elf_find_phdr_by_type(elf, PT_LOAD, &idx);
		 if (elf->is32) {
		   Elf32_Phdr *p = (Elf32_Phdr*) phdr;
			 APPEND_LIST(p, idx);
		 } else {
			 Elf64_Phdr *p = (Elf64_Phdr*) phdr;
			 APPEND_LIST(p, idx);
		 }
		 idx++;
   }
   load_list *head = g_list.head;
   printf("Load sections in the core file\n");
   while (head) {
     printf("0x%016llx-0x%016llx is load%d at offset %8lld\n",
	head->lowaddr, head->hiaddr, head->idx, head->offset);
     head=head->next;
   }
}

void find_vma_from_offset(off_t offset)
{
   load_list *head = g_list.head;
#define HEAD_FILESZ(_head) \
   ((_head)->hiaddr - (_head)->lowaddr)

   while (head) {
     off_t load_end = head->offset + HEAD_FILESZ(head);
     if (head->offset <= offset &&
	 offset < load_end) {
	 printf("0x%016llx-0x%016llx is load%x at offset %8llu\n",
	   head->lowaddr, head->hiaddr, head->idx, head->offset);
	   unsigned long vma_offset = (unsigned long)(offset-head->offset);
	   printf("VMA is approximately 0x%llx\n", head->lowaddr+vma_offset);
	   return;
       }
        head=head->next;
   }
}

static void find_pattern_in_load_segment(Elf_ctxt *elf,
		                                     unsigned long pattern,
																				 unsigned long pat_len)
{
  load_list *head = g_list.head;

  while (head) {
    void  *s = elf->mmap_addr+head->offset;
    int len =  head->f_sz;
    void *p = NULL;
rep:
    p = memmem(s, len, &pattern, pat_len);
    if (p) {
	len -= (unsigned long)p - (unsigned long)s;
	unsigned long offset = (unsigned long)p-(unsigned long)(elf->mmap_addr+head->offset);
	s = (void*)((unsigned long)p + pat_len);
	printf("VMA for the pattern is approx around 0x%llx\n", offset+head->lowaddr);
	goto rep;
    } else {
	head = head->next;
    }
  }
}

static const char *optString ="c:o:hvp:";
static const struct option longOpts[] = {
  {"core", required_argument, NULL, 0 },
  {"o", required_argument, NULL, 0 },
  {"p", required_argument, NULL, 0 },
  {"help", no_argument, NULL, 0 },
  {"version", no_argument, NULL, 0 },
  { NULL, no_argument, NULL, 0}
};

static void print_usage(void)
{
  printf("offtovma utility\n");
  printf("Allowed options: \n");
  printf("-h [ --help ]                            Display this message\n");
  printf("-c [ --core ]                            Core file name\n");
  printf("-o [ --offset ]                          Search for offset within core file\n");
  printf("-p [ --pattern ]                         Search for a pattern within the core file\n");
  printf("-e [ --exe ]                             Exe file name\n");
  printf("-v [ --version ]                         Display version information\n");
}

int main(int argc, char **argv)
{
  Elf_ctxt elf = {0};
  struct stat st;
  int retval = -1, opt = -1, longIndex;
	char core[256] = {0};
	off_t offset = 0;
	unsigned long pattern = 0;

  opt = getopt_long(argc, argv, optString, longOpts, &longIndex);
  while (-1 != opt) {
    switch(opt) {
		 case 'o':
			 offset = atol(optarg);
			 break;
		 case 'p':
			 pattern = strtol(optarg, NULL, 16);
			 break;
     case 'h':
       print_usage();
       exit(0);
       break;
     case 'v':
       fprintf(stderr, "offtovma Version 1.0 [13th Jul 2016]\n");
       exit(0);
     case 'c':
       strncpy(core, optarg, sizeof(core));
       core[256] = 0;
       break;
     case '?':
       print_usage();
       exit(0);
       break;
     case 0:
       if (!strcmp("core", longOpts[longIndex].name)) {
         strncpy(core, optarg, sizeof(core));
         core[256] = 0;
       } else if (!strcmp("offset", longOpts[longIndex].name)) {
				 offset = atol(optarg);
       } else if (!strcmp("pattern", longOpts[longIndex].name)) {
				 pattern = strtol(optarg, NULL, 16);
			 } else if (!strcmp("version", longOpts[longIndex].name)) {
         fprintf(stderr, "offtovma Version 1.0 [13th Jul 2016]\n");
         exit(0);
       } else if (!strcmp("help", longOpts[longIndex].name)) {
         print_usage();
         exit(0);
       }
       break;
     default:
       print_usage();
       exit(0);
       break;
    }
    opt = getopt_long(argc, argv, optString, longOpts, &longIndex);
  }

  if (!*core)  {
    LOG_MSG("--core is a mandatory argument\n");
    print_usage();
    exit(-1);
  } else if (!offset) {
    LOG_MSG("--offset is a mandatory argument\n");
    print_usage();
    exit(-1);
	}

  int fd = SYSCALL_EXIT_ON_ERR(open(core, O_RDONLY));
  SYSCALL_EXIT_ON_ERR(fstat(fd, &st));

  /* read the elf header from the core
   * and mmap it only if it is an elf
   */
  size_t sz = SYSCALL_EXIT_ON_ERR(read(fd, &elf, sizeof(elf.elf_ehdr)));
  if (sizeof(elf.elf_ehdr) != sz) {
    LOGERR_EXIT("Cannot read the elf header\n");
  }
  if (!IS_ELF(elf)) {
    LOGERR_EXIT("Not an ELF\n");
  }

  if (elf.e_ident[EI_CLASS] == ELFCLASS32) {
    LOG_MSG("Elf type: ELF 32-bit LSB executable, Intel 80386\n");
    elf.is32 = 1;
  } else if (elf.e_ident[EI_CLASS] == ELFCLASS64) {
    LOG_MSG("Elf type: ELF 64-bit LSB core file x86-64\n");
  } else {
    LOGERR_EXIT("Invalid elf type\n");
  }

  elf.mmap_addr = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if (elf.mmap_addr < 0) {
    LOGERR_EXIT("File mapping error\n");
  }

  load_the_load_section(&elf);

	printf("Finding vma for the offset %llu\n", offset);
	find_vma_from_offset(offset);

	if (pattern) {
	  printf("Looking for pattern %llx...\n", pattern);
	  find_pattern_in_load_segment(&elf, pattern, 4);
	}
}

