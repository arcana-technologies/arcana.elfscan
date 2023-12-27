#pragma once

#define _GNU_SOURCE

#include <assert.h>
#include <dirent.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <sys/time.h>
#include "misc.h"
#include "plugin.h"
#include "/opt/elfmaster/include/libelfmaster.h"

#define AC_COLOR_YELLOW "\033[33m"
#define AC_COLOR_RED "\033[31m"
#define AC_COLOR_GREEN "\033[32m"
#define AC_COLOR_END "\033[0m"

#define _32BIT_TEXT_BASE 0x8048000
#define _64BIT_TEXT_BASE 0x400000

#define AC_DEFAULT_CONFIG_PATH "/opt/arcana/conf/arcana.conf"
#define AC_PLUGINS_DEFAULT_DIR "/opt/arcana/plugins/"

/*
 * Entry point has been modified
 */
#define AC_ANOMALY_F_MODIFIED_EP		(1ULL <<  0)
/*
 * .ctors/.init_array has been patched
 */
#define AC_ANOMALY_F_MODIFIED_CTORS		(1ULL <<  1)
/*
 * .dtors/.fini_array has been patched
 */
#define AC_ANOMALY_F_MODIFIED_DTORS		(1ULL <<  2)
/*
 * Text segment padding infection
 */
#define AC_ANOMALY_F_TEXT_PAD_INFECTION		(1ULL <<  3)
/*
 * Reverse text infection
 */
#define AC_ANOMALY_F_TEXT_REVERSE_INFECTION	(1ULL <<  4)
/*
 * PT_NOTE converted into PT_LOAD
 */
#define AC_ANOMALY_F_PT_NOTE_CONVERSION		(1ULL <<  5)
/*
 * Extra PT_LOAD segment(s)
 */
#define AC_ANOMALY_F_PT_LOAD_MISC		(1ULL <<  6)
/*
 * Target binary was linked without glibc
 */
#define AC_ANOMALY_F_NOSTDLIB_LINKING		(1ULL <<  7)
/*
 * A .got.plt entry was hooked for hijacking code redirection
 */
#define AC_ANOMALY_F_GOTPLT_INFECTION		(1ULL <<  8)
/*
 * A .got entry was hooked, i.e. for libc_start_main hijacking
 */
#define AC_ANOMALY_F_GOT_INFECTION		(1ULL <<  9)
/*
 * __libc_start_main has been hijacked, likely in .got
 */
#define AC_ANOMALY_F_HOOKED_LIBC_START_MAIN	(1ULL << 10)
/*
 * DT_NEEDED .so injection
 */
#define AC_ANOMALY_F_NEEDED_INJECTION		(1ULL << 11)
/*
 * Section headers have been stripped (libelfmaster reconstructs them)
 */
#define AC_ANOMALY_F_STRIPPED_SHDRS		(1ULL << 12)
/*
 * Writable text segment
 */
#define AC_ANOMALY_F_WRITABLE_TEXT		(1ULL << 13)
/*
 * Executable data segment
 */
#define AC_ANOMALY_F_EXECUTABLE_DATA		(1ULL << 14)

/*
 * DT_NEEDED .so injection that is used as a static LD_PRELOAD
 * for overriding one symbol for another. i.e. system() gets
 * overrided with an evil system()
 */
#define AC_ANOMALY_F_NEEDED_STATIC_PRELOAD	(1ULL << 15)

#define AC_ANOMALY_F_INIT_HOOK			(1ULL << 16)
#define AC_ANOMALY_F_FINI_HOOK			(1ULL << 17)

#define AC_ANOMALY_F_PACKED_BINARY		(1ULL << 18)

#define AC_ANOMALY_F_POISONED_RELOC		(1ULL << 19)

#define AC_ANOMALY_F_STRAY_NEEDED_ENTRY		(1ULL << 20)

#define AC_SINGLE_OBJ(x) (x->single.obj.elfobj)
#define AC_LIST_HEAD(x) (&x->list.obj_list)


struct ac_options {
        bool config;
        bool single;
        bool dirscan;
        bool verbose;
        bool onaccess;
        bool container;
};

/*
 * CONFIG option flags
 */
typedef enum config_flags {
	AC_CONFIG_BLACKLIST =	(1 << 0),
	AC_CONFIG_PREVENT =	(1 << 1),
	AC_CONFIG_DISINFECT =	(1 << 2),
	AC_CONFIG_AGGRESSIVE = 	(1 << 3),
	AC_CONFIG_SCAN_LKMS =	(1 << 4),
	AC_CONFIG_CLASSIFY =	(1 << 5),
	AC_CONFIG_INJECTION_BLACKLIST =	(1 << 6),
	AC_CONFIG_PLUGIN_DIR =	(1 << 7),
	AC_CONFIG_LIGHTWEIGHT = (1 << 8),
	AC_CONFIG_IDS_MODE =	(1 << 9),
	AC_CONFIG_MISC = (1 << 20)
} config_flags_t;

typedef enum file_type {
	AC_FILE_EXEC = 		(1 << 0),
	AC_FILE_ELF =		(1 << 1),
	AC_FILE_SCRIPT =	(1 << 2),
	AC_FILE_BINARY =	(1 << 3),
	AC_FILE_TEXT =		(1 << 4),
	AC_FILE_UNKNOWN =	(1 << 5)
} file_type_t;

typedef struct ac_file {
	file_type_t flag;
	char *path;
	char *basename;
	SLIST_ENTRY(ac_file) _linkage;
} ac_file_t;

typedef struct ac_plugin {
	ac_file_t file;
	elfobj_t elfobj;
	ac_plugin_type_t type;
	char *name; /* ac_plugin_name_t plugin_name = "string" */
	struct elf_symbol init_sym;
	struct elf_symbol exit_sym;
	SLIST_ENTRY(ac_plugin) _linkage;
} ac_plugin_t;

typedef enum confidence_level {
	CONFIDENCE_LEVEL_LOW = 0,
	CONFIDENCE_LEVEL_MEDIUM,
	CONFIDENCE_LEVEL_HIGH,
} confidence_level_t;

typedef enum ac_entropy_bias {
	AC_ENTROPY_COMPRESSED = 0,
	AC_ENTROPY_ENCRYPTED,
	AC_ENTROPY_RANDOM
} ac_entropy_bias_t;

typedef enum ac_hooks {
	AC_HOOK_TYPE_ENTRYPOINT = 0,
	AC_HOOK_TYPE_CTORS,
	AC_HOOK_TYPE_DTORS,
	AC_HOOK_TYPE_INIT,
	AC_HOOK_TYPE_FINI,
	AC_HOOK_TYPE_NONE
} ac_hooks_t;

/*
 * Relocation hooking flags
 */
#define AC_RELOC_HOOK_ENTRYPOINT (1 << 0)
#define AC_RELOC_HOOK_CTORS	(1 << 1)
#define AC_RELOC_HOOK_DTORS	(1 << 2)
#define AC_RELOC_HOOK_PLTGOT	(1 << 3)
#define AC_RELOC_HOOK_NONE	0

typedef enum ac_so_flags {
	AC_SO_F_PLT_LINKAGE =	(1 << 0),
	AC_SO_F_RUNPATH =	(1 << 1),
	AC_SO_F_ORIGIN =	(1 << 2),
	AC_SO_F_PRELINK =	(1 << 3),
	AC_SO_F_BINDNOW =	(1 << 4)
} ac_so_flags_t;

typedef struct ac_shared_object {
	const char *basename;
	char *path;
	char *rpath;
	char *origin;
	ac_so_flags_t so_flags;
	ac_so_flags_t so_flags_missing;
	uint32_t index;
	struct {
		uint64_t base;
		size_t size;
	} range;
	LIST_ENTRY(ac_shared_object) _linkage;
} ac_shared_object_t;

/*
 * TODO
 * This whole thing must be re-abstracted.
 * No matter the type of .so injection, they should
 * ultimately be placed into one list, each node with
 * potentially different injection attributes. There's
 * some programmatic limitation to our current approach.
 */
struct so_injection_state {
	bool dt_debug_found; // Replace these bools with a flag
	bool static_ldpreload;
	bool overriden_symbol_is_weak;
	LIST_HEAD(suspicious_so_list1, ac_shared_object) suspicious_so_list;
	LIST_HEAD(suspicious_so_list2, ac_shared_object) stray_needed_list; // also suspicious. non-contiguous dt_needed entries.
	LIST_HEAD(,ac_so_plt_pair) so_plt_list;
	struct hsearch_data *plt_cache_pointer;
};

#define AC_INFECTION_STRINGS	(1 << 0)
#define AC_INFECTION_VADDRS	(1 << 1)
#define AC_INFECTION_HI_VADDR	(1 << 2)
#define AC_INFECTION_LO_VADDR	(1 << 3)
#define AC_INFECTION_HOOK_VADDR (1 << 4)
#define AC_INFECTION_HOOK_LOCATION	(1 << 5)
#define AC_INFECTION_LEN	(1 << 6)
#define AC_INFECTION_COUNT	(1 << 7)
#define AC_INFECTION_VADDR_COUNT	(1 << 8)
#define AC_INFECTION_STRCOUNT	(1 << 9)
#define AC_INFECTION_PLTGOT_INDEX	(1 << 10)
#define AC_INFECTION_RELOC		(1 << 11)

typedef enum ac_verdict {
	AC_VERDICT_CLEAN = 0,
	AC_VERDICT_SUSPICIOUS,
	AC_VERDICT_INFECTED
} ac_verdict_t;
/*
 * This struct holds various fields of data that
 * help to describe a found infection. Each found
 * infection type has its own instance of 'struct ac_infection_data'
 * to fill out, and it is stored in a linked list.
 */
typedef struct ac_infection_data
{
	char **strings; /* can be used as one more strings for arbitrary purposes */
	size_t strcount;
	uint64_t hook_location; /* Address of pointer slot for hook, i.e. got[7] */
	uint64_t *vaddr; /* can be allocated for multiple addresses if needed */
	size_t vaddr_count;
	uint64_t low_vaddr;
	uint64_t high_vaddr;
	uint64_t hook_vaddr;
	size_t len;
	uint64_t count;
	uint64_t got_index;
	uint64_t data_flags;
	struct elf_relocation rel;
} ac_infection_data_t;

#define AC_INFECTION_L1 0
#define AC_INFECTION_L2 1

struct elfobj_infection_state {
	elfobj_t *elfobj;
	const char *filepath;
	struct so_injection_state injection;
	confidence_level_t confidence;
	ac_so_flags_t so_flags;
	uint64_t anomaly_type;
	uint64_t anomaly_missed_checks;
	ac_infection_data_t infection_data[2];
	TAILQ_ENTRY(elfobj_infection_state) _linkage;
};

typedef struct obj_struct {
	elfobj_t *elfobj;
	char *filename;
	ac_verdict_t verdict;
	ac_infection_data_t infection_data[2];
	TAILQ_HEAD(, elfobj_infection_state) infection_state_list;
	LIST_HEAD(, ac_shared_object) ac_so_list;
	LIST_ENTRY(obj_struct) _linkage;
} obj_struct_t;

typedef struct arcana_ctx {
	/*
	 * Hash tables
	 */
	struct {
		struct hsearch_data obj_cache;
		struct hsearch_data so_cache;
		struct hsearch_data plt_cache;
	} cache;
	/*
	 * Linked lists
	 */
	struct {
		LIST_HEAD(obj_list, obj_struct) obj_list;
	} list;
	/*
	 * When scanning a single object
	 */
	struct {
		obj_struct_t obj;
	} single;
	uint64_t anomaly_flags;
	uint64_t anomaly_missed_checks;
	char *container;
	char *dirpath;
	char *target_file;
	char *config_path;
	struct ac_options opts;
	struct {
		FILE *fp;
		config_flags_t flags;
		const char *plugin_dir;
		const char *container_root;
		SLIST_HEAD(blacklist, ac_file) blacklist;
		SLIST_HEAD(injection_blacklist, ac_file) injection_blacklist;
		SLIST_HEAD(plugin_list, ac_plugin) plugin_list;
	} config;
} arcana_ctx_t;

/*
 * Pairs a PLT to a library path,
 * address of value it ultimately resolves to,
 * and to the target symbol binding.
 */
typedef struct ac_so_plt_pair {
	char *libpath;
	char *basename;
	char *plt_name;
	uint64_t addr;
	bool list_exists;
	uint8_t import_binding; /* Binding of the symbol the PLT entry links to */
	LIST_ENTRY(ac_so_plt_pair) _linkage;
} ac_so_plt_pair;

/*
 * obj.c
 */
bool ac_process_objects(arcana_ctx_t *);
bool ac_build_plugins(arcana_ctx_t *);
bool ac_process_layer1_plugins(arcana_ctx_t *, obj_struct_t *, void **);
bool ac_process_layer2_plugins(arcana_ctx_t *, obj_struct_t *, void **);

/*
 * heuristics.c
 */
bool ac_heuristics_checkall(arcana_ctx_t *, struct obj_struct *);

/*
 * heuristics_l2.c
 */

bool ac_heuristics_2(struct arcana_ctx *, struct obj_struct *,
    struct elfobj_infection_state *);

/*
 * util.c
 */
//void _ac_error(uint64_t, const char *, char *, ...);
#if 0
#ifndef ac_error
#define ac_error(...) \
	{\
		fprintf(stderr, "%s:#%d  ", __PRETTY_FUNCTION__, __LINE__); \
		fprintf(stderr, "__VA_ARGS__"); \
	}
#endif
#endif
typedef struct ac_array_obj ac_array_obj_t;
typedef struct ac_array_desc ac_array_desc_t;

/*
 * Utility.c
 */
bool ac_array_destroy(ac_array_desc_t *);
bool ac_array_init(ac_array_desc_t *);
bool ac_array_grow(ac_array_desc_t *, ac_array_obj_t *, void *);
char *ac_strdup(char *, arcana_ctx_t *);
void *ac_malloc(size_t, arcana_ctx_t *);
void ac_exit_cleanly(arcana_ctx_t *, int);
void ac_printf(char *, ...);
bool ac_address_in_range(uint64_t, uint64_t, uint64_t);
void ac_error(char *, ...);
void ac_alert(char *, ...);
void ac_warning(char *, ...);
/*
 * From heuristics_util.c
 */
bool ac_heuristics_confidence_level(struct elfobj_infection_state *, confidence_level_t);
void ac_heuristics_infection_set_hook_vaddr(ac_infection_data_t *, uint64_t);
void ac_heuristics_infection_set_hook_location(ac_infection_data_t *, uint64_t);
void ac_heuristics_infection_set_count(ac_infection_data_t *, uint64_t);
void ac_heuristics_infection_set_len(ac_infection_data_t *, size_t);
void ac_heuristics_infection_set_low_vaddr(ac_infection_data_t *, uint64_t);
void ac_heuristics_infection_set_high_vaddr(ac_infection_data_t *, uint64_t);
void ac_heuristics_infection_set_pltgot_index(ac_infection_data_t *, uint64_t);
bool ac_heuristics_infection_data_flag(ac_infection_data_t *, uint64_t);
bool ac_heuristics_infection_get_member(ac_infection_data_t *, uint64_t, uint32_t, void **);
void ac_heuristics_infection_set_reloc(ac_infection_data_t *, struct elf_relocation *);

static inline void
ac_heuristics_confidence_set(struct elfobj_infection_state *infection,
    confidence_level_t confidence)
{

        infection->confidence = confidence;
        return;
}
/*
 * From internal.c
 */
bool ac_internal_elf_pt_phdr(elfobj_t *, struct elf_segment *);
bool ac_internal_optimized_got_linkage(elfobj_t *, char *, struct elf_plt *);
bool ac_internal_elf_dyn_entry(elfobj_t *, uint16_t, struct elf_dynamic_entry ***,
    size_t *);
char * ac_internal_elf_shdr_name_by_address(elfobj_t *,
    uint64_t, struct elf_section *);

/*
 * From so.c
 */

bool
ac_so_process_shared_objects(arcana_ctx_t *, struct obj_struct *);

/*
 * From config.c
 */
bool ac_config_parse(arcana_ctx_t *);
bool ac_config_check(arcana_ctx_t *, config_flags_t);

/*
 * From container.c
 */
bool ac_container_ldso_cache(arcana_ctx_t *, char *, const size_t);
