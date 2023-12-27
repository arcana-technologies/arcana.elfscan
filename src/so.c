#include "arcana.h"
#include <sys/queue.h>

/*
 * Is the library prelinked?
 */
static bool
ac_so_plt_linkage(elfobj_t *elfobj, bool *result)
{

	if (elf_flags(elfobj, ELF_PLT_F) == true)
		return true;
	return false;
}

static bool
ac_so_prelinked(elfobj_t *elfobj, bool *result)
{
	elf_section_iterator_t s_iter;
	struct elf_section section;
	elf_iterator_res_t ires;

	elf_section_iterator_init(elfobj, &s_iter);
	for (;;) {
		ires = elf_section_iterator_next(&s_iter, &section);
		if (ires == ELF_ITER_ERROR) {
			ac_printf("elf_section_iterator_next() failed\n");
			return false;
		}
		if (ires == ELF_ITER_DONE)
			break;
		if (strstr(section.name, ".prelink") != NULL) {
			*result = true;
			break;
		}
	}
	if (elf_flags(elfobj, ELF_FORENSICS_F) == true && *result == false) {
		/*
		 * Its possible that the binary is stripped so another way to
		 * test for prelink is to see if the shared library has a fixed
		 * address range, which use to be standard but is now only seen
		 * (In general) if prelinking has been applied to the shared
		 * object.
		 */
		if (elf_text_base(elfobj) > 0UL) 
			*result = true;
	}
	return true;
}

static bool
ac_so_runpath(elfobj_t *elfobj, char *path, size_t len, bool *result)
{

	elf_dynamic_iterator_t d_iter;
	struct elf_dynamic_entry dynentry;
	elf_iterator_res_t ires;

	elf_dynamic_iterator_init(elfobj, &d_iter);
	for (;;) {
		ires = elf_dynamic_iterator_next(&d_iter, &dynentry);
		if (ires == ELF_ITER_DONE)
			break;
		if (ires == ELF_ITER_ERROR) {
			ac_printf("elf_dynamic_iterator_next() failed\n");
			return false;
		}
		if (dynentry.tag == DT_RUNPATH ||
		    dynentry.tag == DT_RPATH) {
			memcpy(path, elf_dynamic_string(elfobj,
			    dynentry.value), len - 1);
			path[len] = '\0';
			return true;
		}
	}
	return false;
}

static bool
ac_so_origin(elfobj_t *elfobj, char *path, size_t len, bool *result)
{

	elf_dynamic_iterator_t d_iter;
	struct elf_dynamic_entry dynentry;
	elf_iterator_res_t ires;

	elf_dynamic_iterator_init(elfobj, &d_iter);
	for (;;) {
		ires = elf_dynamic_iterator_next(&d_iter, &dynentry);
		if (ires == ELF_ITER_DONE)
			break;
		if (ires == ELF_ITER_ERROR) {
			ac_printf("elf_dynamic_iterator_next() failed\n");
			return false;
		}
#if 0
		/*
		 * Handle backwards compatibility. New versions of Linux
		 * are done with DT_FLAG using DF_ORIGIN flag set.
		 */
		if (dynentry.tag == DT_ORIGIN) {
			memcpy(path, elf_dynamic_string(elfobj,
			    dynentry.value), len - 1);
			path[len] = '\0';
			return true;
		}
#endif
		if (dynentry.tag == DT_FLAGS || dynentry.tag == DT_FLAGS_1) {
			switch(dynentry.tag) {
			case DT_FLAGS_1:
				if (dynentry.value & DF_1_ORIGIN) {
					*result = true;
					return true;
				}
				break;
			case DT_FLAGS:
				if (dynentry.value & DF_ORIGIN) {
					*result = true;
					return true;
				}
				break;
			}
		}

	}
	return false;
}

static bool
ac_so_bind_now(elfobj_t *elfobj, bool *result)
{

	elf_dynamic_iterator_t d_iter;
	struct elf_dynamic_entry dynentry;
	elf_iterator_res_t ires;

	*result = false;

	elf_dynamic_iterator_init(elfobj, &d_iter);
	for (;;) {
		ires = elf_dynamic_iterator_next(&d_iter, &dynentry);
		if (ires == ELF_ITER_DONE)
			break;
		if (ires == ELF_ITER_ERROR) {
			ac_printf("elf_dynamic_iterator_next() failed\n");
			return false;
		}
		if (dynentry.tag == DT_BIND_NOW) {
			*result = true;
			return true;
		}
		if (dynentry.tag == DT_FLAGS_1 || dynentry.tag == DT_FLAGS) {
			switch(dynentry.tag) {
			case DT_FLAGS_1:
				if (dynentry.value & DF_1_NOW) {
					ac_printf("AC_SO_BINDNOW is set for: %s\n", elf_pathname(elfobj));
					*result = true;
					return true;
				}
				break;
			case DT_FLAGS:
				if (dynentry.value & DF_BIND_NOW) {
					ac_printf("AC_SO_BINDNOW is set for: %s\n", elf_pathname(elfobj));
					*result = true;
					return true;
				}
				break;
			}
		}
	}
	return false;
}

bool
ac_so_process_object(arcana_ctx_t *ac, struct obj_struct *obj, struct elf_shared_object *elf_so)
{

	elfobj_t elfobj_so;
	bool res;
	bool prelink = false;
	elf_error_t error;
	struct ac_shared_object *ac_so = ac_malloc(sizeof(*ac_so), ac);
	char runpath[PATH_MAX + 1], origin[PATH_MAX + 1];

	res = elf_open_object(elf_so->path, &elfobj_so, ELF_LOAD_F_FORENSICS, &error);
	if (res == false) {
		ac_printf("elf_open_object(\"%s\", ...) failed: %s\n",
		    elf_so->path, elf_error_msg(&error));
		return false;
	}

	if (ac_so_prelinked(&elfobj_so, &prelink) == false) {
		ac_so->so_flags_missing |= AC_SO_F_PRELINK;
	} else if (prelink == true) {
		ac_printf("AC_SO_F_PRELINK flag set for %s\n", elf_pathname(&elfobj_so));
		ac_so->so_flags |= prelink == true ? AC_SO_F_PRELINK : 0;
		ac_so->range.base = elf_text_base(&elfobj_so);
		ac_so->range.size = /* libelfmaster needs an elf_data_memsz() function */
		    elf_data_base(&elfobj_so) + elf_data_filesz(&elfobj_so) - ac_so->range.base;
	}
	/*
	 * Get DT_RPATH/DT_RUNPATH value.
	 */
	if (ac_so_runpath(&elfobj_so, runpath, sizeof(runpath) - 1, &res) == false) {
		ac_so->so_flags_missing |= AC_SO_F_RUNPATH;
	} else if (res == true) {
		ac_so->so_flags |= AC_SO_F_RUNPATH;
		ac_so->rpath = ac_strdup(runpath, ac);
	}

	/*
	 * Look for $ORIGIN expansion variable in dynamic segment
	 */
	if (ac_so_origin(&elfobj_so, origin, sizeof(origin) - 1, &res) == false) {
		ac_so->so_flags_missing |= AC_SO_F_ORIGIN;
	} else if (res == true) {
		ac_so->so_flags |= AC_SO_F_ORIGIN;
		ac_so->origin = ac_strdup(runpath, ac);
	}
	/*
	 * Does the library have PLT linkage?
	 */
	if (ac_so_plt_linkage(&elfobj_so, &res) == false) {
		ac_so->so_flags_missing |= AC_SO_F_PLT_LINKAGE;
	} else if (res == true) {
		ac_so->so_flags |= AC_SO_F_PLT_LINKAGE;
	}

	if (ac_so_bind_now(&elfobj_so, &res) == false) {
		ac_so->so_flags_missing |= AC_SO_F_BINDNOW;
	} else if (res == true) {
		ac_so->so_flags |= AC_SO_F_BINDNOW;
	}
	LIST_INSERT_HEAD(&obj->ac_so_list, ac_so, _linkage);

	return true;
}

/*
 * We only get the top-level shared object dependencies since
 * that is all we need in order to make certain heuristic
 * decisions. We may change this down the road.
 * TODO: In heuristics.c we should be using the ac_so_list
 * of shared objects, rather than running elf_shared_object_iterator again
 */
bool
ac_so_process_shared_objects(arcana_ctx_t *ac, struct obj_struct *obj)
{
	elfobj_t *elfobj = obj->elfobj;
	elf_shared_object_iterator_t so_iter;
	elf_error_t error;
	struct elf_shared_object elf_so;
	bool res;
	char ldso_cache_path[PATH_MAX];

	LIST_INIT(&obj->ac_so_list);
	if (ac->opts.container == true) {
		ac_printf("Container in-use, updating ldso cache path\n");
		res = ac_container_ldso_cache(ac, ldso_cache_path, PATH_MAX);
		if (res == false) {
			ac_printf("Failed to determine ld.so.cache path in container %s\n", ac->container);
			return false;
		}
		ac_printf("ldso_cache_path: %s\n", ldso_cache_path);

		res = elf_shared_object_iterator_init(elfobj, &so_iter,
		    ldso_cache_path, ELF_SO_RESOLVE_F, &error);
		if (res == false) {
			ac_printf("elf_shared_object_iterator_init() failed: %s\n",
			    elf_error_msg(&error));
			return false;
		}
	} else {
		res = elf_shared_object_iterator_init(elfobj, &so_iter,
		    NULL, ELF_SO_LDSO_FAST_F|ELF_SO_IGNORE_VDSO_F|ELF_SO_RESOLVE_ALL_F, &error);
		if (res == false) {
			ac_printf("elf_shared_object_iterator_init() failed: %s\n",
			    elf_error_msg(&error));
			return false;
		}
	}
	for (;;) {
		elf_iterator_res_t res;
		res = elf_shared_object_iterator_next(&so_iter, &elf_so, &error);
		if (res == ELF_ITER_ERROR) {
			ac_printf("elf_shared_object_iterator_next failed: %s\n",
			    elf_error_msg(&error));
			return false;
		}
		if (res == ELF_ITER_DONE)
			break;
		ac_printf("Processing shared object: %s\n", elf_so.path);
		res = ac_so_process_object(ac, obj, &elf_so);
		if (res == false) {
			ac_printf("failed to process shared object: %s\n", elf_so.path);
			return false;
		}
	}
	return true;
}
