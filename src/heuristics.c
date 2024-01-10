#include "arcana.h"
#include <assert.h>

#define AC_MAX_NEEDED_LIBS 2048
#define AC_PLT_SYMBOL_HASH_SIZE 1000000

extern struct options opts;

void
ac_heuristics_set_verdict(arcana_ctx_t *ctx, ac_verdict_t verdict)
{
	struct obj_struct *obj = &ctx->single.obj;

	assert(ctx->opts.single == true);
	obj->verdict = verdict;
	return;
}

bool
ac_heuristics_verdict(arcana_ctx_t *ctx, ac_verdict_t verdict)
{
	struct obj_struct *obj = &ctx->single.obj;

	assert(ctx->opts.single == true);
	if (obj->verdict == verdict)
		return true;
	return false;
}

static const char *
ac_heuristics_confidence(confidence_level_t confidence)
{

	switch(confidence) {
	case CONFIDENCE_LEVEL_LOW:
		return (const char *)"LOW";
		break;
	case CONFIDENCE_LEVEL_MEDIUM:
		return (const char *)"MEDIUM";
		break;
	case CONFIDENCE_LEVEL_HIGH:
		return (const char *)"HIGH";
		break;
	default:
		return (const char *)"UNDEFINED";
		break;
	}
	return "UNDEFINED";
}

/*
 * NOTE: Look to see if shared libaries have duplicate symbols. But only look
 * for symbols that are actually conflicting (Which there shouldn't be).
 * Its normal for one library to have a symbol name, such as memcpy that
 * links to another library such as libc.so, but thats an import not a
 * a duplicate symbol.
 */
static bool
ac_heuristics_duplicate_dsym(elfobj_t *elfobj, const char *string, bool *result)
{
	elf_dynsym_iterator_t sym_iter;
	struct elf_symbol symbol;
	uint32_t count = 0;
	elf_iterator_res_t ires;

	*result = false;
	/*
	 * A shared library may have duplicate symbol names of different
	 * symbol types, i.e. memcpy may exist twice. Once as STT_FUNC and
	 * another as STT_IFUNC
	 */
	elf_dynsym_iterator_init(elfobj, &sym_iter);
	for (;;) {
		ires = elf_dynsym_iterator_next(&sym_iter, &symbol);
		if (ires == ELF_ITER_ERROR) {
			ac_printf("elf_symbol_iterator_next() failed\n");
			return false;
		}
		if (ires == ELF_ITER_DONE)
			break;
		if (strcmp(string, symbol.name) == 0)
			count++;
	}
	*result = count > 1 ? true : false;
	return true;
}

static bool
ac_heuristics_plt_count(elfobj_t *elfobj, uint64_t *count)
{
	elf_plt_iterator_t plt_iter;
	struct elf_plt plt;
	elf_iterator_res_t ires;
	uint64_t c = 0;
	*count = 0UL;
	/*
	 * Return number of PLT entries.
	 */
	elf_plt_iterator_init(elfobj, &plt_iter);
	for (;;) {
		ires = elf_plt_iterator_next(&plt_iter, &plt);
		if (ires == ELF_ITER_ERROR) {
			ac_printf("elf_plt_iterator_next() failed\n");
			return false;
		}
		if (ires == ELF_ITER_DONE)
			break;
		*count = ++c;
	}
	return true;
}

#if 0
static inline bool
ac_heuristics_value_is_st_func(elfobj_t *elfobj, uint64_t value)
{
	struct elf_symbol symbol;

	/*
	 * XXX probably looking for elf_symbol_by_range() --
	 * elf_symbol_by_value is deprecated.
	 */
	if (elf_symbol_by_value(elfobj, value, &symbol) == true) {
		if (symbol.type == STT_FUNC)
			return true;
	}
	return false;
}
#endif

static inline bool
ac_heuristics_so_prelinked(struct obj_struct *obj, uint64_t *base, uint64_t *size)
{
	struct ac_shared_object *current;

	LIST_FOREACH(current, &obj->ac_so_list, _linkage) {
		/*
		 * TODO, we may have more than one prelinked shared object
		 * in the future lets pass an array of structs as an out argument
		 * to fill up all of the different address ranges of the prelinking.
		 */
		if (current->so_flags & AC_SO_F_PRELINK) {
			*base = current->range.base;
			*size = current->range.size;
			return true;
		}
	}
	return false;
}

static bool
ac_heuristics_layer2(struct arcana_ctx *ac, struct obj_struct *obj)
{
	struct elfobj_infection_state *infection = NULL;
	bool res;

	ac_printf("Running L2 heuristics on %s\n", elf_pathname(obj->elfobj));
	TAILQ_FOREACH(infection, &obj->infection_state_list, _linkage) {
		res = ac_heuristics_2(ac, obj, infection);
		if (res == false) {
			ac_printf("Failed to process layer 2 heuristics on %s\n",
			    elf_pathname(obj->elfobj));
		}
	}
	ac_process_layer2_plugins(ac, obj, NULL);
	return true;
}

static bool
ac_heuristics_insert_state(struct arcana_ctx *ac, struct obj_struct *obj,
    uint64_t anomaly_type, uint64_t anomaly_missed_checks, confidence_level_t confidence,
    ac_so_flags_t so_flags, struct ac_infection_data *infdata)
{
	elfobj_t *elfobj = obj->elfobj;
	struct elfobj_infection_state *infection = ac_malloc(sizeof(*infection), ac);

	/*
	 * Set the verdict value based on each infection type and it's
	 * confidence level.
	 */
	switch(anomaly_type) {
	case AC_ANOMALY_F_MODIFIED_EP:
	case AC_ANOMALY_F_MODIFIED_CTORS:
	case AC_ANOMALY_F_MODIFIED_DTORS:
	case AC_ANOMALY_F_TEXT_PAD_INFECTION:
	case AC_ANOMALY_F_TEXT_REVERSE_INFECTION:
	case AC_ANOMALY_F_PT_NOTE_CONVERSION:
	case AC_ANOMALY_F_GOTPLT_INFECTION:
	case AC_ANOMALY_F_NEEDED_INJECTION:
	case AC_ANOMALY_F_STRAY_NEEDED_ENTRY:
	case AC_ANOMALY_F_INIT_HOOK:
	case AC_ANOMALY_F_FINI_HOOK:
	case AC_ANOMALY_F_POISONED_RELOC:
		ac_heuristics_set_verdict(ac, AC_VERDICT_INFECTED);
		break;
	case AC_ANOMALY_F_NOSTDLIB_LINKING:
	case AC_ANOMALY_F_WRITABLE_TEXT:
	case AC_ANOMALY_F_PACKED_BINARY:
	case AC_ANOMALY_F_STRIPPED_SHDRS:
		/*
		 * If it's already set to infected, don't reset it with
		 * suspicious, that would be an incorrect verdict. Only
		 * mark as suspicious if it hasn't been marked as infected
		 * yet.
		 */
		if (ac_heuristics_verdict(ac, AC_VERDICT_INFECTED) != true)
			ac_heuristics_set_verdict(ac, AC_VERDICT_SUSPICIOUS);
		break;
	default:
		break;
	}
	infection->anomaly_type = anomaly_type;
	infection->anomaly_missed_checks = anomaly_missed_checks;
	infection->elfobj = elfobj;
	infection->filepath = elf_pathname(elfobj);
	infection->confidence = confidence;
	infection->so_flags = so_flags;
	memcpy(&infection->infection_data[AC_INFECTION_L1], infdata,
	    sizeof(*infdata));
	TAILQ_INSERT_TAIL(&obj->infection_state_list, infection, _linkage);
	return true;
}

static void
ac_heuristics_display_so_injection(struct arcana_ctx *ac, elfobj_t *elfobj,
    struct so_injection_state *injection, confidence_level_t confidence)
{
	bool ignore_object = false;

	if (ac_config_check(ac, AC_CONFIG_AGGRESSIVE) == false) {
		ac_printf("Aggressive mode disabled: using less heuristics for .so detection\n");
		goto no_plt_linkage;
	}
	if (injection->static_ldpreload == true) {
		/*
		 * NOTE: Static_ldpreload is a terrible naming convention. This attack
		 * injects DT_NEEDED entries, and does not use ldpreload, although it
		 *
		 * If static ldpreload injection (symbol interposition) has been found
		 * then lets iterate over our list, and remember that PLT symbols corresponding
		 * to different libraries are recorded in individual 'struct ac_so_plt_pair' objects
		 * and stored contiguously in a linked list, i.e.
		 * [open:evil.so]<-chain->[open:libc.so]
		 * CAVEAT: In some cases this is legitimate (symbol interposition) and so
		 * the default config file for arcana blacklists certain known cases of this
		 */
		struct ac_so_plt_pair *current, *offending_lib, *next = NULL;
		offending_lib = current = LIST_FIRST(&injection->so_plt_list);
		next = LIST_NEXT(current, _linkage);
		if (ac_config_check(ac, AC_CONFIG_INJECTION_WHITELIST) == true) {
			struct ac_file *bl_obj;

			SLIST_FOREACH(bl_obj,
			    &ac->config.injection_whitelist, _linkage) {
				if (strchr(bl_obj->path, '/') == NULL) {
					if (strstr(offending_lib->libpath,
					    bl_obj->path) != NULL) {
						ignore_object = true;
					}
				} else {
					if (strcmp(offending_lib->libpath, bl_obj->path) == 0)
						ignore_object = true;
				}
			}
		}
		if (ignore_object == true)
			return;
		if (injection->overriden_symbol_is_weak == true) {
			ac_warning("ELF Object: %s <-> has a injected shared library %s\n"
			    "which is overriding PLT entry for the symbol '%s' located at %s:%#lx\n"
			    "The overriden symbol '%s' has a weak (STB_WEAK) binding in %s\n"
			    "therefore it's possible that this is a legitimate dependency linking.\n"
			    "[INFECTION TYPE: DT_NEEDED shared library injection with symbol hijacking\n"
			    "[CONFIDENCE LEVEL: %s]\n",
			    elf_pathname(elfobj), current->basename, current->plt_name,
			    next->basename, current->addr,
			    current->plt_name, next->basename, ac_heuristics_confidence(confidence));
		} else {
			ac_warning("ELF Object: %s <-> has an injected shared library %s\n"
			    "which is overriding PLT entry for the symbol '%s' located\n"
			    "at %s:%#lx\n", elf_pathname(elfobj),
			    current->basename, current->plt_name, next->basename, next->addr);
			ac_warning("[CONFIDENCE LEVEL: %s]\n", ac_heuristics_confidence(confidence));
		}
	}
	/*
	 * This will find shared objects from DT_NEEDED entries that have no
	 * PLT symbols that are found in the target executable. Which indicates
	 * that they are being hooked by something else, i.e. PLT/GOT if the
	 * shared object is built with a non-dynamic base address.
	 */
no_plt_linkage:
	ignore_object = false;
	if (LIST_EMPTY(&injection->suspicious_so_list))
		return;

	struct ac_shared_object *current;

	LIST_FOREACH(current, &injection->suspicious_so_list, _linkage) {
		if (ac_config_check(ac, AC_CONFIG_INJECTION_WHITELIST) == true) {
			struct ac_file *bl_obj;

			SLIST_FOREACH(bl_obj,
			    &ac->config.injection_whitelist, _linkage) {
				if (strchr(bl_obj->path, '/') == NULL) {
					if (strstr(current->path,
					    bl_obj->path) != NULL) {
						ignore_object = true;
					}
				} else {
					if (strcmp(current->path,
					    bl_obj->path) == 0)
						ignore_object = true;
				}
			}
		}
		if (ignore_object == true) {
			ignore_object = false;
			continue;
		}
		ac_printf("ELF Object: %s <-> Injected shared library [%s : %s] via DT_NEEDED\n"
		    "-- No PLT linkage found\n",
		    elf_pathname(elfobj), current->basename, current->path);
	}
}


static inline bool
ac_get_flag(struct arcana_ctx *ac, uint64_t flag)
{

	return ac->anomaly_flags & flag;
}

static inline void
ac_set_flag(struct arcana_ctx *ac, uint64_t flag)
{

	ac->anomaly_flags |= flag;
	return;
}

static inline void
ac_set_missing(struct arcana_ctx *ac, uint64_t flag)
{

	ac->anomaly_missed_checks |= flag;
	return;
}

static bool
ac_heuristics_check_stripped_elf(struct arcana_ctx *ac,
    elfobj_t *elfobj, bool *result)
{
	*result = elf_flags(elfobj, ELF_FORENSICS_F) == true ?
	    true : false;
	return true;
}

#define MAX_CHAR_LEN (1 << 8)
#define MAX_SCAN_LEN (8192 << 2)
#define ENTROPY_ENCRYPTED_THRESHOLD 6.0
#define ENTROPY_COMPRESSED_THRESHOLD 7.0

/*
 * Calculate the entropy of an ELF file, starting
 * from the offset after the program header table.
 *
 */
static bool
ac_heuristics_packed_elf(struct arcana_ctx *ac,
    elfobj_t *elfobj, bool *result, ac_entropy_bias_t *bias)
{
	uint8_t *mem = elfobj->mem;
	size_t filesz;
	size_t phdr_size = elf_class(elfobj) == elfclass32 ?
	    sizeof(Elf32_Phdr) : sizeof(Elf64_Phdr);
	uint64_t offset = elf_phoff(elfobj) + elf_segment_count(elfobj) * phdr_size;
	filesz = elf_size(elfobj) - offset;
	float *bv_array = malloc(filesz * sizeof(float));
	float entropy;
	int i, j, c;
	int a = 0;
	struct timeval tv, tv2;

	*result = false;

	/*
	 * If we are in lightweight mode we can make the assumption
	 * that if the first 16k bytes of the text segment are
	 * high in entropy then so is the rest of the file. Otherwise
	 * we will lose performance by scanning the entire file.
	 */
	if (ac_config_check(ac, AC_CONFIG_LIGHTWEIGHT) == true) {
		ac_printf("Lightweight mode: Truncating scan to %zu bytes"
		    " for entropy analysis\n", MAX_SCAN_LEN);
		if (filesz > MAX_SCAN_LEN) {
			/*
			 * TODO sanity check offset is not larger
			 * than MAX_SCAN_LEN creating an integer
			 * overflow
			 */
			filesz = MAX_SCAN_LEN - offset;
		}
	}
	mem += offset;

	gettimeofday(&tv, NULL);
	for (i = 0; i < MAX_CHAR_LEN; i++) {
		c = 0;

		for (j = 0; j < filesz; j++) {
			if (mem[j] == i)
				c++;
		}
		bv_array[a++] = (float)c / filesz;
	}
	entropy = 0.0;
	for (i = 0; i < a; i++) {
		if (bv_array[i] > 0)
			entropy = entropy + bv_array[i] * log2f(bv_array[i]);
	}
	entropy = -entropy;
	gettimeofday(&tv2, NULL);

	ac_printf("Calculated entropy: (%f) in %zu.%zu seconds\n",
	    entropy, tv2.tv_sec - tv.tv_sec, tv2.tv_usec - tv.tv_usec);
	ac_printf("Calculated entropy: %f\n", entropy);

	if (entropy >= ENTROPY_ENCRYPTED_THRESHOLD &&
	    entropy < ENTROPY_COMPRESSED_THRESHOLD) {
		*result = true;
		*bias = AC_ENTROPY_ENCRYPTED;
		ac_printf("Entropy bias: encrypted\n");
	} else if (entropy >= ENTROPY_COMPRESSED_THRESHOLD) {
		*result = true;
		*bias = AC_ENTROPY_COMPRESSED;
		ac_printf("Entropy bias: compressed\n");
	}
	return true;
}

static bool
ac_heuristics_executable_data(struct arcana_ctx *ac, struct obj_struct *obj,
    elfobj_t *elfobj, bool *result)
{
	/*
	 * XXX elf_data_base() is currently broken in libelfmaster
	 * so use the iterator to find data segment temporarily for
	 * demo.
	 */
	struct elf_segment segment;
	*result = false;

	if (elf_data_segment(elfobj, &segment) == false)
		return false;
	if (segment.flags & PF_X)
		*result = true;
	return true;
}

/*
 * Relocation hooking detection
 *
 * TODO:
 * - Support .fini_array patch detection 
 * - Support .got.plt patch detection
 * This will detect the poisoning of ELF relocation entries.
 * Currently we're only looking at RELATIVE relocations.
 */
static bool
ac_heuristics_relocation_hooks(struct arcana_ctx *ac, elfobj_t *elfobj,
    struct ac_infection_data *infdata, bool *result)
{
	struct elf_relocation_iterator r_iter;
	struct elf_relocation r_entry;
	struct elf_section ctors_shdr, init, text;
	bool res;

	*result = false;

	/*
	 * XXX: should be fixed in libelfmaster, re-namespaced to
	 * elf_typewidth_t
	 */
	typewidth_t width;
	uint64_t addend;

	if (elf_relocation_iterator_init(elfobj, &r_iter) == false) {
		ac_printf("elf_relocation_iterator_init() failed\n");
		return false;
	}
	if (elf_section_by_name(elfobj, ".init", &init) == false) {
		ac_printf("elf_section_by_name(%p, \".init\", ...) failed\n",
		    elfobj);
		return false;
	}
	if (elf_section_by_name(elfobj, ".text", &text) == false) {
		ac_printf("elf_section_by_name(%p, \".text\", ...) failed\n",
		    elfobj);
	}
	/*
	 * Check RELATIVE relocations first. Technically any relocation
	 * can be exploited by an attacker to patch the binary at runtime.
	 * In particular we are looking for .ctors/.dtors hooks.
	 * In the future we will add much more in this area of detecting.
	 */
	if (elf_flags(elfobj, ELF_FULL_PIE_F) == true) {
		while (elf_relocation_iterator_next(&r_iter, &r_entry)
		    == ELF_ITER_OK) {
			if (r_entry.type != R_X86_64_RELATIVE &&
			    r_entry.type != R_386_RELATIVE)
				continue;
			/*
			 * Dereference r_offset to get the offset/addend
			 * from the relocation unit. A RELATIVE
			 * relocation will compute this by adding
			 * the offset to the base address.
			 */
			width = elf_class(elfobj) == elfclass32 ? ELF_DWORD :
			    ELF_QWORD;
			if (elf_section_by_name(elfobj, ".init_array",
			    &ctors_shdr) == false) {
				if (elf_section_by_name(elfobj, ".ctors",
				    &ctors_shdr) == false) {
					ac_printf("elf_section_by_name(%p, \".init_array\", ...)"
					    " failed\n");
					return false;
				}
			}
			if (r_entry.offset >= ctors_shdr.address &&
			    r_entry.offset < ctors_shdr.address + ctors_shdr.size) {
				res = elf_read_address(elfobj, r_entry.offset,
				    &addend, width);
				if (res == false) {
					ac_printf("elf_read_address() "
					    "failed\n");
					return false;
				}
				/*
				 * Note in 32bit ELF the relocation addend is always retrieved
				 * from the deferenced r_offset location. On 64bit it is stored
				 * in the r_addend member of ElfN_Rel AND in the r_offset location,
				 * however the dynamic linker only uses r_addend with 64bit and ignores
				 * the addend stored in the actual binary. 32bit on the other hand
				 * uses it.
				 */
				if (ac_address_in_range(addend, text.address,
				    text.address + text.size) == false &&
				    ac_address_in_range(addend, init.address,
				    init.address + init.size) == false) {
					if (elf_machine(elfobj) == EM_X86_64) {
						if (ac_address_in_range(r_entry.addend,
						    text.address,
						    text.address + text.size)
						    == false &&
						    ac_address_in_range(r_entry.addend,
						    init.address,
						    init.address + init.size)
						    == false) {
							ac_heuristics_infection_set_hook_vaddr(infdata,
							    r_entry.addend);
							ac_heuristics_infection_set_reloc(infdata, &r_entry);
							*result = true;
						}
					} else if (elf_machine(elfobj) == EM_386) {
						ac_heuristics_infection_set_hook_vaddr(infdata,
						    addend);
						ac_heuristics_infection_set_reloc(infdata,
						    &r_entry);
						*result = true;
					}
					continue;
				}

				if (elf_arch(elfobj) == x64 &&
				    addend != r_entry.addend) {
					/*
					 * Sure sign of poisoning
					 * on ELF x86_64
					 *
					 * This means the reloc entry
					 * has been modified. The
					 * addend doesn't match the
					 * addend value in the reloc
					 * unit.
					 */
					ac_heuristics_infection_set_hook_vaddr(infdata,
					    r_entry.addend);
					ac_heuristics_infection_set_reloc(infdata,
					    &r_entry);
					*result = true;
				}
			}
		}
	}
	return true;
}

/*
 * Detect DT_INIT/DT_FINI infection
 * This is tricky because if we forensically reconstruct a stripped binary
 * with libelfmaster, it will create a section header for .init and it gets
 * that information from the DT_INIT tag, which may be infected. So what we
 * do is see if the sh_address points into any other sections, and if not
 * does it point outside of the reconstructed sections? Or if the binary is
 * not stripped it simply has to detect a discrepency between the address of
 * .init and DT_INIT which is much easier. Same detection goes for DT_FINI
 */
#define AC_DT_INIT 0
#define AC_DT_FINI 1

static bool
ac_heuristics_init_hook(struct arcana_ctx *ac, struct obj_struct *obj,
    elfobj_t *elfobj, struct ac_infection_data *infdata, uint32_t which, bool *result)
{

	elf_iterator_res_t ires;
	elf_dynamic_entry_t d_entry;
	elf_dynamic_iterator_t d_iter;
	elf_section_iterator_t s_iter;
	elf_segment_iterator_t p_iter;
	struct elf_section shdr;
	struct elf_segment segment;
	const uint32_t dyn_tag = (which == AC_DT_INIT ? DT_INIT : DT_FINI);
	char *section_name = (which == AC_DT_INIT ? ".init" : ".fini");
	uint64_t init_vaddr;
	bool reversed_text_section = false;

	*result = false;

	elf_dynamic_iterator_init(elfobj, &d_iter);
	for (;;) {
		ires = elf_dynamic_iterator_next(&d_iter, &d_entry);
		if (ires == ELF_ITER_DONE)
			break;
		if (ires == ELF_ITER_ERROR)
			return false;
		if (d_entry.tag != dyn_tag)
			continue;
		init_vaddr = d_entry.value;
		break;
	}

	ac_heuristics_infection_set_hook_vaddr(infdata, init_vaddr);

	if (elf_section_by_name(elfobj, section_name, &shdr) == false)
		return false;

	if (elf_flags(elfobj, ELF_FORENSICS_F) == false) {
		/*
		 * The binary is not stripped (no forensics
		 * for reconstruction section headers was
		 * performed).
		 */
		*result = shdr.address != init_vaddr ? true : false;
		return true;
	}
	/*
	 * This part of the function works on binaries that have been
	 * stripped of their section header table-- the reconstructed
	 * .init section will have the same address as DT_INIT since that
	 * is how it found the address to DT_INIT, so we cannot simply
	 * compare them as it will show up as a false positive since
	 * they will match.
	 */
	elf_section_iterator_init(elfobj, &s_iter);
	for (;;) {
		ires = elf_section_iterator_next(&s_iter, &shdr);
		if (ires == ELF_ITER_DONE)
			break;
		if (ires == ELF_ITER_ERROR)
			return false;
		/*
		 * !!!HANDLING STRIPPED ELF BINARY WITH DT_INIT/DT_FINI HOOKS!!!
		 *
		 * Look for section header names that do not
		 * compare true to ".init" (Or ".fini") and
		 * if the reconstructed .init/.fini section
		 * address points inside of another section
		 * then its likely been infected. This is because
		 * the forensics reconstruction of libelfmaster
		 * uses DT_INIT to learn the address it should use
		 * for .init, which if infected will be pointing into
		 * a section range other than the original .init section
		 * before the binary was stripped.
		 *
		 * NOTE: If there is a reverse text padding infection that
		 * we've already detected, and we find that .init is overlapping
		 * with .text... then we don't flag a DT_INIT infection here.
		 */
		if (strcmp(shdr.name, section_name) != 0) {
			if (init_vaddr >= shdr.address &&
			    init_vaddr < shdr.address + shdr.size) {
				/*
				 * .init section is sharing an address range with
				 * another section...
				 *
				 * If it is .text with an existing reverse infection
				 * we ignore the situation.
				 *
				 * NOTE: This caveat only applies if we're looking at .init
				 * because it exists before the .text section and therefore
				 * the reverse text extension will include it in its range.
				 * This won't apply to .fini which exists after the .text.
				 * So we check: which == AC_DT_INIT
				 */
				if (which == AC_DT_INIT && (strcmp(shdr.name, ".text") == 0) &&
				    ac_get_flag(ac, AC_ANOMALY_F_TEXT_REVERSE_INFECTION)) {
					reversed_text_section = true;
					continue;
				}

				/*
				 * Otherwise we mark this as true/infected.
				 */
				*result = true;
				return true;
			}
		}
	}
	/*
	 * If we made it here then several conditions have been met:
	 * 1. The target ELF is stripped and was reconstructed by libelfmaster
	 * 2. We have not been able to yet identify whether DT_INIT has been hooked.
	 */
	if (which == AC_DT_INIT && reversed_text_section == true) {
		/*
		 * If the text section is reverse-infected and was sharing
		 * an address range with .init, while the binary is also
		 * stripped then we have no way to detect a hooked DT_INIT
		 * unless we do code fingerprinting. Save the code finger
		 * printing for future plugins.
		 */
		*result = false;
		return true;
	}
	if (which == AC_DT_FINI &&
	    ac_get_flag(ac, AC_ANOMALY_F_TEXT_REVERSE_INFECTION)) {

		*result = false;
		return true;
	}
	/* DT_INIT does not point inside of any section we see...
	 * If we made it here than lets check to see if the address
	 * atleast points into a valid memory range, otherwise its
	 * a broken binary, not a hooked/malicious one.
	 */
	elf_segment_iterator_init(elfobj, &p_iter);
	for (;;) {
		ires = elf_segment_iterator_next(&p_iter, &segment);
		if (ires == ELF_ITER_DONE)
			break;
		if (ires == ELF_ITER_ERROR)
			return false;
		if (segment.type != PT_LOAD)
			continue;
		if (init_vaddr >= segment.vaddr &&
		    init_vaddr < segment.vaddr + segment.memsz) {
			*result = true;
			return true;
		}
	}
	return true;
}
/*
 * TODO This is the first layer heuristics engine, another pass will be done in
 * the second layer heuristics to take into consideration .got.plt mods that
 * point into PT_NOTE to PT_LOAD 
 * conversions, and data segment infections.
 * TODO Handle gathering data about multiple hooked locations vs. just the
 * first one found.
 */
static bool
ac_heuristics_got_plt_hooks(struct arcana_ctx *ac, struct obj_struct *obj,
    elfobj_t *elfobj, struct ac_infection_data *infdata, bool *result)
{
	elf_iterator_res_t ires;
	elf_pltgot_iterator_t pltgot_iter;
	struct elf_pltgot_entry pltgot;
	size_t base, size;
	struct elf_section plt_shdr;
	uint64_t plt_count = 0, got_index = 0;
	int64_t real_got_index = -1;

	*result = false;

	if (elf_section_by_name(elfobj, ".plt", &plt_shdr) == false) {
		ac_printf("elf_section_by_name(%p, \".plt\", ...) failed\n");
		return false;
	}

	if (ac_heuristics_plt_count(elfobj, &plt_count) == false) {
		ac_printf("ac_heuristics_plt_count() failed\n");
		return false;
	}
	elf_pltgot_iterator_init(elfobj, &pltgot_iter);
	for (;;) {
		ires = elf_pltgot_iterator_next(&pltgot_iter, &pltgot);
		if (ires == ELF_ITER_ERROR) {
			ac_printf("elf_pltgot_iterator_next() failed\n");
			return false;
		}
		if (ires == ELF_ITER_DONE)
			break;
		real_got_index++;
		/*
		 * plt_count - 1, because we don't want to count
		 * PLT-0, since this is a stub pointed to only by
		 * .got.plt[2] e.g. __dl_resolve()
		 */
		if (got_index >= plt_count - 1)
			break;
		if (pltgot.flags == ELF_PLTGOT_RESERVED_DYNAMIC_F ||
		    pltgot.flags == ELF_PLTGOT_RESERVED_LINKMAP_F ||
		    pltgot.flags == ELF_PLTGOT_RESERVED_DL_RESOLVE_F) {
			continue; /* We don't goto next here because we don't want to increment got_index
				   * since the first 3 entries are reserved they don't count for what
				   * we are looking for.
				   */
		}
		if (ac_config_check(ac, AC_CONFIG_IDS_MODE) == true) {
			if (ac_heuristics_so_prelinked(obj, &base, &size) == true) {
				if (pltgot.value >= base && pltgot.value < base + size) {
					goto next;
				}
			}
		}
		/*
		 * If its a valid PLT stub address then continue looking
		 */
		if (pltgot.value >= plt_shdr.address &&
		    pltgot.value < plt_shdr.address + plt_shdr.size) {
			goto next;
		}
		if (pltgot.value >= elf_text_base(elfobj) &&
		    pltgot.value < elf_text_base(elfobj) + elf_scop_text_filesz(elfobj)) {
			ac_heuristics_infection_set_hook_location(infdata, pltgot.offset);
			ac_heuristics_infection_set_hook_vaddr(infdata, pltgot.value);
			ac_heuristics_infection_set_pltgot_index(infdata, (uint64_t)real_got_index);
			*result = true;
			return true;
		}
next:
		got_index++;
		continue;
	}
	return true;
}
/*
 * Detects whether or not a binary has had its PT_NOTE converted to a PT_LOAD
 */
static bool
ac_heuristics_pt_note_conversion(arcana_ctx_t *ac, elfobj_t *elfobj,
    ac_infection_data_t *infdata, bool *result)
{
	struct elf_segment segment;
	elf_segment_iterator_t p_iter;
	bool scop_binary = elf_flags(elfobj, ELF_SCOP_F);
	elf_iterator_res_t ires;
	uint32_t load_count = 0;
	uint64_t vaddr;
	size_t segment_size;

	*result = false;

	elf_segment_iterator_init(elfobj, &p_iter);
	for (;;) {
		ires = elf_segment_iterator_next(&p_iter, &segment);
		if (ires == ELF_ITER_ERROR) {
			ac_printf("elf_segment_iterator_next() failed\n");
			return false;
		}
		if (ires == ELF_ITER_DONE)
			break;

		if (segment.type == PT_NOTE) {
			*result = false;
			goto done;
		}
		if (segment.type == PT_LOAD) {
			vaddr = segment.vaddr;
			segment_size = segment.filesz;
			load_count++;
		}
	}
	/*
	 * If we made it here then we know that there is no PT_NOTE segment.
	 * TODO: scop_binary will be true in the event that the text is broken
	 * up into 2 load segments instead of 3. Currently arcana doesn't take
	 * this into consideration.
	 */
	if (scop_binary == true) {
		*result = load_count > 4 ? true : false;
	} else {
		*result = load_count > 2 ? true : false;
	}
	ac_heuristics_infection_set_count(infdata, load_count);
	ac_heuristics_infection_set_low_vaddr(infdata, vaddr);
	ac_heuristics_infection_set_high_vaddr(infdata, vaddr + segment_size);
	ac_heuristics_infection_set_len(infdata, segment_size);
done:
	return true;
}

/*
 * The heuristics functions all return true/false based on whether
 * or not they functionally succeed. (Some of them will always succeed
 * but we still set a bool return value out of convention).
 * 3rd argument: "bool *result" is set to whether the heuristic check
 * passes (returns false) or fails (returns true).
 */
static bool
ac_heuristics_nostdlib(arcana_ctx_t *ac, elfobj_t *elfobj, bool *result)
{
	struct elf_symbol sym;
	bool res;
	const char *basename;

	*result = false;

	if (elf_linking_type(elfobj) == ELF_LINKING_STATIC_PIE) {
		/*
		 * If the linking type is static pie, and we find
		 * no _start symbol to begin with, then lets lean
		 * with the high likelyhood that this is not a -nostdlib
		 * compiled/linked binary because the _start symbol does
		 * not exist, infact there is only a .dynsym symbol table
		 * in static PIE's built with -static-pie-- this behavior
		 * can differ in other variations of static PIE though.
		 * NOTE: This addresses part of the issue in the bug:
		 * https://github.com/arcana-technologies/elf.arcana/issues/5
		 */
		if (elf_symbol_by_name(elfobj, "_start", &sym) == false) {
			*result = false;
			return true;
		}
	}
	/*
	 * We do not perform this check on shared library objects since
	 * many of them have a legitimate reason to be linked this way.
	 */
	basename = elf_basename(elfobj);
	if (basename == NULL)
		return false;

	if (strstr(basename, ".so") != NULL) {
		if (elf_type(elfobj) == ET_DYN) {
			*result = false;
			return true;
		}
	}
	/*
	 * If the binary isn't stripped, it should still have a .symtab/.strtab sections
	 * containing symbol data for initialization functions. A binary built with '-nostdlib'
	 * will have no standard glibc initialization code.
	 */
	if (elf_flags(elfobj, ELF_SYMTAB_F) == true) {
		res = elf_symbol_by_name(elfobj, "__libc_start_main", &sym);
		if (res == false)
			*result = true; /* -nostdlib linking is present */
		return true;
	}
	return false;
}

static bool
ac_heuristics_entrypoint(arcana_ctx_t *ac, elfobj_t *elfobj,
    struct ac_infection_data *infdata, bool *result)
{
	uint64_t ep;
	struct elf_section shdr;
	bool res;
	size_t elf_hdr_sz = elf_class(elfobj) ==
	    elfclass32 ? sizeof(Elf32_Ehdr) : sizeof(Elf64_Ehdr);

	*result = false;

	if (elf_entry_point(elfobj) < elf_hdr_sz)
		return false;

	res = elf_section_by_name(elfobj, ".text", &shdr);
	if (res == false)
		return false;

	ep = elf_entry_point(elfobj);
	if (ep < shdr.address || ep >= shdr.address + shdr.size) {
		*result = true; /* ep has been modified */
		ac_heuristics_infection_set_hook_vaddr(infdata, ep);
		return true;
	}
	*result = false;
	return true;
}

static bool
ac_heuristics_reverse_text_infection(arcana_ctx_t *ac, elfobj_t *elfobj,
    ac_infection_data_t *infdata, bool *result, confidence_level_t *confidence)
{
	uint64_t text_base;
	uint64_t entry_point;
	struct elf_segment segment;

	*result = false;

	if (elf_flags(elfobj, ELF_FULL_PIE_F) == true) {
		/*
		 * Has a text segment vaddr of 0x0 which
		 * is not compatible with reverse text infections.
		 */
		*result = false;
		return true;
	} else {
		/*
		 * We use elf_executable_text_base() because it is
		 * SCOP friendly, whereas elf_text_base() is deprecated
		 * (unofficially) from libelfmaster.
		 */
		text_base = elf_executable_text_base(elfobj);
		entry_point = elf_entry_point(elfobj);

		switch(elf_class(elfobj)) {
		case elfclass32:
			/*
			 * Heuristics (Reverse text padding detection)
			 * By this point The executable is not PIE with a base of zero.
			 * If p_vaddr of the text segment is less than _32BIT_TEXT_BASE &&
			 * If the p_vaddr is aligned by a PAGE_SIZE its quite possibly infected
			 * which we would declare with CONFIDENCE_LEVEL_MEDIUM-- if it is not
			 * aligned then we would say the confidence is low.
			 * If the ehdr->entry points to p_vaddr of PT_PHDR + sizeof(ElfN_Phdr)
			 * Then the confidence level becomes high.
			 */
			if (text_base >= _32BIT_TEXT_BASE) {
				*result = false;
				return true;
			}
			if ((text_base % 0x1000) != 0) {
				*result = false;
				return true;
			}
			/*
			 * We can typically rely on PT_PHDR p_offset being updated--
			 * because this type of infection shifts it forward to live
			 * right after the new carved out reverse text area.
			 * [ehdr][reverse_text_area][phdr][original text content]
			 * so lets see if the entry_point has been modified to point
			 * to code right after the elf_header which is where it
			 * usually lives. Lets also see if its been hooked to
			 * point directly after the program header table, in
			 * which case it could possibly then jump/hook back to
			 * the reverse text padding area right after the elf_header.
			 */
			if (elf_segment_by_p_type(elfobj, PT_PHDR,
			    &segment) == false) {
				return false;
			}

			if (entry_point < segment.vaddr || entry_point == text_base + elf_ehsize(elfobj)) {
				ac_heuristics_infection_set_low_vaddr(infdata,
				    text_base);
				ac_heuristics_infection_set_high_vaddr(infdata,
				    text_base + elf_phoff(elfobj));
				*confidence = CONFIDENCE_LEVEL_HIGH;
				*result = true;
			} else if (segment.vaddr - text_base > elf_ehsize(elfobj)) {
				/*
				 * Confidence is Subject to change if we find
				 * that there is a hook in ctors pointing to
				 * this area, or some other hook.
				 */
				ac_heuristics_infection_set_low_vaddr(infdata,
				    text_base);
				ac_heuristics_infection_set_high_vaddr(infdata,
				    text_base + elf_phoff(elfobj));
				*confidence = CONFIDENCE_LEVEL_MEDIUM;
				*result = true;
			}
			return true;
		case elfclass64:
			if (text_base >= _64BIT_TEXT_BASE) {
				*result = false;
				return true;
			}
			if ((text_base % 0x1000) != 0) {
				*result = false;
				return true;
			}
			if (elf_segment_by_p_type(elfobj, PT_PHDR,
			    &segment) == false) {
				return false;
			}
			if (entry_point < segment.vaddr || entry_point == text_base + elf_ehsize(elfobj)) {
				ac_heuristics_infection_set_low_vaddr(infdata,
				    text_base);
				ac_heuristics_infection_set_high_vaddr(infdata,
				    text_base + elf_phoff(elfobj));
				*confidence = CONFIDENCE_LEVEL_HIGH;
				*result = true;
			} else if (segment.vaddr - text_base > elf_ehsize(elfobj)) {
				/*
				 * Subject to change if we find that
				 * there is a hook in ctors pointing to
				 * this area.
				 */
				ac_heuristics_infection_set_low_vaddr(infdata,
				    text_base);
				ac_heuristics_infection_set_high_vaddr(infdata,
				    text_base + elf_phoff(elfobj));
				*confidence = CONFIDENCE_LEVEL_MEDIUM;
				*result = true;
			}
			return true;
		}
	}
	return true;
}

static bool
ac_heuristics_text_padding(arcana_ctx_t *ac, elfobj_t *elfobj, ac_infection_data_t *infdata,
    bool *result, confidence_level_t *confidence)
{
	struct elf_section section;
	elf_section_iterator_t s_iter;
	uint64_t text_base, data_base, last_section_offset, last_section_addr;
	size_t last_section_size;
	ssize_t text_filesz;
	elf_iterator_res_t ires;
	bool res;
	bool section_reconstruction = elf_flags(elfobj, ELF_FORENSICS_F) == true ?
		true : false;
	size_t c = 0;

	*result = false;

	/*
	 * We want the first PT_LOAD segment which may be read-only if its a
	 * SCOP binary. See my paper
	 * https://github.com/elfmaster/scop_virus_paper to understand various
	 * infection types within SCOP (secure code partitioned) ELF
	 * executables.
	 */
	text_base = elf_executable_text_base(elfobj);
	text_filesz = elf_executable_text_filesz(elfobj);
	data_base = elf_data_base(elfobj);

	if (section_reconstruction == false &&
	    elf_flags(elfobj, ELF_SHDRS_F) == false) {
		*result = false;
		return false;
	}
	/*
	 * This first '.eh_frame technique' won't work on ELF_SCOP_F binaries
	 * because .eh_frame won't be in the R+X segment, but rather in the
	 * following segment which is only read-only. The last section in
	 * the executable region of a SCOP ELF binary is usually .fini
	 */
	if (elf_flags(elfobj, ELF_SCOP_F) == true) {
		res = elf_section_by_name(elfobj, ".fini", &section);
	} else {
		res = elf_section_by_name(elfobj, ".eh_frame", &section);
	}
	if (res == true) {
		if (elf_entry_point(elfobj) >= section.address &&
		    elf_entry_point(elfobj) < section.address + section.size) {
			*result = true;
			if (section.address + section.size == text_base +
			    text_filesz) {
				/*
				 * This indicates that the section's sh_size was
				 * intentionally extended to house the entire
				 * parasite. This is typically done so that the
				 * Virus is strip safe. (i.e. strip utility will
				 * remove any data not housed by a section.
				 */
				*confidence = CONFIDENCE_LEVEL_HIGH;
			} else {
				/*
				 * The .eh_frame section is not the last section
				 * in the text segment. Its possible that a phony
				 * section was added that looks like its the last
				 * section but doesn't really exist. In this case
				 * we will file a confidence level of medium.
				 */
				*confidence = CONFIDENCE_LEVEL_MEDIUM;
			}
			ac_heuristics_infection_set_low_vaddr(infdata,
			    section.address);
			ac_heuristics_infection_set_high_vaddr(infdata,
			    section.address + section.size);
			return true;
		}
	}
	/*
	 * In the case of section reconstruction its possible
	 * we weren't able to reconstruct the section that the
	 * parasite (or data) lives in. The padding is always
	 * added into the last section within the text segment.
	 * A naive virus implementation might not extend the last
	 * section header to make room for the parasite, which would
	 * make the virus non-strip-safe, so we should account for
	 * that scenario too.
	 */
	elf_section_iterator_init(elfobj, &s_iter);
	for (;;) {
		ires = elf_section_iterator_next(&s_iter, &section);
		if (ires == ELF_ITER_ERROR)
			return false;
		if (ires == ELF_ITER_DONE)
			break;
		if (c++ == 0)
			last_section_offset = section.offset;


		if (section.address + section.size == text_base + text_filesz) {
			/*
			 * we found the last section of the text segment
			 */
			if (elf_entry_point(elfobj) >= section.address &&
			    elf_entry_point(elfobj) < section.address + section.size) {
				*result = true;
				*confidence = CONFIDENCE_LEVEL_HIGH;
				ac_heuristics_infection_set_low_vaddr(infdata,
				    section.address);
				ac_heuristics_infection_set_high_vaddr(infdata,
				    section.address + section.size);
				return true;
			}
		}
		if (section.type == SHT_PROGBITS && (section.flags & SHF_ALLOC) &&
		    (section.address < text_base + text_filesz) &&
		    last_section_offset < section.offset) {
			last_section_addr = section.address;
			last_section_offset = section.offset;
			last_section_size = section.size;
		}
	}
	/*
	 * In the case that the parasite exists outside of the range of the
	 * last SHT_PROGBITS section header, which is most likely going to
	 * occur when the virus didn't adjust the last section headers size
	 * or when we aren't able to reconstruct every section (Within libelfmaster)
	 */
	if (last_section_offset + last_section_size < text_base + text_filesz) {
		struct elf_section interp_section;

		// If this last section was the .interp section, ignore this as it
		// likely isn't a text infection - should be scanned some other way
		// this was observed through past testing of false positives.
		res = elf_section_by_name(elfobj, ".interp", &interp_section);
		if (elf_entry_point(elfobj) >
		    last_section_addr + last_section_size &&
		    elf_entry_point(elfobj) < data_base &&
			(!res || last_section_addr != interp_section.address)) {
			*result = true;
			*confidence = CONFIDENCE_LEVEL_HIGH;
			ac_heuristics_infection_set_low_vaddr(infdata,
			    last_section_addr);
			ac_heuristics_infection_set_high_vaddr(infdata,
			    last_section_addr + last_section_size);
			return true;
		}
	}
	return true;
}

/*
 * Has .ctors or .dtors been modified?
 */
#define AC_CTORS 0x1
#define AC_DTORS 0x2

static bool
ac_heuristics_ctors(arcana_ctx_t *ac, elfobj_t *elfobj,
    ac_infection_data_t *infdata, uint32_t which, bool *result)
{
	size_t ctors_ent_size, i;
	uint64_t ctors_addr, v;
	bool res;
	struct elf_section ctors, text, init;
	char *name1 = which == AC_CTORS ? ".ctors" : ".dtors";
	char *name2 = which == AC_CTORS ? ".init_array" : ".fini_array";

	*result = false;

	res = elf_section_by_name(elfobj, name1, &ctors);
	if (res == false) { /* .ctors also marked as .init_array */
		res = elf_section_by_name(elfobj, name2, &ctors);
		if (res == false)
			return false;
	}
	res = elf_section_by_name(elfobj, ".text", &text);
	if (res == false)
		return false;
	if (which == AC_CTORS) {
		res = elf_section_by_name(elfobj, ".init", &init);
		if (res == false)
			return false;
	} else if (which == AC_DTORS) {
		res = elf_section_by_name(elfobj, ".fini", &init);
		if (res == false)
			return false;
	}
	/*
	 * Get .ctors entry size based on elfclass otherwise
	 * we could run into a malware author who sets the entsize
	 * to zero to obscure information about it.
	 */
	ctors_ent_size = elf_class(elfobj) == elfclass32 ?
	    sizeof(uint32_t) : sizeof(uint64_t);
	ctors_addr = ctors.address;

	for (i = 0; i < ctors.size; i += ctors_ent_size) {
		if (elf_class(elfobj) == elfclass32) {
			res = elf_read_address(elfobj, ctors_addr + i, &v,
			    ELF_DWORD);
			if (res == false) /* Invalid memory */
				return false;
		} else {
			res = elf_read_address(elfobj, ctors_addr + i, &v,
			    ELF_QWORD);
			if (res == false)
				return false;
		}
		if (ac_address_in_range(v, text.address,
		    text.address + text.size) == false &&
		    ac_address_in_range(v, init.address,
		    init.address + init.size) == false &&
		    v != 0 && v != 0xffffffff && v != 0xffffffffffffffff) {
			printf("v: %#lx text.address: %#lx init.address: %#lx\n",
			    v, text.address, init.address);
			/*
			 * Found a .ctors function pointer that is illegal, meaning
			 * that it points outside of .init and .text, and its not
			 * a terminator value (either 0 or ~0).
			 */
			ac_heuristics_infection_set_hook_location(infdata, v);
			*result = true;
			break;

		}
	}
	return true;
}

static bool
ac_heuristics_plt_override_helper(struct arcana_ctx *ac, elfobj_t *elfobj,
    struct elf_symbol *dsym,  struct elf_shared_object *so, elfobj_t *so_elfobj,
    struct so_injection_state *injection, bool *found_plt_entry,
    bool *result, confidence_level_t *confidence)
{

	struct elf_plt plt;						  
	struct ac_so_plt_pair *plt_pair;				  
	bool res;
	struct duplicate_dsyms {
		char *name;
		char *libpath;
		uint64_t value;
		bool ignore;
		SLIST_ENTRY(duplicate_dsyms) _linkage;
	};
	struct duplicate_dsyms *dsyms_list_ptr, *dupsym;
	SLIST_HEAD(, duplicate_dsyms) duplicate_dsyms_list;
	SLIST_INIT(&duplicate_dsyms_list);

	*found_plt_entry = false;

	if (elf_plt_by_name(elfobj, dsym->name,
	    &plt) == true ||
	    ac_internal_optimized_got_linkage(elfobj, (char *)dsym->name, &plt) == true) {
		*found_plt_entry = true;
		/*
		 * This shared library is *probably*
		 * benign since we found a corresponding
		 * PLT entry in the binary that's requesting
		 * its NEEDED entry, however it could still be
		 * overriding a PLT entry for a subsequent
		 * library, so we will take that into
		 * account later if we find two symbols
		 * of the same name in two libraries.
		 * There are some cases where duplicate symbol
		 * names exist either in the same library; i.e.
		 * STT_FUNC: memcpy and STT_IFUNC memcpy in libc.so,
		 * or other cases where a library such as libselinux.so.1
		 * has an import for memcpy and will therefore have an
		 * st_value of 0x0 since its a JUMP_SLOT relocation. We
		 * want to ignore any duplicates or imports.
		 */
		if (dsym->value == 0UL) {
			return true;
		}
		if (ac_heuristics_duplicate_dsym(so_elfobj,
		    dsym->name, &res) == false) {
			ac_printf("ac_heuristics_duplicate_symbol failed\n");
			return false;
		} else {
			if (res == true) {
				dupsym = ac_malloc(sizeof(*dupsym), ac);
				dupsym->name = ac_strdup((char *)dsym->name, ac);
				dupsym->value = dsym->value;
				dupsym->libpath = ac_strdup(so->path, ac);
				dupsym->ignore = false;
				SLIST_INSERT_HEAD(&duplicate_dsyms_list,
				    dupsym, _linkage);
			}
		}
		ENTRY e, *ep;
		/*
		 * The plt_pair is used for pairing a shared library
		 * given by path and basename, to a PLT symbol name
		 * and value (The PLT entry address)
		 */
		plt_pair = ac_malloc(sizeof(*plt_pair), ac);
		plt_pair->libpath = ac_strdup(so->path, ac);
		plt_pair->basename = ac_strdup((char *)so->basename, ac);
		plt_pair->plt_name = ac_strdup(plt.symname, ac);
		plt_pair->addr = dsym->value;
		plt_pair->import_binding = dsym->bind;

		/*
		 * Check to see if there already exists this symbol
		 * and if it does, then initialize a linked list as there
		 * may be more than one object referencing the same symbol
		 * name in the event of DT_NEEDED override injection.
		 */
		e.key = (char *)plt.symname;
		e.data = (void *)plt_pair;

		SLIST_FOREACH(dsyms_list_ptr, &duplicate_dsyms_list,  _linkage) {
			if (strcmp(dsym->name, dsyms_list_ptr->name) == 0) {
				/*
				 * If we made it here then we have a symbol
				 * duplicate within the same library and don't
				 * want to add it to the plt_cache since we already
				 * have one symbol with that name. i.e. STT_FUNC:memcpy
				 * and STT_IFUNC:memcpy can both be within libc.so
				 * for instance. This will appear as symbol hijacking
				 * if we don't deal with this edge-case.
				 */
				if (strcmp(dsyms_list_ptr->libpath, so->path) == 0)
					return true;
			}
		}
		if ((hsearch_r(e, FIND, &ep, &ac->cache.plt_cache) != 0) &&
		    (injection->static_ldpreload == false)) {
			struct ac_so_plt_pair *so_plt_entry =
			    ac_malloc(sizeof(*so_plt_entry), ac);
			/*
			 * Matching PLT symbol in our cache which means
			 * another library references the same PLT entry.
			 */
			memcpy(so_plt_entry, ep->data, sizeof(*so_plt_entry));
			if (so_plt_entry->list_exists != true) {
				so_plt_entry->list_exists = true;
				LIST_INIT(&injection->so_plt_list);
			}
			/*
			 * Inserting the symbol that was found first into the
			 * injection list, i.e. libc.so:puts()
			 */
			LIST_INSERT_HEAD(&injection->so_plt_list, so_plt_entry,
			    _linkage);
			/*
			 * Inserting the symbol that was found to override libc.so:puts()
			 * from libevil.so (for instance). This leaves us with a linked
			 * list holding two values: <libevil.so:puts> <-> <libc.so:puts>
			 */
			LIST_INSERT_HEAD(&injection->so_plt_list, plt_pair,
			    _linkage);
			*result = true;
			injection->static_ldpreload = true;
			if (so_plt_entry->import_binding == STB_WEAK) {
				/*
				 * Low confidence because its a 50/50 chance. Someone
				 * could legitimately have a library dependency that
				 * is hijacking another function that is marked with
				 * weak symbol bindings, in which case its ambiguous
				 * as to whether or not this is shared object injection
				 */
				injection->overriden_symbol_is_weak = true;
				*confidence = CONFIDENCE_LEVEL_LOW;
			}
			return true;
		}
		e.key = (char *)plt_pair->plt_name;
		e.data = (void *)plt_pair;
		hsearch_r(e, ENTER, &ep, &ac->cache.plt_cache);
		if (ep == NULL && errno == ENOMEM) {
			ac_error("hsearch_r: %s\n", strerror(errno));
			return false;
		}
		return true;
	}
	return true;
}

/*
 * TODO: This algorithm won't work on certain ELF binaries, such as those
 * on Solaris where the DT_NEEDED entries are placed into the dynamic
 * segment in a non-contiguous manner by the linker.
 *
 * Our algorithm looks to see if there are any DT_NEEDED entries that aren't
 * right next to all the others. This will detect DT_DEBUG's overwritten
 * with a DT_NEEDED/
 *
 */
bool
ac_heuristics_dt_debug2dt_needed(struct arcana_ctx *ac, elfobj_t *elfobj,
    struct so_injection_state *injection, bool *result, confidence_level_t *confidence)
{
	elf_dynamic_iterator_t dyn_iter;
	struct elf_dynamic_entry dyn_entry;
	struct dt_needed_index {
		size_t index;
		char *so_basename;
		STAILQ_ENTRY(dt_needed_index) _linkage;
	};
	struct dt_needed_index *current;
	STAILQ_HEAD(, dt_needed_index) nidx_list;
	STAILQ_INIT(&nidx_list);
	size_t n_index = 0;

	elf_dynamic_iterator_init(elfobj, &dyn_iter);
	while (elf_dynamic_iterator_next(&dyn_iter, &dyn_entry) == ELF_ITER_OK) {
		if (dyn_entry.tag != DT_NEEDED) {
			n_index++;
			continue;
		}
		if (dyn_entry.tag == DT_DEBUG)
			injection->dt_debug_found = true;
		struct dt_needed_index *tmp = alloca(sizeof(*tmp));
		tmp->index = n_index;
		tmp->so_basename = (char *)
		    elf_dynamic_string(elfobj, dyn_entry.value);
		STAILQ_INSERT_TAIL(&nidx_list, tmp, _linkage);
		n_index++;
	}
	/*
	 * Our list is sorted. Make sure the distance between
	 * each index isn't larger than 1 (Meaning non-contiguous).
	 */
	LIST_INIT(&injection->stray_needed_list);
	STAILQ_FOREACH(current, &nidx_list, _linkage) {
		if (STAILQ_NEXT(current, _linkage) == NULL)
			break;
		if ((STAILQ_NEXT(current, _linkage)->index - current->index) > 1) {
			struct ac_shared_object *ac_so;

			ac_so = ac_malloc(sizeof(*ac_so), ac);
			memset(ac_so, 0, sizeof(*ac_so));
			ac_so->basename = ac_strdup(STAILQ_NEXT(current, _linkage)->so_basename, ac);
			ac_so->path = (char *)ac_so->basename;
			LIST_INSERT_HEAD(&injection->stray_needed_list, ac_so, _linkage);
			*result = true;
			*confidence = CONFIDENCE_LEVEL_HIGH;
		}
	}
	return true;
}

/*
 * Detection DT_NEEDED injected shared libraries. Sometimes
 * attackers will shift all other shared libraries forward and
 * put their malicious library first so that it takes precedence,
 * similar to LD_PRELOAD. This allows them to overwrite functions
 * in libc and other libraries. We are looking for shared libaries
 * that have no corresponding X86_ARCH_JUMPSLOT relocation's.
 * In other cases the DT_NEEDED basename will be non-contiguous with
 * the legitimate ones created by the linker and you will see one that
 * is several entries below the previous DT_NEEDED entry that is overwriting
 * DT_DEBUG.
 */
/*
 * struct so_injection_state is a parameter which contains a pointer to the PLT hash table
 * we create in elfobj_t *obj, as well as the heads to several linked lists
 */
bool
ac_heuristics_so_injection(struct arcana_ctx *ac, elfobj_t *elfobj,
    struct so_injection_state *injection, bool *result, confidence_level_t *confidence)
{
	elf_shared_object_iterator_t so_iter;
	struct elf_shared_object so;
	elf_error_t e;
	bool res;
	struct ac_shared_object *ac_so;

	*result = false;
	LIST_INIT(&injection->suspicious_so_list);

	ac_printf("Running .so injection detection heuristics\n");
	/*
	 * the top-level entries for DT_NEEDED entries for the current elf object. Whereas
	 * ELF_SO_RESOLVE_ALL_F will transitively resolve all dependencies
	 * similar to /usr/bin/ldd
	 */
	res = elf_shared_object_iterator_init(elfobj, &so_iter,
	    NULL, /*ELF_SO_LDSO_FAST_F|ELF_SO_IGNORE_VDSO_F|*/ELF_SO_RESOLVE_F, &e);
	if (res == false) {
		ac_error(
		    "elf_shared_object_iterator_init: %s\n",
		    elf_error_msg(&e));
		return false;
	}
	if (hcreate_r(AC_PLT_SYMBOL_HASH_SIZE, &ac->cache.plt_cache) == 0) {
		ac_error("hcreate_r: %s\n", strerror(errno));
		return false;
	}
	injection->plt_cache_pointer = &ac->cache.plt_cache;
	for (;;) {
		elf_iterator_res_t ires;
		bool found_plt_entry = false;
		bool library_has_linkage = false;

		ires = elf_shared_object_iterator_next(&so_iter, &so, &e);
		if (ires == ELF_ITER_DONE) {
			break;
		}
		if (ires == ELF_ITER_ERROR) {
			ac_error(".so iterator failed: %s\n", elf_error_msg(&e));
			break;
		}
		if (ires == ELF_ITER_NOTFOUND) {
			ac_error(".so iterator unable to locate: %s\n", elf_error_msg(&e));
			continue;
		}
		elf_dynsym_iterator_t dsym_iter;
		struct elf_symbol dsym;
		elfobj_t newobj; // handle for shared object

		/*
		 * i.e. elf_open_object("/lib/libc.so.6", &newobj, etc.);
		 */
		ac_printf("Opening file: %s\n", so.path);
		if (elf_open_object(so.path, &newobj,
		    ELF_LOAD_F_FORENSICS, &e) == false) {
			ac_error("elf_open_object: %s\n", elf_error_msg(&e));
			return false;
		}
		ac_printf("Resolved and analyzing shared library path: %s\n", so.path);
		/*
		 * We now check to see if there are corresponding PLT entries
		 * that related to any of the symbols in this shared library.
		 * Since they are dynamic symbols they won't be stripped. If
		 * the section header table is stripped libelfmaster will have
		 * reconstructed it by now so we can use elf_plt_iterator etc.
		 */
		elf_dynsym_iterator_init(&newobj, &dsym_iter);
		for (;;) {
			elf_iterator_res_t ires;

			ires = elf_dynsym_iterator_next(&dsym_iter, &dsym);
			if (ires == ELF_ITER_ERROR) {
				ac_error("elf_dynsym_iterator_next failed\n");
				return false;
			} else if (ires == ELF_ITER_DONE) {
				break;
			}
			/*
			 * For each shared object dependency we check its
			 * symbol table and see each symbol
			 * corresponds to a PLT entry in the executable.
			 * If there is more than one symbol from two diff
			 * libraries that match a PLT executable in the
			 * executable pointed to by elfobj_t *obj, then one
			 * of two things is happening:
			 * A. weak symbol is being overwritten legitimately
			 * B. symbol interposition is taking place which could
			 * be legitimate or NOT. We must determine this with
			 * some special casing where we see this most commonly.
			 */
			if (ac_heuristics_plt_override_helper(ac, elfobj, &dsym, &so,
			    &newobj, injection, &found_plt_entry, result, confidence) == false) {
				ac_error("ac_so_plt_override_helper failed "
				    "with an unexpected failure\n");
				return false;
			}
			if (found_plt_entry == true)
				library_has_linkage = true;
		}
		/*
		 * We may have not found any symbol hijacking going on with DT_NEEDED
		 * precedence injection (e.g. static_preload) but if we find a shared library
		 * who has symbols that are not found as imported/linked in the executable pointed
		 * to by elfobj, then we deem it as suspicious.
		 */
		if (library_has_linkage == false) {
			ac_so = ac_malloc(sizeof(*ac_so), ac);
			memset(ac_so, 0, sizeof(*ac_so));
			ac_so->basename = ac_strdup((char *)so.basename, ac);
			ac_so->path = ac_strdup(so.path, ac);
			LIST_INSERT_HEAD(&injection->suspicious_so_list, ac_so, _linkage);
			*result = true;
			*confidence = CONFIDENCE_LEVEL_HIGH;
		}
		elf_close_object(&newobj);
	}
	return true;
}

/*
 * We run_heuristics on a single object at a time
 * This handles the first layer of heuristics which looks for individual
 * signs of infections. It will the run "ac_heuristics_process_infection_list"
 * which is the second layer of heuristics to cross reference and examine
 * more once all of the infection data is gathered together.
 */
bool
ac_heuristics_checkall(struct arcana_ctx *ac, struct obj_struct *obj)
{
	bool hres; // heuristics result
	struct so_injection_state injection;
	confidence_level_t confidence;
	struct ac_infection_data *infdata = &obj->infection_data[AC_INFECTION_L1];
	elfobj_t *elfobj = obj->elfobj;
	ac_entropy_bias_t bias;

	memset(&confidence, 0, sizeof(confidence));
	memset(&injection, 0, sizeof(injection));
	memset(infdata, 0, sizeof(*infdata));
	/*
	 * Is the target ELF file linked with -nostdlib
	 */
	ac_printf("Running 1st layer of heuristics\n");
	ac_printf("Object '%s' has SCOP?: %s\n", elf_pathname(elfobj),
	    elf_flags(elfobj, ELF_SCOP_F) ? "Yes" : "No");

	if (ac_heuristics_packed_elf(ac, elfobj, &hres, &bias) == true) {
		if (hres == true) {
			ac_warning("ELF Object: %s <-> File is likely %s (packed executable)\n",
			    elf_pathname(elfobj), bias == AC_ENTROPY_COMPRESSED ?
			    "compressed" : "encrypted");
			ac_set_flag(ac, AC_ANOMALY_F_PACKED_BINARY);
			ac_heuristics_insert_state(ac, obj, AC_ANOMALY_F_PACKED_BINARY,
			    0, CONFIDENCE_LEVEL_MEDIUM, 0, infdata);
		} else {
			ac_heuristics_insert_state(ac, obj, 0, 0, 0, 0, infdata);
		}
	} else {
		ac_set_missing(ac, AC_ANOMALY_F_PACKED_BINARY);
		ac_heuristics_insert_state(ac, obj, 0, AC_ANOMALY_F_PACKED_BINARY,
		    0, 0, infdata);
	}
	/*
	 * Checks to see if the binary is built with -nostdlib, this is
	 * generally evident if there is no glibc init code.
	 */
	if (ac_heuristics_nostdlib(ac, elfobj, &hres) == true) {
		if (hres == true) {
			ac_warning("ELF Object: %s <-> \"gcc -nostdlib\" "
			    "linking found\n", elf_pathname(elfobj));
			ac_warning("[CONFIDENCE LEVEL: HIGH]\n");
			ac_set_flag(ac, AC_ANOMALY_F_NOSTDLIB_LINKING);
			ac_heuristics_insert_state(ac, obj, AC_ANOMALY_F_NOSTDLIB_LINKING,
			    0, CONFIDENCE_LEVEL_HIGH, 0, infdata);
		} else {
			/*
			 * No infection
			 */
			ac_heuristics_insert_state(ac, obj, 0, 0, 0, 0, infdata);
		}
	} else {
		/*
		 * Unable to determine if this infection is present
		 */
		ac_set_missing(ac, AC_ANOMALY_F_NOSTDLIB_LINKING);
		ac_heuristics_insert_state(ac, obj, 0, AC_ANOMALY_F_NOSTDLIB_LINKING,
		    0, 0, infdata);
	}

	/*
	 * Discover if the ehdr->e_entry value has been modified. This is easily detectable
	 * although if the binary is built with -nostdlib its harder to detect, which is where
	 * the TODO: 2nd layer of heuristics comes in, which will scan the infection items in
	 * the infection_state list, and cross-reference to determine if a further course of
	 * action needs to be taken. Other actions such as re-rating confidence, and adding
	 * more information about a specific infection will be applied in this layer as well.
	 */
	if (ac_heuristics_entrypoint(ac, elfobj, infdata, &hres) == true) {
		if (hres == true) {
			ac_warning("ELF Object: %s <-> entry point has been"
			    " modified to %#llx\n", elf_pathname(elfobj),
			    elf_entry_point(elfobj));
			ac_warning("[CONFIDENCE LEVEL: HIGH]\n");
			ac_set_flag(ac, AC_ANOMALY_F_MODIFIED_EP);
			ac_heuristics_insert_state(ac, obj, AC_ANOMALY_F_MODIFIED_EP,
			    0, CONFIDENCE_LEVEL_HIGH, 0, infdata);
		} else {
			ac_heuristics_insert_state(ac, obj, 0, 0, 0, 0, infdata);
		}
	} else {
		ac_set_missing(ac, AC_ANOMALY_F_MODIFIED_EP);
		ac_heuristics_insert_state(ac, obj, 0, AC_ANOMALY_F_MODIFIED_EP,
		    0, 0, infdata);
	}

	/*
	 * Detect whether or not .ctors (aka .init_array) has been infected
	 * with function pointer hooks. Common entry point modification for
	 * ELF Malware.
	 */
	if (ac_heuristics_ctors(ac, elfobj, infdata, AC_CTORS, &hres) == true) {
		if (hres == true) {
			ac_warning("ELF Object: %s <-> modified .ctors/.init_array\n",
			    elf_pathname(elfobj));
			ac_warning("[CONFIDENCE LEVEL: HIGH]\n");
			ac_set_flag(ac, AC_ANOMALY_F_MODIFIED_CTORS);
			ac_heuristics_insert_state(ac, obj,
			    AC_ANOMALY_F_MODIFIED_CTORS, 0, CONFIDENCE_LEVEL_HIGH,
			    0, infdata);
		} else {
			ac_heuristics_insert_state(ac, obj, 0, 0, 0, 0, infdata);
		}
	} else {
		ac_set_missing(ac, AC_ANOMALY_F_MODIFIED_CTORS);
		ac_heuristics_insert_state(ac, obj, 0, AC_ANOMALY_F_MODIFIED_CTORS,
		    0, 0, infdata);
	}

	if (ac_heuristics_ctors(ac, elfobj, infdata, AC_DTORS, &hres) == true) {
		if (hres == true) {
			ac_warning("ELF Object: %s <-> modified .dtors/.fini_array\n",
			    elf_pathname(elfobj));
			ac_warning("[CONFIDENCE LEVEL: HIGH]\n");
			ac_set_flag(ac, AC_ANOMALY_F_MODIFIED_DTORS);
			ac_heuristics_insert_state(ac, obj,
			    AC_ANOMALY_F_MODIFIED_DTORS, 0, CONFIDENCE_LEVEL_HIGH,
			    0, infdata);
		} else {
			ac_heuristics_insert_state(ac, obj, 0, 0, 0, 0, infdata);
		}
	} else {
		ac_set_missing(ac, AC_ANOMALY_F_MODIFIED_DTORS);
		ac_heuristics_insert_state(ac, obj, 0, AC_ANOMALY_F_MODIFIED_DTORS,
		    0, 0, infdata);
	}


	/*
	 * We don't check for deep .so injection if we are in lightweight mode.
	 * This speeds up performance tremendously at the expensive of missing
	 * any shared library injection that is present.
	 */
	if (ac_config_check(ac, AC_CONFIG_LIGHTWEIGHT) == true) {
			ac_printf("Lightweight mode: Skipping .so injection detection\n");
	}
	/*
	 * We won't run this type of .so injection detection if we are not
	 * in IDS mode either. This check requires full system .so resolution.
	 */
	if ((elf_linking_type(elfobj) == ELF_LINKING_DYNAMIC) &&
	    ac_config_check(ac, AC_CONFIG_LIGHTWEIGHT) == false &&
	    ac_config_check(ac, AC_CONFIG_IDS_MODE) == true &&
	    ac_heuristics_so_injection(ac, elfobj, &injection, &hres, &confidence) == true) {
		if (hres == true) {
			uint64_t fval = AC_ANOMALY_F_NEEDED_INJECTION;

			ac_heuristics_display_so_injection(ac, elfobj, &injection, confidence);
			ac_set_flag(ac, fval);
			if (injection.static_ldpreload == true) {
				fval |= AC_ANOMALY_F_NEEDED_STATIC_PRELOAD;
				ac_set_flag(ac, fval);
			}
			ac_heuristics_insert_state(ac, obj,
			    fval, 0, confidence, 0, infdata);
		} else {
			ac_heuristics_insert_state(ac, obj, 0, 0, 0, 0, infdata);
		}
	} else {
		ac_set_missing(ac, AC_ANOMALY_F_NEEDED_INJECTION);
		ac_heuristics_insert_state(ac, obj, 0,
		    AC_ANOMALY_F_NEEDED_INJECTION, confidence, 0, infdata);
	}

	/*
	 * We detect DT_NEEDED infections that overwrite the DT_DEBUG entry
	 * even when we are in lightweight mode, or out of IDS Mode.
	 */
	if (elf_linking_type(elfobj) == ELF_LINKING_DYNAMIC) {
		if (ac_heuristics_dt_debug2dt_needed(ac,
		    elfobj, &injection, &hres, &confidence) == true) {
			if (hres == true) {
				struct ac_shared_object *current;
				uint64_t fval = AC_ANOMALY_F_NEEDED_INJECTION |
				    AC_ANOMALY_F_STRAY_NEEDED_ENTRY;

				LIST_FOREACH(current, &injection.stray_needed_list, _linkage) {
					ac_warning("ELF Object: %s <-> Injected dependency found: %s\n",
					    elf_pathname(elfobj), current->basename);
					ac_warning("Infected DT_NEEDED .so injection... %s\n",
					    injection.dt_debug_found == false ? "DT_DEBUG overwrite" : "");
					ac_warning("[CONFIDENCE LEVEL: %s]\n",
					    ac_heuristics_confidence(confidence));
					ac_set_flag(ac, fval);
					ac_heuristics_insert_state(ac, obj, fval,
					    0, confidence, 0, infdata);	
				}
			} else {
				ac_heuristics_insert_state(ac, obj, 0, 0, 0, 0, infdata);
			}
		} else {
			ac_set_missing(ac, AC_ANOMALY_F_STRAY_NEEDED_ENTRY);
			ac_heuristics_insert_state(ac, obj, 0,
			    AC_ANOMALY_F_STRAY_NEEDED_ENTRY, confidence, 0, infdata);
		}
	}

	if (ac_heuristics_reverse_text_infection(ac, elfobj, infdata, &hres, &confidence) == true) {
		if (hres == true) {
			ac_warning("ELF Object: %s <-> has a reverse text padding infection\n",
			    elf_pathname(elfobj));
			ac_warning("[CONFIDENCE LEVEL: %s]\n", ac_heuristics_confidence(confidence));
			ac_set_flag(ac, AC_ANOMALY_F_TEXT_REVERSE_INFECTION);
			ac_heuristics_insert_state(ac, obj,
			    AC_ANOMALY_F_TEXT_REVERSE_INFECTION, 0, confidence, 0, infdata);
		} else {
			ac_heuristics_insert_state(ac, obj, 0, 0, 0, 0, infdata);
		}
	} else {
		ac_set_missing(ac, AC_ANOMALY_F_TEXT_REVERSE_INFECTION);
		ac_heuristics_insert_state(ac, obj, 0,
		    AC_ANOMALY_F_TEXT_REVERSE_INFECTION, 0, 0, infdata);
	}

	if (ac_heuristics_text_padding(ac, elfobj, infdata, &hres, &confidence) == true) {
		if (hres == true) {
			ac_warning("ELF Object: %s <-> has a traditional text segment"
			    " padding infection\n", elf_pathname(elfobj));
			ac_warning("[CONFIDENCE LEVEL: %s]\n", ac_heuristics_confidence(confidence));
			ac_set_flag(ac, AC_ANOMALY_F_TEXT_PAD_INFECTION);
			ac_heuristics_insert_state(ac, obj,
			    AC_ANOMALY_F_TEXT_PAD_INFECTION, 0, confidence, 0, infdata);
		} else {
			ac_heuristics_insert_state(ac, obj, 0, 0, 0, 0, infdata);
		}
	} else {
		ac_set_missing(ac, AC_ANOMALY_F_TEXT_PAD_INFECTION);
		ac_heuristics_insert_state(ac, obj, 0,
		    AC_ANOMALY_F_TEXT_PAD_INFECTION, 0, 0, infdata);
	}

	if (ac_heuristics_pt_note_conversion(ac, elfobj, infdata, &hres) == true) {
		if (hres == true) {
			ac_warning("ELF Object: %s <-> has a PT_NOTE to PT_LOAD conversion infection\n",
			    elf_pathname(elfobj));
			ac_warning("[CONFIDENCE LEVEL: HIGH]\n");
			ac_set_flag(ac, AC_ANOMALY_F_PT_NOTE_CONVERSION);
			ac_heuristics_insert_state(ac, obj,
			    AC_ANOMALY_F_PT_NOTE_CONVERSION, 0,
			    CONFIDENCE_LEVEL_HIGH, 0, infdata);
		} else {
			ac_heuristics_insert_state(ac, obj, 0, 0, 0, 0, infdata);
		}
	} else {
		ac_set_missing(ac, AC_ANOMALY_F_PT_NOTE_CONVERSION);
		ac_heuristics_insert_state(ac, obj, 0,
		    AC_ANOMALY_F_PT_NOTE_CONVERSION, 0, 0, infdata);
	}

	if (elf_linking_type(elfobj) != ELF_LINKING_STATIC_PIE) {
		if (ac_heuristics_got_plt_hooks(ac, obj, elfobj, infdata, &hres) == true) {
			if (hres == true) {
				ac_warning("ELF Object: %s <-> has .got.plt function pointer hooks\n",
				    elf_pathname(elfobj));
				ac_warning("[CONFIDENCE LEVEL: HIGH]\n");
				ac_set_flag(ac, AC_ANOMALY_F_GOTPLT_INFECTION);
				ac_heuristics_insert_state(ac, obj,
				    AC_ANOMALY_F_GOTPLT_INFECTION, 0,
				    CONFIDENCE_LEVEL_HIGH, 0, infdata);
			} else {
				ac_heuristics_insert_state(ac, obj, 0, 0, 0, 0, infdata);
			}
		} else {
			ac_set_missing(ac, AC_ANOMALY_F_GOTPLT_INFECTION);
			ac_heuristics_insert_state(ac, obj, 0,
			    AC_ANOMALY_F_GOTPLT_INFECTION, 0, 0, infdata);
		}
	}

	if (ac_heuristics_executable_data(ac, obj, elfobj, &hres) == true) {
		if (hres == true) {
			ac_warning("ELF Object: %s <-> has an executable data segment.\n",
			    elf_pathname(elfobj));
			ac_warning("[CONFIDENCE LEVEL: HIGH]\n");
			ac_set_flag(ac, AC_ANOMALY_F_EXECUTABLE_DATA);
			ac_heuristics_insert_state(ac, obj,
			    AC_ANOMALY_F_EXECUTABLE_DATA, 0,
			    CONFIDENCE_LEVEL_HIGH, 0, infdata);
		} else {
			ac_heuristics_insert_state(ac, obj, 0, 0, 0, 0, infdata);
		}
	} else {
		ac_set_missing(ac, AC_ANOMALY_F_EXECUTABLE_DATA);
		ac_heuristics_insert_state(ac, obj, 0,
		    AC_ANOMALY_F_EXECUTABLE_DATA, 0, 0, infdata);
	}

	if (ac_heuristics_init_hook(ac, obj, elfobj, infdata, AC_DT_INIT, &hres) == true) {
		if (hres == true) {
			ac_warning("ELF Object: %s <-> has a DT_INIT infection hook\n",
			    elf_pathname(elfobj));
			ac_warning("[CONFIDENCE LEVEL: HIGH]\n");
			ac_set_flag(ac, AC_ANOMALY_F_INIT_HOOK);
			ac_heuristics_insert_state(ac, obj,
			    AC_ANOMALY_F_INIT_HOOK, 0, CONFIDENCE_LEVEL_HIGH, 0,
			    infdata);
		} else {
			ac_heuristics_insert_state(ac, obj, 0, 0, 0, 0, infdata);
		}
	} else {
		ac_set_missing(ac, AC_ANOMALY_F_INIT_HOOK);
		ac_heuristics_insert_state(ac, obj, 0,
		    AC_ANOMALY_F_INIT_HOOK, 0, 0, infdata);
	}

	if (ac_heuristics_init_hook(ac, obj, elfobj, infdata, AC_DT_FINI, &hres) == true) {
		if (hres == true) {
			ac_warning("ELF Object: %s <-> has a DT_FINI infection hook\n",
			    elf_pathname(elfobj));
			ac_warning("[CONFIDENCE LEVEL: HIGH]\n");
			ac_set_flag(ac, AC_ANOMALY_F_FINI_HOOK);
			ac_heuristics_insert_state(ac, obj,
			    AC_ANOMALY_F_FINI_HOOK, 0, CONFIDENCE_LEVEL_HIGH, 0,
			    infdata);
		} else {
			ac_heuristics_insert_state(ac, obj, 0, 0, 0, 0, infdata);
		}
	} else {
		ac_set_missing(ac, AC_ANOMALY_F_FINI_HOOK);
		ac_heuristics_insert_state(ac, obj, 0,
		    AC_ANOMALY_F_FINI_HOOK, 0, 0, infdata);
	}

	if (ac_heuristics_relocation_hooks(ac, elfobj, infdata, &hres) == true) {
		if (hres == true) {
			ac_warning("ELF Object: %s <-> has poisoned relocation data\n",
			    elf_pathname(elfobj));
			ac_warning("[CONFIDENCE LEVEL: HIGH]\n");
			ac_set_flag(ac, AC_ANOMALY_F_POISONED_RELOC);
			ac_heuristics_insert_state(ac, obj, AC_ANOMALY_F_POISONED_RELOC, 0,
			    CONFIDENCE_LEVEL_HIGH, 0, infdata);
		} else {
			ac_heuristics_insert_state(ac, obj, 0, 0, 0, 0, infdata);
		}
	} else {
		ac_set_missing(ac, AC_ANOMALY_F_POISONED_RELOC);
		ac_heuristics_insert_state(ac, obj, 0, AC_ANOMALY_F_POISONED_RELOC,
		    0, 0, infdata);
	}

	if (ac_heuristics_check_stripped_elf(ac, elfobj, &hres) == true) {
		if (hres == true) {
			ac_warning("ELF Object: %s <-> Completely stripped of all section headers.\n",
			    elf_pathname(elfobj));
			ac_warning("[CONFIDENCE LEVEL: HIGH]\n");
			ac_set_flag(ac, AC_ANOMALY_F_STRIPPED_SHDRS);
			ac_heuristics_insert_state(ac, obj, AC_ANOMALY_F_STRIPPED_SHDRS, 0,
			    CONFIDENCE_LEVEL_HIGH, 0, infdata);
		} else {
			ac_heuristics_insert_state(ac, obj, 0, 0, 0, 0, infdata);
		}
	} else {
		ac_set_missing(ac, AC_ANOMALY_F_STRIPPED_SHDRS);
		ac_heuristics_insert_state(ac, obj, 0, AC_ANOMALY_F_STRIPPED_SHDRS,
		    0, 0, infdata);
	}

	/*
	 * Call the plugins that are to be invoked from within
	 * the l1 plugin engine.
	 */
	ac_process_layer1_plugins(ac, obj, NULL);

	if (ac_heuristics_layer2(ac, obj) == false) {
		ac_printf("Failed to run heuristics layer-2\n");
	}
	printf("\n");
	return true;
}
