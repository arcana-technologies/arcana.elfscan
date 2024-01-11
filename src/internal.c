#include "arcana.h"
#include <sys/queue.h>

/*
 * On newer x86 ELF binaries we see there is not only a .plt and .got.plt section
 * but also (And confusingly so) a .plt.got section. This 3rd section is an optimized
 * .plt section, and does not use JUMP_SLOT relocations, therefore the elf_plt_iterator
 * API will not find these PLT entries.
 */
bool
ac_internal_optimized_got_linkage(elfobj_t *obj, char *name, struct elf_plt *plt)
{
	struct elf_section plt_got_section;
	elf_dynsym_iterator_t dsym_iter;
	struct elf_symbol dsym;
	size_t idx = 0;
	uint64_t plt_got_vaddr = 0;
	const size_t OPTIMIZED_PLT_ENTSIZE = 8; // on x86_32/x86_64 its the same

	if (elf_section_by_name(obj, ".plt.got",
	    &plt_got_section) == false) {
		return false;
	}
	plt_got_vaddr = plt_got_section.address;

	elf_dynsym_iterator_init(obj, &dsym_iter);
	while (elf_dynsym_iterator_next(&dsym_iter, &dsym) == ELF_ITER_OK) {
		if (strcmp(dsym.name, name) == 0) {
			plt->symname = name;
			plt->addr = plt_got_vaddr + idx * OPTIMIZED_PLT_ENTSIZE;
			return true;
		}
		idx++;
	}
	return false;
}
/*
 * Return the PT_PHDR program header
 */
bool
ac_internal_elf_pt_phdr(elfobj_t *obj, struct elf_segment *segment_out)
{
	struct elf_segment segment;
	elf_segment_iterator_t iter;
	elf_iterator_res_t res;
	bool found = false;

	elf_segment_iterator_init(obj, &iter);
	for (;;) {
		res = elf_segment_iterator_next(&iter, &segment);
		if (res == ELF_ITER_ERROR) {
			ac_printf("Error in locating PT_PHDR segment\n");
			return false;
		} else if (res == ELF_ITER_DONE) {
			if (found == false)
				return false;
			return true;
		}
		if (segment.type == PT_PHDR) {
			memcpy(segment_out, &segment, sizeof(segment));
			return true;
		}
	}
	return false;
}

char *
ac_internal_elf_shdr_name_by_address(elfobj_t *elfobj,
    uint64_t addr, struct elf_section *section)
{

	if (elf_section_by_address(elfobj, addr, section) == true) {
		return section->name;
	}
	return "<unknown>";
}
