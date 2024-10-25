/*
 *
 * extended_section.c - plugin for detecting extended sections (altered padding bytes)
 * by isra - isra _replace_this_by_@ fastmail.net
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/types.h>
#include <search.h>
#include <sys/time.h>
#include "../include/arcana.h"
#include "../include/plugin.h"
#include "/opt/elfmaster/include/libelfmaster.h"

const ac_plugin_type_t plugin_type = 0;
ac_plugin_name_t plugin_name = "extended section plugin v2";

static bool
check_padding(struct elfobj *elfobj, uint64_t lower_bound, uint64_t upper_bound)
{
	uint64_t i;
	uint8_t *ptr, last_byte = 0;
	for (i = lower_bound; i < upper_bound; i++) {
		ptr = elf_offset_pointer(elfobj, i);
		/* If elf_offset_pointer returns NULL, it's not a
		 * sane offset - abort the search.
		 */
		if (!ptr)
			return false;

		// save the last non-zero byte
		if (*ptr != 0)
			last_byte = *ptr;
	}

	if (last_byte)
		return true;

	return false;
}

static bool
check_init_section(struct elfobj *elfobj)
{
	struct elf_section init, cont_init;
	if (!elf_section_by_name(elfobj, ".init", &init)) {
		printf("No .init section found\n");
		return false;
	}
	printf("Found .init section @ 0x%lx\n", init.offset);
	if (elf_section_by_name(elfobj, ".plt", &cont_init)) {
		printf("Found .plt section @ 0x%lx\n", cont_init.offset);
		return check_padding(elfobj, init.offset+init.size, cont_init.offset);
	}

	printf("ELF without PLT detected\n");

	if (elf_section_by_name(elfobj, ".text", &cont_init)) {
		printf("Found .text section @ 0x%lx\n", cont_init.offset);
		return check_padding(elfobj, init.offset+init.size, cont_init.offset);
	}

	printf(".init is followed by an unexpected section\n");
	return false;
}

static bool
check_fini_section(struct elfobj *elfobj)
{
	struct elf_section fini, cont_fini;
	if (!elf_section_by_name(elfobj, ".fini", &fini)) {
		printf("No .fini section found\n");
		return false;
	}
	printf("Found .fini section @ 0x%lx\n", fini.offset);
	if (elf_section_by_name(elfobj, ".rodata", &cont_fini)) {
		printf("Found .rodata section @ 0x%lx\n", cont_fini.offset);
		return check_padding(elfobj, fini.offset+fini.size, cont_fini.offset);
	}

	printf(".fini is followed by an unexpected section\n");
	return false;
}

bool
init_plugin_detect_extended_section(arcana_ctx_t *ac, struct obj_struct *obj, void **arg)
{
	(void)arg;

	if (check_init_section(obj->elfobj)) {
		/* padding bytes after .init section have been altered */
		obj->verdict = AC_VERDICT_INFECTED;
		printf("Extension of .init section detected\n");
	}

	if (check_fini_section(obj->elfobj)) {
		/* padding bytes after .fini section have been altered */
		obj->verdict = AC_VERDICT_INFECTED;
		printf("Extension of .fini section detected\n");
	}
	return true;
}

void exit_plugin_detect_extended_section(arcana_ctx_t *ac, struct obj_struct *obj, void **arg)
{
	(arcana_ctx_t *)ac;
	(void)arg;
	(struct obj_struct *)obj;

	return;
}
