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
ac_plugin_name_t plugin_name = "extended section plugin v1";

bool
init_plugin_detect_extended_section(arcana_ctx_t *ac, struct obj_struct *obj, void **arg)
{
	(void)arg;
	uint8_t *ptr, read_init, read_fini;
	uint64_t i, init_last_byte, fini_last_byte;

	elfobj_t *elfobj = obj->elfobj;
	/* executable sections that are most likely to be extended */
	struct elf_section init, fini;
	/* contiguous sections to .init and .fini */
	struct elf_section plt, rodata;

	read_init = 0;
	read_fini = 0;

	if(elf_section_by_name(elfobj, ".init", &init) == true) {
		if(elf_section_by_name(elfobj, ".plt", &plt) == true) {
			printf("Found .init and .plt sections.\n");
			read_init = 1;
		}
	}

	if(elf_section_by_name(elfobj, ".fini", &fini) == true) {
		if(elf_section_by_name(elfobj, ".rodata", &rodata) == true) {
			printf("Found .fini and .rodata sections.\n");
			read_fini = 1;
		}
	}

	if(!read_init && !read_fini) {
		printf("Couldn't read .init or .fini sections\n");
		return false;
	}

	/* last non-zero byte after the end of .init or .fini */
	init_last_byte = 0;

	/* loop from the end of .init to the start of .plt */
	for(i = init.offset + (uint64_t)init.size; i < plt.offset; i++) {
		ptr = elf_offset_pointer(elfobj, i);
		if(*ptr != 0) {
			/* save the last non-zero byte */
			init_last_byte = i;
		}
	}

	/* last non-zero byte after the end of .init or .fini */
	fini_last_byte = 0;

	/* loop from the end of .fini to the start of .rodata */
	for(i = fini.offset + (uint64_t)fini.size; i < rodata.offset; i++) {
		ptr = elf_offset_pointer(elfobj, i);
		if(*ptr != 0) {
			/* save the last non-zero byte */
			fini_last_byte = i;
		}
	}

	if(init_last_byte != 0) {
		/* padding bytes after .init section have been altered */
		obj->verdict = AC_VERDICT_INFECTED;
		printf("Extension of .init section detected\n");
		printf("End of section at offset: %lx\n", init.offset + (uint64_t)init.size );
		printf("Last padding byte altered at offset: %lx\n", init_last_byte);
	}

	if(fini_last_byte != 0) {
		/* padding bytes after .fini section have been altered */
		obj->verdict = AC_VERDICT_INFECTED;
		printf("Extension of .fini section detected\n");
		printf("End of section at offset: %lx\n", fini.offset + (uint64_t)fini.size );
		printf("Last padding byte altered at offset: %lx\n", fini_last_byte);
	} 

	if(init_last_byte || fini_last_byte) {
		return true;
	}

	if(!init_last_byte && !fini_last_byte) {
		printf("Extension of .init or .fini sections not detected\n");
		return false;
	}
}

void exit_plugin_detect_extended_section(arcana_ctx_t *ac, struct obj_struct *obj, void **arg)
{
	(arcana_ctx_t *)ac;
	(void)arg;
	(struct obj_struct *)obj;

	return;
}
