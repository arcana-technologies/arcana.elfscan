/*
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

/*
 * Define the plugin type and name:
 * NOTE: plugin_type and plugin_name are the
 * naming conventions that must be used.
 */
const ac_plugin_type_t plugin_type = AC_PLUGIN_PRE_HANDLER;
ac_plugin_name_t plugin_name = "golang plugin v1";

bool
init_plugin_detect_go_binary(arcana_ctx_t *ac, struct obj_struct *obj, void **arg)
{
	(void)arg;

	elfobj_t *elfobj = obj->elfobj;
	struct elf_section section;

	/*
	 * Cheap quick way to detect if its a GO binary, fix this later.
	 * This is just an example of writing a plugin to test with our
	 * new plugin system.
	 */
	if (elf_section_by_name(elfobj, ".gosymtab", &section) == false) {
		printf("golang.plugin: Executable %s is not a golang binary\n", elf_pathname(elfobj));
		return false;
	}
	printf("golang.plugin: Executable %s is a golang built binary\n", elf_pathname(elfobj));
	return true;
}

void exit_plugin_detect_go_binary(arcana_ctx_t *ac, struct obj_struct *obj, void **arg)
{
	(arcana_ctx_t *)ac;
	(void)arg;
	(struct obj_struct *)obj;

	return;
}
