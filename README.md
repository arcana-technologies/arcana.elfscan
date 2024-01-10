# Arcana ElfScan

Arcana ElfScan is an open source ELF binary forensics tool for APT, virus,
backdoor and rootkit detection. It has been released open source under the MIT
license.

### Author

Ryan "ElfMaster" O'Neill, 2018-2024

### Contributions

Thank you to MalcomVX for continuing to design new APT's, Viruses, and implants
to test against. :)

## Compile and install

git clone https://github.com/arcana-technologies/arcana.elfscan
cd arcana.elfscan

mkdir build
cd build
cmake ..
make
cd ../plugins
make
cd ..
sudo ./install.sh

## Try Arcana Elfscan

$ arcana -e /bin/ls
$ arcana -e ~/git/arcana.elfscan/infected_bins/jp-retal

## Description of Arcana ElfScan

Arcana ElfScan uses a multi-layered heuristics engine for analyzing ELF
binaries to look for specific anomalies that indicate  Virus infection, backdoor
implants, and userland rootkits. These underground techniques are able to
cleverly modify the ELF binary in such a way that it looks and behaves normally
to the un-trained eye, but under the hood it is surreptitiously executing
threatening code. Arcana aims to mitigate these threats by giving users the
ability to finally detect this type of "Advanced persistent threats".

Arcana does not analyze the code itself, but rather validates the structural
geometry of the ELF binary at an extremely nuanced level, with inherent insight
into the most sophisticated types of ELF binary infections. For users that want
to further analyze the code to validate that the code itself is malicious (vs.
some benign instrumentation), they may write plugins for Arcana. For example,
once Arcana has identified the location of the implanted code, the user may
write a plugin that uses an emulator (Such as unicorn) to analyze the code.
Please see the section on plugins.

## The Plugin system

The plugin system for Arcana is easy to use, and can plugin to 4 different
phases of runtime execution. (See include/plugin.h). 

```
#pragma once

#define _GNU_SOURCE
#define AC_MAX_PLUGIN_NAME_LEN 256

#include "arcana.h"

typedef enum ac_plugin_type {
        /*
         * Before heuristics l1 engine
         */
        AC_PLUGIN_PRE_HANDLER = 0,
        /*
         * After heuristics l2 engine
         */
        AC_PLUGIN_POST_HANDLER,
        /*
         * Called during either l1 or l2 engine
         */
        AC_PLUGIN_HEURISTICS_L1_HANDLER,
        AC_PLUGIN_HEURISTICS_L2_HANDLER,
        AC_PLUGIN_TYPE_UNKNOWN
} ac_plugin_type_t;

typedef char * ac_plugin_name_t;
```

This plugin struct is simple and indicates that the plugin type can be one of
four types. The plugin can either run before all heuristics, within heuristics
layer-1, within heuristics layer-2 or after the heuristics engines are done.

(See plugins/golang.c example)

```
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
```

This plugin should be fairly easy to dissect. At runtime, just before the
heuristics L1 is fired off, this plugin will be executed; specifically the
`init_plugin_detect_go_binary()` will be executed, passing Arcana's state
to the plugin via `arcana_ctx_t *ac` pointer and an optional argument
`void **arg`.

This particular plugin detects whether or not an ELF binary was created by GO.
It simply checks whether the ELF section ".gosymtab" exists within the ELF
binary that is abeing analyzed.


## Contact

elfmaster [at] arcana-technologies.io

