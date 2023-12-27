#include "arcana.h"

static bool ac_process_pre_plugins(arcana_ctx_t *, obj_struct_t *, void **);
static bool ac_process_post_plugins(arcana_ctx_t *, obj_struct_t *, void **);

bool
ac_process_objects(struct arcana_ctx *ac)
{
	elf_error_t e;
	bool res;
	obj_struct_t *current;

	if (LIST_EMPTY(AC_LIST_HEAD(ac))) {
		ac_printf("No files to scan\n");
		return false;
	}
	/*
	 * TODO: Ideally we want to do this concurrently, so handle processing
	 * of up to upwards of 10 objects at any given time.
	 */
	LIST_FOREACH(current, AC_LIST_HEAD(ac), _linkage) {
		elfobj_t *elfobj = current->elfobj;
		char *filename = current->filename;

		TAILQ_INIT(&current->infection_state_list);
		ac_printf("Processing: %s\n", filename);
		res = elf_open_object(filename, elfobj,
		    ac->opts.container ? ELF_LOAD_F_LXC_MODE : 0 | ELF_LOAD_F_FORENSICS, &e);
		if (res == false) {
			ac_printf("Unable to open object %s: %s\n", filename,
			    elf_error_msg(&e));
			continue;
		}
		if (elf_arch(elfobj) == unsupported) {
			ac_printf("Arcana cannot scan this ELF file: unsupported architecture\n");
			elf_close_object(elfobj);
			continue;
		}
		if (elf_type(elfobj) == ET_REL) {
			ac_printf("Currently arcana does not handle ET_REL objects, aborting\n");
			ac_printf("closing: %s\n", filename);
			elf_close_object(elfobj);
			continue;
		}
		if (ac->opts.container) {
			char rootfs[PATH_MAX];

			snprintf(rootfs, PATH_MAX, "%s/%s/rootfs/",
			    ac->config.container_root, ac->container);
			ac_printf("Setting LXC rootfs: %s\n", rootfs);
			elf_lxc_set_rootfs(elfobj, rootfs);
		}
		if (ac_config_check(ac, AC_CONFIG_IDS_MODE) == true)
			ac_so_process_shared_objects(ac, current);
		/*
		 * Our AC_PLUGIN_PRE_HANDLER type of plugin gets executed
		 * before everything except the processing of shared objects
		 * above.
		 */
		ac_process_pre_plugins(ac, current, NULL);
		ac_heuristics_checkall(ac, current);
		ac_process_post_plugins(ac, current, NULL);
		switch(current->verdict) {
		case AC_VERDICT_CLEAN:
			ac_printf("ELF File: %s -- VERDICT: %sFILE IS CLEAN%s\n",
			    current->filename, AC_COLOR_GREEN, AC_COLOR_END);
		      break;
		case AC_VERDICT_SUSPICIOUS:
			ac_printf("ELF File: %s -- VERDICT: %sFILE IS SUSPICIOUS%s\n",
			    current->filename, AC_COLOR_YELLOW, AC_COLOR_END);
			break;
		case AC_VERDICT_INFECTED:
			ac_printf("ELF File: %s -- VERDICT: %sFILE IS INFECTED%s\n",
			    current->filename, AC_COLOR_RED, AC_COLOR_END);
			break;
		default:
			ac_printf("ELF File: %s -- VERDICT: Unknown...\n");
			break;
		}
	}
	return true;
}

/*
 * Validates that the plugin type who's value is at the address of the
 * symbol for the object plugin_type, is a valid plugin type. It sets
 * the plugin type in ac_plugin_type_t *type
 */
bool
ac_plugin_validate_type(elfobj_t *elfobj, uint64_t symaddr, ac_plugin_type_t *type)
{
	bool res;
	uint64_t byte;

	*type = AC_PLUGIN_TYPE_UNKNOWN;

	res = elf_read_address(elfobj, symaddr, &byte, ELF_BYTE);
	if (res == false)
		return false;

	*type = byte;

	if ((ac_plugin_type_t)byte == AC_PLUGIN_PRE_HANDLER) {
		return true;
	} else if ((ac_plugin_type_t)byte == AC_PLUGIN_POST_HANDLER) {
		return true;
	} else if ((ac_plugin_type_t)byte == AC_PLUGIN_HEURISTICS_L1_HANDLER) {
		return true;
	} else if ((ac_plugin_type_t)byte == AC_PLUGIN_HEURISTICS_L2_HANDLER) {
		return true;
	}
	return false;
}

bool
ac_plugin_get_name(elfobj_t *elfobj, struct elf_symbol sym, char **plugin_name)
{
	bool res;
	uint64_t i = 0;
	uint64_t byte, vaddr;
	size_t read_size = elf_class(elfobj) == elfclass32 ? ELF_DWORD : ELF_QWORD;
	char buf[AC_MAX_PLUGIN_NAME_LEN];

	res = elf_read_address(elfobj, sym.value, &vaddr, read_size);
	if (res == false) {
		ac_printf("Failed to read symbol value for plugin_name at %#lx\n", sym.value);
		return false;
	}
	do {
		res = elf_read_address(elfobj, vaddr + i, &byte, ELF_BYTE);
		if (res == false) {
			*plugin_name = NULL;
			return false;
		}
		buf[i++] = byte;
		if (i >= AC_MAX_PLUGIN_NAME_LEN)
			break;
	} while(byte != '\0');

	ac_printf("Plugin name found: %s\n", buf);
	*plugin_name = strdup(buf);
	if (*plugin_name == NULL) {
		perror("malloc");
		return false;
	}
	return true;
}

bool
ac_plugin_validate(struct ac_plugin *plugin)
{
	struct elf_symbol sym;
	elf_symtab_iterator_t iter;
	uint32_t sym_count = 0;
	elf_iterator_res_t ires;
	const uint32_t PLUGIN_REQUIRED_SYMCOUNT = 4;
	elfobj_t *elfobj = &plugin->elfobj;
	ac_plugin_type_t plugin_type;

	elf_symtab_iterator_init(elfobj, &iter);
	for (;;) {
		ires = elf_symtab_iterator_next(&iter, &sym);
		switch (ires) {
		case ELF_ITER_NOTFOUND:
			break;
		case ELF_ITER_ERROR:
			return false;
		case ELF_ITER_DONE:
			if (sym_count == PLUGIN_REQUIRED_SYMCOUNT)
				return true;
			return false;
		case ELF_ITER_OK:
			if (strncmp(sym.name, "plugin_type", 11) == 0) {
				if (ac_plugin_validate_type(&plugin->elfobj,
				    sym.value, &plugin_type) == false) {
					ac_printf("Invalid plugin type: %d\n", plugin_type);
					return false;
				} else {
					ac_printf("Plugin type: %d\n", plugin_type);
					sym_count++;
					continue;
				}
			}
			if (strncmp(sym.name, "init_plugin", 11) == 0) {
				sym_count++;
				memcpy(&plugin->init_sym, &sym, sizeof(sym));
			}
			if (strncmp(sym.name, "exit_plugin", 11) == 0) {
				sym_count++;
				memcpy(&plugin->exit_sym, &sym, sizeof(sym));
			}
			if (strncmp(sym.name, "plugin_name", 11) == 0) {
				if (ac_plugin_get_name(&plugin->elfobj, sym,
				    &plugin->name) == false) {
					ac_printf("Plugin %s is missing a plugin_name\n",
					    plugin->file.path);
					return false;
				}
				sym_count++;
			}
			break;
		}
	}
	return true;
}

bool
ac_build_plugins(struct arcana_ctx *ac)
{
	DIR *dir;
	struct dirent *entry;
	struct ac_plugin *plugin;
	elf_error_t e;
	bool res;

	if ((ac->config.flags & AC_CONFIG_PLUGIN_DIR) == 0)
		return true;

	ac_printf("Opening plugin directory: %s\n", ac->config.plugin_dir);
	dir = opendir(ac->config.plugin_dir);
	if (dir == NULL) {
		ac_printf("opendir failed: %s\n", strerror(errno));
		return false;
	}
	for (;;) {
		char *p;
		/*
		 * TODO re-factor by taking this next chunk of code and
		 * storing it into a register_plugin() function.
		 */
		entry = readdir(dir);
		if (entry == NULL)
			break;
		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0) {
			continue;
		}
		plugin = ac_malloc(sizeof(*plugin), ac);
		/*
		 * Allocate enough memory for plugin path + filename
		 */
		plugin->file.path = malloc(strlen(ac->config.plugin_dir) +
		    strlen("/") + strlen(entry->d_name) + 1);
		strcpy(plugin->file.path, ac->config.plugin_dir);
		/*
		 * Ensure plugin directory ends with a '/'
		 */
		if (plugin->file.path[strlen(plugin->file.path) - 1] != '/')
			strcat(plugin->file.path, "/");
		p = strrchr(plugin->file.path, '/');
		assert(p != NULL);
		strcat(plugin->file.path, entry->d_name);
		plugin->file.basename = ac_strdup(entry->d_name, ac);

		res = elf_open_object(plugin->file.path, &plugin->elfobj,
		    ELF_LOAD_F_STRICT, &e);
		if (res == false) {
			ac_printf("Unable to load file '%s' from plugins: %s\n",
			    plugin->file.path, elf_error_msg(&e));
			free(plugin->file.path);
			free(plugin->file.basename);
			free(plugin);
			continue;
		}
		if (elf_type(&plugin->elfobj) != ET_DYN) {
			ac_printf("Plugin file: '%s' not in the correct format\n",
			    plugin->file.path);
			free(plugin->file.path);
			free(plugin->file.basename);
			free(plugin);
			continue;
		}
		if (ac_plugin_validate(plugin) == false) {
			ac_printf("Invalid plugin: %s\n",
			    plugin->file.path);
			free(plugin->file.path);
			free(plugin->file.basename);
			free(plugin);
			continue;
		}
		plugin->name = plugin->file.basename;
		ac_printf("Validated plugin: %s\n", plugin->file.path);
		ac_printf("Registered function: %s\n", plugin->init_sym.name);
		ac_printf("Registered function: %s\n", plugin->exit_sym.name);
		SLIST_INSERT_HEAD(&ac->config.plugin_list, plugin, _linkage);
	}
	return true;
}

/*
 * Load any plugin code
 */
static bool
ac_process_pre_plugins(struct arcana_ctx *ac, struct obj_struct *obj, void **arg)
{
	struct ac_plugin *current;
	bool (*plugin_fn)(arcana_ctx_t *, obj_struct_t *, void **);
	void (*plugin_exit)(arcana_ctx_t *, obj_struct_t *, void **);
	void *handle;
	bool res;

	(void) arg;

	ac_printf("Processing pre-plugins\n");
	/*
	 * Iterate over each plugin shared library and execute the
	 * init/exit function for each.
	 */
	SLIST_FOREACH(current, &ac->config.plugin_list, _linkage) {
		if (current->type != AC_PLUGIN_PRE_HANDLER)
			continue;
		/*
		 * We use strict symbol binding to make sure that the
		 * plugin doesn't result in failing for arbitrary reasons
		 * such as symbol version incompatibility etc.
		 */
		handle = dlopen(current->file.path, RTLD_NOW);
		if (handle == NULL) {
			ac_printf("dlopen failed on plugin: %s : %s\n",
			    current->file.path, strerror(errno));
			continue;
		}
		plugin_fn = dlsym(handle, current->init_sym.name);
		if (plugin_fn == NULL) {
			ac_printf("dlsym failed on loading function: %s\n",
			    current->init_sym.name);
			continue;
		}
		ac_printf("Calling pre-plugin functionality %s:%s()\n",
		    current->name, current->init_sym.name);
		res = plugin_fn(ac, obj, arg);
		(void) res;
		plugin_exit = dlsym(handle, current->exit_sym.name);
		if (plugin_exit == NULL) {
			ac_printf("dlsym failed on loading function: %s\n",
			    current->exit_sym.name);
			continue;
		}
		ac_printf("Calling plugin functionality %s:%s()\n",
		    current->name, current->exit_sym.name);
		plugin_exit(ac, obj, arg);
	}
	return true;
}

static bool
ac_process_post_plugins(struct arcana_ctx *ac, obj_struct_t *obj, void **arg)
{
	struct ac_plugin *current;
	bool (*plugin_fn)(arcana_ctx_t *, obj_struct_t *, void **);
	void (*plugin_exit)(arcana_ctx_t *, obj_struct_t *, void **);
	void *handle;

	(void) arg;

	ac_printf("Processing post-plugins\n");
	/*
	 * Iterate over each plugin shared library and execute the
	 * init/exit function for each.
	 */
	SLIST_FOREACH(current, &ac->config.plugin_list, _linkage) {
		if (current->type != AC_PLUGIN_POST_HANDLER)
			continue;
		/*
		 * We use strict symbol binding to make sure that the
		 * plugin doesn't result in failing for arbitrary reasons
		 * such as symbol version incompatibility etc.
		 */
		handle = dlopen(current->file.path, RTLD_NOW);
		if (handle == NULL) {
			ac_printf("dlopen failed on plugin: %s : %s\n",
			    current->file.path, strerror(errno));
			continue;
		}
		plugin_fn = dlsym(handle, current->init_sym.name);
		if (plugin_fn == NULL) {
			ac_printf("dlsym failed on loading function: %s\n",
			    current->init_sym.name);
			continue;
		}
		ac_printf("Calling post-plugin functionality %s:%s()\n",
		    current->name, current->init_sym.name);
		(void) plugin_fn(ac, obj, arg); /* Eventually check res value */

		plugin_exit = dlsym(handle, current->exit_sym.name);
		if (plugin_exit == NULL) {
			ac_printf("dlsym failed on loading function: %s\n",
			    current->exit_sym.name);
			continue;
		}
		ac_printf("Calling plugin functionality %s:%s()\n",
		    current->name, current->exit_sym.name);
		plugin_exit(ac, obj, arg);
	}
	return true;
}

bool
ac_process_layer1_plugins(struct arcana_ctx *ac, obj_struct_t *obj, void **arg)
{
	struct ac_plugin *current;
	bool (*plugin_fn)(arcana_ctx_t *, obj_struct_t *, void **);
	void (*plugin_exit)(arcana_ctx_t *, obj_struct_t *, void **);
	void *handle;

	(void) arg;

	ac_printf("Processing layer1-plugins\n");
	/*
	 * Iterate over each plugin shared library and execute the
	 * init/exit function for each.
	 */
	SLIST_FOREACH(current, &ac->config.plugin_list, _linkage) {
		if (current->type != AC_PLUGIN_HEURISTICS_L1_HANDLER)
			continue;
		/*
		 * We use strict symbol binding to make sure that the
		 * plugin doesn't result in failing for arbitrary reasons
		 * such as symbol version incompatibility etc.
		 */
		handle = dlopen(current->file.path, RTLD_NOW);
		if (handle == NULL) {
			ac_printf("dlopen failed on plugin: %s : %s\n",
			    current->file.path, strerror(errno));
			continue;
		}
		plugin_fn = dlsym(handle, current->init_sym.name);
		if (plugin_fn == NULL) {
			ac_printf("dlsym failed on loading function: %s\n",
			    current->init_sym.name);
			continue;
		}
		ac_printf("Calling layer1-plugin functionality %s:%s()\n",
		    current->name, current->init_sym.name);
		(void) plugin_fn(ac, obj, arg);

		plugin_exit = dlsym(handle, current->exit_sym.name);
		if (plugin_exit == NULL) {
			ac_printf("dlsym failed on loading function: %s\n",
			    current->exit_sym.name);
			continue;
		}
		ac_printf("Calling plugin functionality %s:%s()\n",
		    current->name, current->exit_sym.name);
		plugin_exit(ac, obj, arg);
	}
	return true;
}

bool
ac_process_layer2_plugins(struct arcana_ctx *ac, obj_struct_t *obj, void **arg)
{
	struct ac_plugin *current;
	bool (*plugin_fn)(arcana_ctx_t *, obj_struct_t *, void **);
	void (*plugin_exit)(arcana_ctx_t *, obj_struct_t *, void **);
	void *handle;

	(void) arg;

	ac_printf("Processing layer2-plugins\n");
	/*
	 * Iterate over each plugin shared library and execute the
	 * init/exit function for each.
	 */
	SLIST_FOREACH(current, &ac->config.plugin_list, _linkage) {
		if (current->type != AC_PLUGIN_HEURISTICS_L2_HANDLER)
			continue;
		/*
		 * We use strict symbol binding to make sure that the
		 * plugin doesn't result in failing for arbitrary reasons
		 * such as symbol version incompatibility etc.
		 */
		handle = dlopen(current->file.path, RTLD_NOW);
		if (handle == NULL) {
			ac_printf("dlopen failed on plugin: %s : %s\n",
			    current->file.path, strerror(errno));
			continue;
		}
		plugin_fn = dlsym(handle, current->init_sym.name);
		if (plugin_fn == NULL) {
			ac_printf("dlsym failed on loading function: %s\n",
			    current->init_sym.name);
			continue;
		}
		ac_printf("Calling layer2-plugin functionality %s:%s()\n",
		    current->name, current->init_sym.name);
		(void) plugin_fn(ac, obj, arg);

		plugin_exit = dlsym(handle, current->exit_sym.name);
		if (plugin_exit == NULL) {
			ac_printf("dlsym failed on loading function: %s\n",
			    current->exit_sym.name);
			continue;
		}
		ac_printf("Calling plugin functionality %s:%s()\n",
		    current->name, current->exit_sym.name);
		plugin_exit(ac, obj, arg);
	}
	return true;
}

__attribute__((unused)) void
ac_close_objects(struct arcana_ctx *ac)
{

}
