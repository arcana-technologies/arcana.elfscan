#include "arcana.h"

#include <ctype.h>
#include <sys/mman.h>

static bool
ac_config_classify_file(struct ac_file *file, const char *path)
{
	uint8_t *mem;
	bool bindata = false;
	struct stat st;
	int fd, i;
	char *p;

	if (access(path, F_OK) != 0) {
		perror("access");
		return false;
	}

	if (stat(path, &st) < 0) {
		perror("stat");
		return false;
	}

	/*
	 * Is the file executable?
	 * AC_FILE_EXEC
	 */
	if (st.st_mode & S_IXUSR) {
		file->flag |= AC_FILE_EXEC;
	} else if (st.st_mode & S_IXGRP) {
		file->flag |= AC_FILE_EXEC;
	} else if (st.st_mode & S_IXOTH) {
		file->flag |= AC_FILE_EXEC;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return false;
	}
	mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		return false;
	}
	for (p = (char *)mem, i = 0; i < st.st_size; i++) {
		if (isascii(p[i]) == false) {
			bindata = true;
			break;
		}
	}
	/*
	 * We are dealing with a 7bit ascii file
	 */
	if (bindata == false)
		file->flag |= AC_FILE_TEXT;

	if (memcmp(mem, ELFMAG, SELFMAG) == 0)
		file->flag |= AC_FILE_ELF;

	/*
	 * For now our heuristic to see if a file is a script
	 * is by seeing if its executable, and if its not an ELF
	 * file, but is a text file. In the future we can expand
	 * on this.
	 */
	if (file->flag & AC_FILE_EXEC) {
		if ((file->flag & AC_FILE_ELF) == 0) {
			if (file->flag & AC_FILE_TEXT)
				file->flag |= AC_FILE_SCRIPT;
		}
	}
	return true;
}
/*
 * TODO
 * In essence I believe this should actually be called `whitelist` and not `blacklist`
 * due to the fact that we are "allowing" certain shared libraries to use symbol interposition
 * without calling them out as a DT_NEEDED infection. This is due to cases where symbol
 * interposition is legitimate but appears infected, causing false positives. Hence we
 * have an injection whitelist that tells us which shared libraries are allowed to have
 * this anomaly situation. :)
 */
static bool
ac_config_process_injection_blacklist(arcana_ctx_t *ac, char *value)
{
	char *sp, *p, *np;
	char *ptr = value;

	SLIST_INIT(&ac->config.injection_blacklist);

	while ((p = strtok_r(ptr, ",: ", &sp)) != NULL) {
		struct ac_file *file = ac_malloc(sizeof(*file), ac);
		char *name = p;

		if (strchr(name, '/') != NULL) {
			np = strchr(name, '\n');
			if (np != NULL)
				*np = '\0';
			if (ac_config_classify_file(file, name) == false) {
				ac_printf("Unable to find and blacklist: %s\n", name);
				continue;
			}
			file->basename = ac_strdup(strrchr(name, '/') + 1, ac);
			file->path = ac_strdup(name, ac);
		} else {
			/*
			 * Unknown indicates its a basename, in which case
			 * we ignore all files with a given basename.
			 * i.e. all instances of ld-linux.so
			 */
			np = strchr(name, '\n');
			if (np != NULL)
				*np = '\0';
			file->flag |= AC_FILE_UNKNOWN;
			file->path = file->basename = ac_strdup(name, ac);
		}
		SLIST_INSERT_HEAD(&ac->config.injection_blacklist, file, _linkage);
		ptr = NULL;
	}
	return true;
}

static bool
ac_config_process_blacklist(arcana_ctx_t *ac, char *value)
{
	char *sp, *p, *np;
	char *ptr = value;

	SLIST_INIT(&ac->config.blacklist);

	while ((p = strtok_r(ptr, ",: ", &sp)) != NULL) {
		struct ac_file *file = ac_malloc(sizeof(*file), ac);
		char *name = p;

		if (strchr(name, '/') != NULL) {
			np = strchr(name, '\n');
			if (np != NULL)
				*np = '\0';
			if (ac_config_classify_file(file, value) == false) {
				ac_printf("Unable to find and blacklist: %s\n", name);
				continue;
			}
			file->basename = ac_strdup(strrchr(name, '/') + 1, ac);
			file->path = ac_strdup(name, ac);
		} else {
			/*
			 * Unknown indicates its a basename, in which case
			 * we ignore all files with a given basename.
			 * i.e. all instances of ld-linux.so
			 */
			np = strchr(name, '\n');
			if (np != NULL)
				*np = '\0';
			file->flag |= AC_FILE_UNKNOWN;
			file->path = file->basename = ac_strdup(name, ac);
		}
		ac_printf("Blacklisting file-path or file-path pattern: %s\n", file->path);
		SLIST_INSERT_HEAD(&ac->config.blacklist, file, _linkage);
		ptr = NULL;
	}
	return true;
}

static void
ac_config_process_option(struct arcana_ctx *ac, char *key, char *value)
{
	char *p;

	if (strcasecmp(key, "prevent") == 0) {
		if (strcasecmp(value, "true") == 0) {
			ac_printf("config: AC_CONFIG_PREVENT is true\n");
			ac->config.flags |= AC_CONFIG_PREVENT;
		}
	} else if (strcasecmp(key, "disinfect") == 0) {
		if (strcasecmp(value, "true") == 0) {
			ac_printf("config: AC_CONFIG_DISINFECT is true\n");
			ac->config.flags |= AC_CONFIG_DISINFECT;
		}
	} else if (strcasecmp(key, "aggressive") == 0) {
		if (strcasecmp(value, "true") == 0) {
			ac_printf("config: AC_CONFIG_AGGRESSIVE is true\n");
			ac->config.flags |= AC_CONFIG_AGGRESSIVE;
		}
	} else if (strcasecmp(key, "scan_lkms") == 0) {
		if (strcasecmp(value, "true") == 0) {
			ac_printf("config: AC_CONFIG_SCAN_LKMS is true\n");
			ac->config.flags |= AC_CONFIG_SCAN_LKMS;
		}
	} else if (strcasecmp(key, "classify_malware") == 0) {
		if (strcasecmp(value, "true") == 0) {
			ac_printf("config: AC_CONFIG_CLASSIFY is true\n");
			ac->config.flags |= AC_CONFIG_CLASSIFY;
		}
	} else if (strcasecmp(key, "intrusion_detection_mode") == 0) {
		if (strcasecmp(value, "true") == 0) {
			ac_printf("config: AC_CONFIG_INTRUSION_DETECTION_MODE is true\n");
			ac->config.flags |= AC_CONFIG_IDS_MODE;
		}
	} else if (strcasecmp(key, "plugin_location") == 0) {
		if (strcasecmp(value, "false") != 0) {
			ac_printf("config: AC_CONFIG_PLUGIN_DIR is true\n");
			ac->config.flags |= AC_CONFIG_PLUGIN_DIR;
			printf("Setting plugin_location: %s\n", value);
			ac->config.plugin_dir = (char *)ac_strdup(value, ac);
			p = strchr(ac->config.plugin_dir, '\n');
			if (p != NULL)
				*p = '\0';
			if (access(ac->config.plugin_dir, F_OK) != 0) {
				ac_printf("Failed to access %s for plugins, defaulting to %s\n",
				    ac->config.plugin_dir, AC_PLUGINS_DEFAULT_DIR);
				free((char *)ac->config.plugin_dir);
				ac->config.plugin_dir = ac_strdup(AC_PLUGINS_DEFAULT_DIR, ac);
			}
		}
	} else if (strcasecmp(key, "lightweight") == 0) {
		if (strcasecmp(value, "true") == 0) {
			ac_printf("config: AC_CONFIG_LIGHTWEIGHT is true\n");
			ac->config.flags |= AC_CONFIG_LIGHTWEIGHT;
		}
	} else if (strcasecmp(key, "container_root") == 0) {
		char *p2, *tmp;
		size_t len;

		if (strchr(value, '"') == NULL) {
			ac->config.container_root = ac_strdup(value, ac);
			ac_printf("config: CONTAINER ROOT: %s\n", value);
		} else {
			p = strchr(value, '"');
			if ((p2 = strrchr(value, '"')) != NULL) {
				if ((p2 - p) == 0) {
					ac_printf("config: container_root"
					    " directive is missing terminating quote \"\n");
					return;
				}
				len = p2 - p - 1;
				tmp = alloca(len + 1);
				strncpy(tmp, &p[1], len);
				tmp[len] = '\0';
				ac->config.container_root = ac_strdup(tmp, ac);
				ac_printf("config: CONTAINER ROOT: %s\n",
				    ac->config.container_root);
			}
		}
	}
	return;
}

bool
ac_config_parse(struct arcana_ctx *ac)
{
	char line[PATH_MAX];

	ac->config.fp = fopen(ac->config_path, "r");
	if (ac->config.fp == NULL) {
		perror("fopen");
		return false;
	}
	while (fgets(line, sizeof(line), ac->config.fp) != NULL) {
		char *p = line;
		char *key = line;
		char *value = NULL;

		if (*p == '#' || *p == '\n' || *p == '~') {
			continue;
		}
		while (*p == ' ')
			p++;
		while (*p != ' ' && *p != '=')
			p++;
		*p = '\0';
		value = strchr(p + 1, '=');
		if (value == NULL) {
			ac_printf("config: %s parse error\n", ac->config_path);
			exit(EXIT_FAILURE);
		}
		value += 1;
		while (*value == ' ')
			value++;
		if (strcasecmp(key, "blacklist") == 0) {
			ac_config_process_blacklist(ac, value);
			ac->config.flags |= AC_CONFIG_BLACKLIST;
		} else if (strcasecmp(key, "injection_blacklist") == 0) {
			ac_config_process_injection_blacklist(ac, value);
			ac->config.flags |= AC_CONFIG_INJECTION_BLACKLIST;
		} else {
			p = strchr(value, '\n');
			if (p != NULL)
				*p = '\0';
			ac_config_process_option(ac, key, value);
		}
	}
	fclose(ac->config.fp);
	return true;
}

bool
ac_config_check(struct arcana_ctx *ctx, config_flags_t flag)
{

	if (ctx->config.flags & flag)
		return true;
	return false;
}

