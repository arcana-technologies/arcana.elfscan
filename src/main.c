#define _GNU_SOURCE
#include <stdio.h>
#include "arcana.h"

bool
ac_process_file(char *filename, struct arcana_ctx *ac)
{
	struct obj_struct *obj =
	    ac->opts.single == true ? &ac->single.obj : ac_malloc(sizeof(*obj), ac);

	memset(obj, 0, sizeof(*obj));

	/*
	 * TODO put traversal through blacklist in its own
	 * function.
	 */
	if (ac_config_check(ac, AC_CONFIG_BLACKLIST) == true) {
		struct ac_file *bl_obj;

		SLIST_FOREACH(bl_obj, &ac->config.blacklist, _linkage) {
			if (strchr(bl_obj->path, '/') == NULL) {
				if (strstr(filename,
				    bl_obj->path) != NULL) {
					ac_printf("Ignoring blacklisted pattern match: %s\n", filename);
					return true;
				}
			} else {
				if (strcmp(filename, bl_obj->path) == 0) {
					ac_printf("Ignoring blacklisted pattern match: %s\n", filename);
					return true;
				}
			}
		}
	}
	if (access(filename, F_OK) != 0) {
		fprintf(stderr, "File: %s, does not exist\n", filename);
		return false;
	}
	if (access(filename, R_OK) != 0) {
		fprintf(stderr, "Read access denied on file: %s\n", filename);
		return false;
	}
	obj->elfobj = ac_malloc(sizeof(elfobj_t), ac);
	obj->filename = filename;
	/*
	 * A single elfobj_t is placed into the linked list, just as if
	 * we were procesing multiple ELF files.
	 */
	LIST_INIT(AC_LIST_HEAD(ac));
	ac_printf("Inserting single file \"%s\" into object list\n", filename);
	LIST_INSERT_HEAD(AC_LIST_HEAD(ac), obj, _linkage);
	return true;
}

int main(int argc, char **argv)
{
	arcana_ctx_t ac;
	int c;

	if (argc < 3) {
		printf("Usage: %s [-Ccedv] <dir|exec>\n", argv[0]);
		exit(EXIT_SUCCESS);
	}

	memset(&ac, 0, sizeof(ac));

	while ((c = getopt(argc, argv, "c:C:e:d:v")) != -1) {
		switch(c) {
		case 'C':
			ac.opts.config = true;
			ac.config_path = strdup(optarg);
			if (ac.config_path == NULL) {
				perror("strdup");
				exit(EXIT_FAILURE);
			}
			break;
		case 'e':
			ac.opts.single = true;
			ac.target_file = malloc(strlen(optarg) + 3);
			if (strchr(optarg, '/') == NULL) {
				ac.target_file[0] = '.';
				ac.target_file[1] = '/';
				strcpy(&ac.target_file[2], optarg);
			} else {
				strcpy(ac.target_file, optarg);
			}
			if (ac.target_file == NULL) {
				perror("strdup");
				exit(EXIT_FAILURE);
			}
			break;
		case 'd':
			ac.opts.dirscan = true;
			ac.dirpath = strdup(optarg);
			if (ac.dirpath == NULL) {
				perror("strdup");
				exit(EXIT_FAILURE);
			}
			break;
		case 'v':
			ac.opts.verbose = true;
			break;
		case 'c':
			ac.opts.container = true;
			ac.container = strdup(optarg);
			if (ac.container == NULL) {
				perror("strdup");
				exit(EXIT_FAILURE);
			}
			break;
		default:
			fprintf(stderr, "Unknown option");
			exit(EXIT_FAILURE);
		}
	}
	if (ac.opts.config == false) {
		ac.config_path = AC_DEFAULT_CONFIG_PATH;
	}
	if (ac_config_parse(&ac) == false) {
		ac_error("failed to parse configuration file: %s\n", ac.config_path);
		exit(EXIT_FAILURE);
	}
	if (ac_build_plugins(&ac) == false) {
		ac_error("Failed to build plugin list\n");
		exit(EXIT_FAILURE);
	}
	if (ac.opts.single == true) {
		ac_process_file(ac.target_file, &ac);
	}
	if (ac_process_objects(&ac) == false) {
		ac_error("Failed to process objects\n");
		exit(EXIT_FAILURE);
	}
	exit(EXIT_SUCCESS);
}
