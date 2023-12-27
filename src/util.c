#include "arcana.h"
#include "misc.h"

#include <sys/queue.h>
#include <sys/klog.h>

typedef struct ac_array_obj {
	void *data;
	size_t objsize;
	LIST_ENTRY(ac_array_obj) _linkage;
} ac_array_obj_t;

typedef struct ac_array_desc {
	LIST_HEAD(ac_array_list, ac_array_obj) array_list;
} ac_array_desc_t;

void
ac_exit_cleanly(struct arcana_ctx *ac, int exit_code)
{

	if (ac->opts.single == true) {
		free(ac->target_file);
		elf_close_object(ac->single.obj.elfobj);
	}
	exit(exit_code);
}

void *
ac_malloc(size_t len, arcana_ctx_t *ac)
{
	void *ptr;

	ptr = malloc(len);
	if (ptr == NULL) {
		perror("malloc");
		ac_exit_cleanly(ac, EXIT_FAILURE);
	}
	return ptr;
}

char *
ac_strdup(char *string, arcana_ctx_t *ac)
{
	char *s;

	s = strdup(string);
	if (s == NULL) {
		perror("strdup");
		ac_exit_cleanly(ac, EXIT_FAILURE);
	}
	return s;
}

bool
ac_address_in_range(uint64_t vaddr, uint64_t lo, uint64_t hi)
{
	if (vaddr >= lo && vaddr < hi)
		return true;
	return false;
}

void
ac_printf(char *fmt, ...)
{
	char buf[4096];
	va_list va;
	va_start(va, fmt);
	vsnprintf(buf, sizeof(buf), fmt, va);
	va_end(va);

	fprintf(stdout, "%s", buf);
	return;
}

void
ac_warning(char *fmt, ...)
{
	char buf[4096];
	va_list va;
	va_start(va, fmt);
	vsnprintf(buf, sizeof(buf), fmt, va);
	va_end(va);

	fprintf(stdout, "%s[WARNING]:%s %s%s%s", AC_COLOR_YELLOW, AC_COLOR_END, AC_COLOR_YELLOW, buf, AC_COLOR_END);
	return;
}
void
ac_alert(char *fmt, ...)
{
	char buf[4096];
	va_list va;
	va_start(va, fmt);
	vsnprintf(buf, sizeof(buf), fmt, va);
	va_end(va);

	fprintf(stdout, "%s[ALERT]%s %s%s%s", AC_COLOR_RED, AC_COLOR_END, AC_COLOR_RED, buf, AC_COLOR_END);
	return;
}

bool
ac_array_init(ac_array_desc_t *desc)
{

	memset(desc, 0, sizeof(*desc));
	LIST_INIT(&desc->array_list);
	return true;
}

bool
ac_array_grow(ac_array_desc_t *desc, ac_array_obj_t *arrobj, void *data)
{

	arrobj = calloc(1, sizeof(*arrobj));
	if (arrobj == NULL)
		return false;
	arrobj->data = data;
	LIST_INSERT_HEAD(&desc->array_list, arrobj, _linkage);
	return true;
}

bool
ac_array_destroy(ac_array_desc_t *desc)
{

	ac_array_obj_t *current, *next;

	LIST_FOREACH_SAFE(current, &desc->array_list, _linkage, next) {
		free(current);
	}
	return true;
}

void
ac_error(char *fmt, ...)
{
	char buf[8192];
	va_list va;

	va_start(va, fmt);
	vsnprintf(buf, sizeof(buf), fmt, va);
	va_end(va);

	//syslog(LOG_MAKEPRI(LOG_USER, LOG_WARNING), "%s",
	//    buf);
	fprintf(stderr, "%s", buf);
	return;
}
