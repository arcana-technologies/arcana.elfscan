/*
 * Functions for supporting LXC containers.
 */

#include "arcana.h"
#include "misc.h"

bool
ac_container_ldso_cache(arcana_ctx_t *ac, char *ldso_cache, const size_t maxlen)
{
	char *p;
	char final[PATH_MAX];

	if (maxlen > PATH_MAX) {
		ac_printf("maxlen cannot exceed PATH_MAX\n");
		return false;
	}
	if ((strlen(ac->config.container_root) + strlen(ac->container) +
	    strlen("/rootfs/etc/ld.so.cache") + strlen("/") + 1) > maxlen) {
		ac_printf("Container path exceeds PATH_MAX\n");
		return false;
	}
	strcpy(final, ac->config.container_root);
	p = strrchr(final, '/');
	if (p != NULL) {
		if ((p - final) != strlen(final)) {
			/*
			 * The last instance of a '/' does not reside
			 * on the last byte of the path, so we must
			 * add one.
			 */
			strcat(final, "/");
		}
	}
	strcat(final, ac->container);
	strcat(final, "/rootfs/etc/ld.so.cache");
	strncpy(ldso_cache, final, PATH_MAX);
	ldso_cache[PATH_MAX - 1] = '\0';
	return true;
}
