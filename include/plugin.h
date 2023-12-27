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
