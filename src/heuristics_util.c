#include "arcana.h"

bool
ac_heuristics_confidence_level(struct elfobj_infection_state *infstate, confidence_level_t c)
{

	return c == infstate->confidence;
}

bool
ac_heuristics_infection_data_flag(struct ac_infection_data *infdata, uint64_t flag)
{

	return ((infdata->data_flags & flag) > 0);
}

void
ac_heuristics_infection_set_hook_vaddr(struct ac_infection_data *infdata, uint64_t value)
{

	infdata->hook_vaddr = value;
	infdata->data_flags |= AC_INFECTION_HOOK_VADDR;
	return;
}

void
ac_heuristics_infection_set_reloc(struct ac_infection_data *infdata, struct elf_relocation *rel)
{

	memcpy(&infdata->rel, rel, sizeof(struct elf_relocation));
	infdata->data_flags |= AC_INFECTION_RELOC;
	return;
}

void
ac_heuristics_infection_set_pltgot_index(struct ac_infection_data *infdata, uint64_t value)
{

	infdata->got_index = value;
	infdata->data_flags |= AC_INFECTION_PLTGOT_INDEX;
	return;
}

void
ac_heuristics_infection_set_hook_location(struct ac_infection_data *infdata, uint64_t value)
{

	infdata->hook_location = value;
	infdata->data_flags |= AC_INFECTION_HOOK_LOCATION;
	return;
}

void
ac_heuristics_infection_set_count(struct ac_infection_data *infdata, uint64_t value)
{

	infdata->count = value;
	infdata->data_flags |= AC_INFECTION_COUNT;
	return;
}

void
ac_heuristics_infection_set_len(struct ac_infection_data *infdata, size_t value)
{

	infdata->len = value;
	infdata->data_flags |= AC_INFECTION_LEN;
}

void
ac_heuristics_infection_set_low_vaddr(struct ac_infection_data *infdata, uint64_t value)
{

	infdata->low_vaddr= value;
	infdata->data_flags |= AC_INFECTION_LO_VADDR;
	return;
}

void
ac_heuristics_infection_set_high_vaddr(struct ac_infection_data *infdata, uint64_t value)
{

	infdata->high_vaddr = value;
	infdata->data_flags |= AC_INFECTION_HI_VADDR;
	return;
}

bool
ac_heuristics_infection_get_member(struct ac_infection_data *infdata, uint64_t flag, uint32_t layer,
    void **ptr)
{

	if (layer > AC_INFECTION_L2)
		return false;

	if ((infdata[layer].data_flags & flag) == 0)
		return false;

	switch(flag) {
	case AC_INFECTION_HOOK_VADDR:
		if (ptr != NULL)
			*ptr = (void *)infdata[layer].hook_vaddr;
		break;
	case AC_INFECTION_HOOK_LOCATION:
		if (ptr != NULL)
			*ptr = (void *)infdata[layer].hook_location;
		break;
	case AC_INFECTION_VADDRS:
		if (ptr != NULL)
			*ptr = (void *)infdata[layer].vaddr;
		break;
	case AC_INFECTION_HI_VADDR:
		if (ptr != NULL)
			*ptr = (void *)infdata[layer].high_vaddr;
		break;
	case AC_INFECTION_LO_VADDR:
		if (ptr != NULL)
			*ptr = (void *)infdata[layer].low_vaddr;
		break;
	case AC_INFECTION_STRINGS:
		if (ptr != NULL)
			*ptr = (void *)infdata[layer].strings;
		break;
	case AC_INFECTION_LEN:
		if (ptr != NULL)
			*ptr = (void *)infdata[layer].len;
		break;
	case AC_INFECTION_COUNT:
		if (ptr != NULL)
			*ptr = (void *)infdata[layer].count;
		break;
	case AC_INFECTION_STRCOUNT:
		if (ptr != NULL)
			*ptr = (void *)infdata[layer].strcount;
		break;
	case AC_INFECTION_VADDR_COUNT:
		if (ptr != NULL)
			*ptr = (void *)infdata[layer].vaddr_count;
		break;
	case AC_INFECTION_PLTGOT_INDEX:
		if (ptr != NULL)
			*ptr = (void *)infdata[layer].got_index;
		break;
	default:
		return false;
	}
	return true;
}
