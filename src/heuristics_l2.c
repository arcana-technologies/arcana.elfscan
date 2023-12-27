#include "arcana.h"

__attribute__((unused)) static bool
ac_heuristics_l2_check_anomaly(struct arcana_ctx *ac, uint64_t flag)
{

	return (ac->anomaly_flags & flag);
}

static bool
ac_heuristics_get_l1_infection_data(struct obj_struct *obj, uint64_t flag,
    struct ac_infection_data *infdata)
{
	struct elfobj_infection_state *infection;

	TAILQ_FOREACH(infection, &obj->infection_state_list, _linkage) {
		/*
		 * NOTE: infection->anomaly_type can only be set to a single flag
		 * value corresponding to the type of infection that this
		 * item in the linked list represents. infection->anomaly_type
		 * will be set to either 0 or AC_ANOMALY_F_<infection_type>
		 * but not other flags will be set; this differs from ac->anomaly_type
		 * which contains a combination of all flags that resulted in positive
		 * for all l1 heuristic checks.
		 */
		if (infection->anomaly_type == flag) {
			if (infdata != NULL) {
				memcpy(infdata,
				    &infection->infection_data[AC_INFECTION_L1],
				    sizeof(*infdata));
			}
			return true;
		}
	}
	return false;
}

#if 0
static bool ac_heuristics_l2_reloc_hooks(struct obj_struct *obj,
    struct elfobj_infection_state *infection, uint64_t low_vaddr,
    uint64_t high_vaddr, uint64_t *hook_vaddr, uint64_t reloc_hook_flags)
{

	return true;
}

#endif
static ac_hooks_t
ac_heuristics_l2_hook_check(struct obj_struct *obj,
    struct elfobj_infection_state *infection, uint64_t low_vaddr,
    uint64_t high_vaddr, uint64_t *out)
{
	uint64_t ep;
	ac_infection_data_t infdata;

	/*
	 * Check for hooked elfhdr->e_entry
	 */
	ep = elf_entry_point(obj->elfobj);
	if (ep != 0) {
		if (ep >= low_vaddr && ep < high_vaddr) {
			*out = ep;
			return AC_HOOK_TYPE_ENTRYPOINT;
		}
	}
	/*
	 * Check for hooked DT_INIT/DT_FINI
	 */
	if (ac_heuristics_get_l1_infection_data(obj, AC_ANOMALY_F_INIT_HOOK,
	    &infdata) == true) {
		if ((ac_heuristics_infection_get_member(infection->infection_data,
		    AC_INFECTION_LO_VADDR, AC_INFECTION_L1,
		    (void **)&low_vaddr) == true) &&
		    (ac_heuristics_infection_get_member(infection->infection_data,
		    AC_INFECTION_HI_VADDR, AC_INFECTION_L1,
		    (void **)&high_vaddr) == true)) {
			if (infdata.hook_vaddr >= low_vaddr &&
			    infdata.hook_vaddr < high_vaddr) {
				*out = infdata.hook_vaddr;
				return AC_HOOK_TYPE_INIT;
			}
		}
	} else if (ac_heuristics_get_l1_infection_data(obj, AC_ANOMALY_F_FINI_HOOK,
		&infdata) == true) {
		if ((ac_heuristics_infection_get_member(infection->infection_data,
		    AC_INFECTION_LO_VADDR, AC_INFECTION_L1,
		    (void **)&low_vaddr) == true) &&
		    (ac_heuristics_infection_get_member(infection->infection_data,
		    AC_INFECTION_HI_VADDR, AC_INFECTION_L1,
		    (void **)&high_vaddr) == true)) {
			if (infdata.hook_vaddr >= low_vaddr &&
			    infdata.hook_vaddr < high_vaddr) {
				*out = infdata.hook_vaddr;
				return AC_HOOK_TYPE_FINI;
			}
		}
	} else if (ac_heuristics_get_l1_infection_data(obj, AC_ANOMALY_F_MODIFIED_CTORS,
	    &infdata) == true) {
		if ((ac_heuristics_infection_get_member(infection->infection_data,
		    AC_INFECTION_LO_VADDR, AC_INFECTION_L1,
		    (void **)&low_vaddr) == true) &&
		    (ac_heuristics_infection_get_member(infection->infection_data,
		    AC_INFECTION_HI_VADDR, AC_INFECTION_L1,
		    (void **)&high_vaddr) == true)) {
			if (infdata.hook_vaddr >= low_vaddr &&
			    infdata.hook_vaddr < high_vaddr) {
				*out = infdata.hook_vaddr;
				return AC_HOOK_TYPE_CTORS;
			}
		}
	} else if (ac_heuristics_get_l1_infection_data(obj, AC_ANOMALY_F_MODIFIED_CTORS,
	    &infdata) == true) {
		if ((ac_heuristics_infection_get_member(infection->infection_data,
		    AC_INFECTION_LO_VADDR, AC_INFECTION_L1,
		    (void **)&low_vaddr) == true) &&
		    (ac_heuristics_infection_get_member(infection->infection_data,
		    AC_INFECTION_HI_VADDR, AC_INFECTION_L1,
		    (void **)&high_vaddr) == true)) {
			if (infdata.hook_vaddr >= low_vaddr &&
			    infdata.hook_vaddr < high_vaddr) {
				*out = infdata.hook_vaddr;
				return AC_HOOK_TYPE_DTORS;
			}
		}
	}
	return AC_HOOK_TYPE_NONE;
}

bool
ac_heuristics_l2_packed_executable(struct arcana_ctx *ac, struct obj_struct *obj,
    struct elfobj_infection_state *infection, bool *hres)
{
	struct ac_infection_data infdata;
	size_t load_count = 0;

	*hres = false;

	/*
	 * At this point we have used entropy in the L1 heuristics to
	 * determine that the file is likely compressed or encrypted.
	 * At this point we look for other factors to help determine
	 * this. Primarily looking for the indirect signs of an ELF stub--
	 * typically an ELF stub will contain one or two program headers
	 * of type PT_LOAD, and a GNU_STACK program header. Sometimes
	 * the PT_LOAD segments will violate DEP, i.e. a writable
	 * text segment or an executable data segment.
	 */

	assert((ac_heuristics_get_l1_infection_data(obj,
	    AC_ANOMALY_F_PACKED_BINARY, NULL) == true));

	if (ac_heuristics_get_l1_infection_data(obj,
	    AC_ANOMALY_F_EXECUTABLE_DATA, NULL) == true) {
		ac_alert("ELF Object: %s <-> has an executable data segment "
		    "housing obfuscated code\n", elf_pathname(obj->elfobj));
		ac_heuristics_confidence_set(infection, CONFIDENCE_LEVEL_HIGH);
		*hres = true;
	}
	if (ac_heuristics_get_l1_infection_data(obj,
	    AC_ANOMALY_F_WRITABLE_TEXT, NULL) == true) {
		ac_alert("ELF Object: %s <-> has a writable text segment "
		    "housing obfuscated code\n", elf_pathname(obj->elfobj));
		ac_heuristics_confidence_set(infection, CONFIDENCE_LEVEL_HIGH);
		*hres = true;
	}

	if (elf_flags(obj->elfobj, ELF_MERGED_SEGMENTS_F) == true) {
		ac_alert("ELF Object: %s <-> has a single PT_LOAD segment "
		    "housing obfuscated code\n", elf_pathname(obj->elfobj));
		ac_heuristics_confidence_set(infection, CONFIDENCE_LEVEL_HIGH);
		*hres = true;
	}

	if (ac_heuristics_get_l1_infection_data(obj,
	    AC_ANOMALY_F_NOSTDLIB_LINKING, NULL) == true) {
		ac_alert("ELF Object: %s <-> built with -nostdlib linking"
		    " which indicates a stub\n");
		ac_heuristics_confidence_set(infection, CONFIDENCE_LEVEL_HIGH);
		*hres = true;
	}
	if (elf_linking_type(obj->elfobj) != ELF_LINKING_DYNAMIC) {
		ac_alert("ELF Object: %s <-> statically linked with high entropy"
		    " indicates high probability of ELF binary packing\n",
		    elf_pathname(obj->elfobj));
		ac_heuristics_confidence_set(infection, CONFIDENCE_LEVEL_HIGH);
		*hres = true;
	}
	return true;
}

bool
ac_heuristics_l2_pltgot_infection(struct arcana_ctx *ac, struct obj_struct *obj,
    struct elfobj_infection_state *infection, bool *hres)
{
	*hres = false;
	uint64_t hook_vaddr, got_index, low_vaddr, high_vaddr;
	struct ac_infection_data infdata;

	assert((ac_heuristics_get_l1_infection_data(obj,
	    AC_ANOMALY_F_GOTPLT_INFECTION, NULL) == true));

	(void) ac_heuristics_infection_get_member(infection->infection_data,
	    AC_INFECTION_PLTGOT_INDEX, AC_INFECTION_L1, (void **)&got_index);
	(void) ac_heuristics_infection_get_member(infection->infection_data,
	    AC_INFECTION_HOOK_VADDR, AC_INFECTION_L1, (void **)&hook_vaddr);

	if (ac_heuristics_get_l1_infection_data(obj,
	    AC_ANOMALY_F_TEXT_PAD_INFECTION, &infdata) == true) {
	    (void) ac_heuristics_infection_get_member(&infdata,
		    AC_INFECTION_LO_VADDR, AC_INFECTION_L1, (void **)&low_vaddr);
		(void) ac_heuristics_infection_get_member(&infdata,
		    AC_INFECTION_HI_VADDR, AC_INFECTION_L1, (void **)&high_vaddr);
		if (hook_vaddr >= low_vaddr && hook_vaddr < high_vaddr) {
			ac_alert("ELF Object: %s <-> Infected .got.plt[%zu] redirects"
			    " control flow into text\n"
			    "segment padding infection at %#lx\n", elf_pathname(obj->elfobj),
			    got_index, hook_vaddr);
			*hres = true;
			return true;
		}
	} else if (ac_heuristics_get_l1_infection_data(obj,
	    AC_ANOMALY_F_TEXT_REVERSE_INFECTION, &infdata) == true) {
		(void) ac_heuristics_infection_get_member(&infdata,
		AC_INFECTION_LO_VADDR, AC_INFECTION_L1, (void **)&low_vaddr);
		(void) ac_heuristics_infection_get_member(&infdata,
		    AC_INFECTION_HI_VADDR, AC_INFECTION_L1, (void **)&high_vaddr);
		if (hook_vaddr >= low_vaddr && hook_vaddr < high_vaddr) {
			ac_alert("ELF Object: %s <-> Infected .got.plt[%zu] redirects"
			    " control flow into reverse\n"
			    "text infection at %#lx\n", elf_pathname(obj->elfobj),
			    got_index, hook_vaddr);
			*hres = true;
			return true;
		}
	}
	return true;
}

bool
ac_heuristics_l2_text_padding_infection(struct arcana_ctx *ac, struct obj_struct *obj,
    struct elfobj_infection_state *infection, bool *hres)
{
	*hres = false;
	uint64_t hook_vaddr, low_vaddr, high_vaddr;
	struct elf_section shdr;
	ac_hooks_t hook_type;

	assert((ac_heuristics_get_l1_infection_data(obj,
	    AC_ANOMALY_F_TEXT_PAD_INFECTION, NULL) == true));

	(void) ac_heuristics_infection_get_member(infection->infection_data,
	    AC_INFECTION_LO_VADDR, AC_INFECTION_L1, (void **)&low_vaddr);
	(void) ac_heuristics_infection_get_member(infection->infection_data,
	    AC_INFECTION_HI_VADDR, AC_INFECTION_L1, (void **)&high_vaddr);

	hook_type = ac_heuristics_l2_hook_check(obj, infection, low_vaddr,
	    high_vaddr, &hook_vaddr);
	switch(hook_type) {
	case AC_HOOK_TYPE_ENTRYPOINT:
		ac_alert("ELF Object: %s <-> has a modified entry point "
		    "that transfers control flow into the"
		    " text padding infection at address: %#lx\n",
		    elf_pathname(obj->elfobj), hook_vaddr);
		infection->confidence = CONFIDENCE_LEVEL_HIGH;
		break;
	case AC_HOOK_TYPE_INIT:
		ac_alert("ELF Object: %s <-> "
		    " has a modified DT_INIT hook "
		    "that transfers control flow into the "
		    "text padding "
		    "infection at address: %#lx\n",
			elf_pathname(obj->elfobj), hook_vaddr);
		infection->confidence = CONFIDENCE_LEVEL_HIGH;
		break;
	case AC_HOOK_TYPE_FINI:
		ac_alert("ELF Object: %s <-> "
		    " has a modified DT_FINI hook "
		    "that transfers control flow into the "
		    "text padding "
		    "infection at address: %#lx\n",
			elf_pathname(obj->elfobj), hook_vaddr);
		infection->confidence = CONFIDENCE_LEVEL_HIGH;
		break;
	case AC_HOOK_TYPE_CTORS:
		ac_alert("ELF Object: %s <-> "
		    " has a modified DT_INIT_ARRAY (.ctors) hook "
		    "that transfers control flow into the "
		    "text padding "
		    "infection at address: %#lx\n",
		     elf_pathname(obj->elfobj), hook_vaddr);
		infection->confidence = CONFIDENCE_LEVEL_HIGH;
		break;
	case AC_HOOK_TYPE_DTORS:
		ac_alert("ELF Object: %s <-> "
		    " has a modified DT_FINI_ARRAY (.dtors) hook "
		    "that transfers control flow into the "
		    "text padding "
		    "infection at address: %#lx\n",
		    elf_pathname(obj->elfobj), hook_vaddr);
		    infection->confidence = CONFIDENCE_LEVEL_HIGH;
		break;
	case AC_HOOK_TYPE_NONE:
	default:
		break;
	}

	// This is a special case that must be handled first, since the
	// infection low_vaddr will not be pointing to the .dynstr section
	// and the confidence of this metric is explicitly HIGH
	if (elf_section_by_name(obj->elfobj, ".dynstr", &shdr) == true) {
		if (shdr.address >= low_vaddr && shdr.address < high_vaddr) {
			ac_alert("ELF Object: %s <-> Is using a text padding "
			    "infection to host section: \".dynstr\"\n",
			    elf_pathname(obj->elfobj));
			infection->confidence = CONFIDENCE_LEVEL_HIGH;

			// Shortcut out as this is the most specific we can get
			return true;
		}
	}

	if (ac_heuristics_confidence_level(infection,
		CONFIDENCE_LEVEL_HIGH) == true) {
		struct elf_section shdr;

		*hres = true;
		ac_alert("ELF Object: %s <-> has a text padding infection"
			" in the section: %s in the range: %#lx-%#lx\n",
			elf_pathname(obj->elfobj),
			ac_internal_elf_shdr_name_by_address(obj->elfobj, low_vaddr, &shdr),
			low_vaddr, high_vaddr);
	}
	return true;
}

/*
 * L2 Reverse text alogirithm:
 * Look at results of L1 reverse text infection analysis--
 * Look for any hooks that transfer control flow into
 * the address range of the reverse text padding area:
 * Check: e_entry, DT_INIT, DT_FINI, DT_INIT_ARRAY, DT_FINI_ARRAY
 */
bool
ac_heuristics_l2_reverse_text_infection(struct arcana_ctx *ac, struct obj_struct *obj,
    struct elfobj_infection_state *infection, bool *hres)
{
	*hres = false;
	uint64_t hook_vaddr, low_vaddr, high_vaddr;
	struct elf_section shdr;
	ac_hooks_t hook_type;

	/*
	 * Retrieve the L1 infection data and store it into
	 * infection_data[AC_INFECTION_l2], and if this returns
	 * true then we know that the AC_ANOMALY_F_TEXT_REVERSE_INFECTION
	 * exists. If we got into this function then the text_reverse_infection
	 * should always be true hence the assert.
	 */
	assert((ac_heuristics_get_l1_infection_data(obj,
	    AC_ANOMALY_F_TEXT_REVERSE_INFECTION, NULL) == true));
		/*
		 * If the l1 heuristic check for this infection type set
		 * the hook_vaddr-- which this particular heuristic in the l1
		 * will set if it finds that the ehdr->e_entry is pointing to
		 * a location in the reverse text padding area then it will
		 * set the hook value to ehdr->e_entry.
		 */

	(void) ac_heuristics_infection_get_member(infection->infection_data,
	    AC_INFECTION_LO_VADDR, AC_INFECTION_L1, (void **)&low_vaddr);
	(void) ac_heuristics_infection_get_member(infection->infection_data,
	    AC_INFECTION_HI_VADDR, AC_INFECTION_L1, (void **)&high_vaddr);

	/*
	 * Lets look for other signs of proving that the reverse text padding
	 * infection is legitimate, such as hooks pointing into it.
	 */
	hook_type = ac_heuristics_l2_hook_check(obj, infection, low_vaddr,
	    high_vaddr, &hook_vaddr);
	switch(hook_type) {
	case AC_HOOK_TYPE_ENTRYPOINT:
		ac_alert("ELF Object: %s <-> has a modified entry point "
		    "that transfers control flow into the"
		    " reverse text infection at address: %#lx\n",
		    elf_pathname(obj->elfobj), hook_vaddr);
		infection->confidence = CONFIDENCE_LEVEL_HIGH;
		break;
	case AC_HOOK_TYPE_INIT:
		ac_alert("ELF Object: %s <-> "
		    " has a modified DT_INIT hook "
		    "that transfers control flow into the "
		    "reverse text "
		    "infection at address: %#lx\n",
			elf_pathname(obj->elfobj), hook_vaddr);
		infection->confidence = CONFIDENCE_LEVEL_HIGH;
		break;
	case AC_HOOK_TYPE_FINI:
		ac_alert("ELF Object: %s <-> "
		    " has a modified DT_FINI hook "
		    "that transfers control flow into the "
		    "reverse text "
		    "infection at address: %#lx\n",
			elf_pathname(obj->elfobj), hook_vaddr);
		infection->confidence = CONFIDENCE_LEVEL_HIGH;
		break;
	case AC_HOOK_TYPE_CTORS:
		ac_alert("ELF Object: %s <-> "
		    " has a modified DT_INIT_ARRAY (.ctors) hook "
		    "that transfers control flow into the "
		    "reverse text "
		    "infection at address: %#lx\n",
		     elf_pathname(obj->elfobj), hook_vaddr);
		infection->confidence = CONFIDENCE_LEVEL_HIGH;
		break;
	case AC_HOOK_TYPE_DTORS:
		ac_alert("ELF Object: %s <-> "
		    " has a modified DT_FINI_ARRAY (.dtors) hook "
		    "that transfers control flow into the "
		    "reverse text "
		    "infection at address: %#lx\n",
		    elf_pathname(obj->elfobj), hook_vaddr);
		    infection->confidence = CONFIDENCE_LEVEL_HIGH;
		break;
	case AC_HOOK_TYPE_NONE:
	default:
		break;
	}

	// This is a special case that must be handled first, since the
	// infection low_vaddr will not be pointing to the .dynstr section
	// and the confidence of this metric is explicitly HIGH
	if (elf_section_by_name(obj->elfobj, ".dynstr", &shdr) == true) {
		if (shdr.address >= low_vaddr && shdr.address < high_vaddr) {
			ac_alert("ELF Object: %s <-> Is using a reverse text "
			    "padding to host section: \".dynstr\"\n",
			    elf_pathname(obj->elfobj));
			infection->confidence = CONFIDENCE_LEVEL_HIGH;

			// Shortcut out as this is the most specific we can get
			return true;
		}
	}

	if (ac_heuristics_confidence_level(infection,
		CONFIDENCE_LEVEL_HIGH) == true) {
		struct elf_section shdr;

		*hres = true;
		ac_alert("ELF Object: %s <-> has reverse text infection padding"
			" in the section: %s in the range: %#lx-%#lx\n",
			elf_pathname(obj->elfobj),
			ac_internal_elf_shdr_name_by_address(obj->elfobj, low_vaddr, &shdr),
			low_vaddr, high_vaddr);
	}

	return true;
}

bool
ac_heuristics_l2_pt_note_infection(struct arcana_ctx *ac, struct obj_struct *obj,
    struct elfobj_infection_state *infection, bool *hres)
{
	*hres = false;
	uint64_t hook_vaddr, low_vaddr, high_vaddr;
	struct elf_section shdr;
	ac_hooks_t hook_type;

	assert((ac_heuristics_get_l1_infection_data(obj,
	    AC_ANOMALY_F_PT_NOTE_CONVERSION,
	    &infection->infection_data[AC_INFECTION_L2]) == true));

	(void) ac_heuristics_infection_get_member(infection->infection_data,
	    AC_INFECTION_LO_VADDR, AC_INFECTION_L1, (void **)&low_vaddr);
	(void) ac_heuristics_infection_get_member(infection->infection_data,
	    AC_INFECTION_HI_VADDR, AC_INFECTION_L1, (void **)&high_vaddr);

	hook_type = ac_heuristics_l2_hook_check(obj, infection, low_vaddr,
	   high_vaddr, &hook_vaddr);
	switch(hook_type) {
	case AC_HOOK_TYPE_ENTRYPOINT:
		ac_alert("ELF Object: %s <-> has a modified entry point "
		    "that transfers control flow into the"
		    " PT_NOTE infection at address: %#lx\n",
		    elf_pathname(obj->elfobj), hook_vaddr);
		infection->confidence = CONFIDENCE_LEVEL_HIGH;
		break;
	case AC_HOOK_TYPE_INIT:
		ac_alert("ELF Object: %s <-> "
		    " has a modified DT_INIT hook "
		    "that transfers control flow into the "
		    "PT_NOTE "
		    "infection at address: %#lx\n",
			elf_pathname(obj->elfobj), hook_vaddr);
		infection->confidence = CONFIDENCE_LEVEL_HIGH;
		break;
	case AC_HOOK_TYPE_FINI:
		ac_alert("ELF Object: %s <-> "
		    " has a modified DT_FINI hook "
		    "that transfers control flow into the "
		    "PT_NOTE "
		    "infection at address: %#lx\n",
			elf_pathname(obj->elfobj), hook_vaddr);
		infection->confidence = CONFIDENCE_LEVEL_HIGH;
		break;
	case AC_HOOK_TYPE_CTORS:
		ac_alert("ELF Object: %s <-> "
		    " has a modified DT_INIT_ARRAY (.ctors) hook "
		    "that transfers control flow into the "
		    "PT_NOTE "
		    "infection at address: %#lx\n",
		    elf_pathname(obj->elfobj), hook_vaddr);
		infection->confidence = CONFIDENCE_LEVEL_HIGH;
		break;
	case AC_HOOK_TYPE_DTORS:
		ac_alert("ELF Object: %s <-> "
		    " has a modified DT_FINI_ARRAY (.dtors) hook "
		    "that transfers control flow into the "
		    "PT_NOTE "
		    "infection at address: %#lx\n",
		    elf_pathname(obj->elfobj), hook_vaddr);
		    infection->confidence = CONFIDENCE_LEVEL_HIGH;
		break;
	case AC_HOOK_TYPE_NONE:
	default:
		break;
	}

	if (ac_heuristics_confidence_level(infection,
	    CONFIDENCE_LEVEL_HIGH) == true) {
		struct elf_section shdr;

		*hres = true;
		ac_alert("ELF Object: %s <-> has a PT_NOTE infection"
		    " in the range: %#lx-%#lx\n",
		    elf_pathname(obj->elfobj), low_vaddr, high_vaddr);
	}
	return true;
}

bool
ac_heuristics_2(struct arcana_ctx *ac, struct obj_struct *obj,
    struct elfobj_infection_state *infection)
{
	bool res, hres;
	static uint32_t unsafe_static_count = 0;
	uint32_t final_result = 0;

	/*
	 * Look deeper into reverse text infection. Is it
	 * actually an infection? Is it just an anomalous binary
	 * with an unusual virtual address base? We will take
	 * a number of things into consideration. If the confidence
	 * level is already high then lets see if its being used
	 * to store code or data-- i.e. making room for a .dynstr
	 * for shared library injection. If its a PIE executable
	 * this infection is impossible so we will not do anything
	 * in that case.
	 */
	if (infection->anomaly_type == AC_ANOMALY_F_TEXT_REVERSE_INFECTION) {
		res = ac_heuristics_l2_reverse_text_infection(ac, obj, infection, &hres);
		if (res == false) {
			ac_printf("Unable to perform L2 heuristics in reverse text infection\n");
		}
	}
	if (infection->anomaly_type == AC_ANOMALY_F_PT_NOTE_CONVERSION) {
		res = ac_heuristics_l2_pt_note_infection(ac, obj, infection, &hres);
		if (res == false) {
			ac_printf("Unable to perform L2 heuristics in PT_NOTE infection\n");
		}
	}
	if (infection->anomaly_type == AC_ANOMALY_F_TEXT_PAD_INFECTION) {
		res = ac_heuristics_l2_text_padding_infection(ac, obj, infection, &hres);
		if (res == false) {
			ac_printf("Unable to perform L2 heuristics in text padding infection\n");
		}
	}
	if (infection->anomaly_type == AC_ANOMALY_F_PACKED_BINARY) {
		res = ac_heuristics_l2_packed_executable(ac, obj, infection, &hres);
		if (res == false) {
			ac_printf("Unable to perform L2 heuristics on probable packed binary\n");
		}
	}
	if (infection->anomaly_type == AC_ANOMALY_F_GOTPLT_INFECTION) {
		res = ac_heuristics_l2_pltgot_infection(ac, obj, infection, &hres);
		if (res == false) {
			ac_printf("Unable to perform got.plt heuristics on probable packed binary\n");
		}
	}
	return true;
}
