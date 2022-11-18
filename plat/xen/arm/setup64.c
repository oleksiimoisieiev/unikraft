/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
/* Ported from Mini-OS */

#include <arm/smccc.h>
#include <xen-arm/os.h>
#include <xen-arm/mm.h>
#include <common/events.h>
#include <common/console.h>
#include <xen/xen.h>
#include <uk/plat/memory.h>
#include <xen/memory.h>
#include <xen/intctrl.h>
#include <xen/hvm/params.h>
#include <libfdt.h>
#include <xen-arm/setup.h>
#include <gic/gic.h>
#include <uk/plat/common/lcpu.h>

/*
 * This structure contains start-of-day info, such as pagetable base pointer,
 * address of the shared_info structure, and things like that.
 * On x86, the hypervisor passes it to us. On ARM, we fill it in ourselves.
 */

/*
 * Shared page for communicating with the hypervisor.
 * Events flags go here, for example.
 */
shared_info_t *HYPERVISOR_shared_info;

union start_info_union start_info_union;

extern char shared_info_page[PAGE_SIZE];
extern lpae_t boot_l1_pgtable[512];
extern lpae_t fixmap_pgtable[512];

void *HYPERVISOR_dtb;
/*
 * Physical address offset
 */
paddr_t _libxenplat_paddr_offset;

smccc_conduit_fn_t smccc_psci_call;

/*
 * Memory region description
 */
#define UKPLAT_MEMRD_MAX_ENTRIES 7
unsigned int _libxenplat_mrd_num;
struct ukplat_memregion_desc _libxenplat_mrd[UKPLAT_MEMRD_MAX_ENTRIES];

static int hvm_get_parameter(int idx, uint64_t *value)
{
	struct xen_hvm_param xhv;
	int ret;

	xhv.domid = DOMID_SELF;
	xhv.index = idx;
	ret = HYPERVISOR_hvm_op(HVMOP_get_param, &xhv);
	if (ret < 0)
		BUG();

	*value = xhv.value;
	return ret;
}

/*
 * Command line handling
 */
#define MAX_CMDLINE_SIZE 1024
static char cmdline[MAX_CMDLINE_SIZE];

static xen_pfn_t map_console(xen_pfn_t mfn)
{
	paddr_t phys;

	phys = PFN_PHYS(mfn);
	uk_pr_debug("%s, phys = 0x%lx\n", __func__, phys);

	set_pgt_entry(&fixmap_pgtable[l2_pgt_idx(FIX_CON_START)],
				  ((phys & L2_MASK) | BLOCK_DEV_ATTR | L2_BLOCK));

	return (xen_pfn_t) (FIX_CON_START + (phys & L2_OFFSET));
}

static xen_pfn_t map_xenbus(xen_pfn_t mfn)
{
	paddr_t phys;

	phys = PFN_PHYS(mfn);
	uk_pr_debug("%s, phys = 0x%lx\n", __func__, phys);

	set_pgt_entry(&fixmap_pgtable[l2_pgt_idx(FIX_XS_START)],
				  ((phys & L2_MASK) | BLOCK_DEV_ATTR | L2_BLOCK));

	return (xen_pfn_t) (FIX_XS_START + (phys & L2_OFFSET));
}

static void get_console(void)
{
	uint64_t v = -1;

	hvm_get_parameter(HVM_PARAM_CONSOLE_EVTCHN, &v);
	HYPERVISOR_start_info->console.domU.evtchn = v;

	hvm_get_parameter(HVM_PARAM_CONSOLE_PFN, &v);
#if defined(__aarch64__)
	HYPERVISOR_start_info->console.domU.mfn = map_console(v);
#else
	HYPERVISOR_start_info->console.domU.mfn = v;
#endif

	uk_pr_debug("Console is on port %d\n",
				HYPERVISOR_start_info->console.domU.evtchn);
	uk_pr_debug("Console ring is at mfn %lx\n",
				(unsigned long)HYPERVISOR_start_info->console.domU.mfn);
}

void get_xenbus(void)
{
	uint64_t value;

	if (hvm_get_parameter(HVM_PARAM_STORE_EVTCHN, &value))
		BUG();

	HYPERVISOR_start_info->store_evtchn = (int)value;

	if (hvm_get_parameter(HVM_PARAM_STORE_PFN, &value))
		BUG();
#if defined(__aarch64__)
	HYPERVISOR_start_info->store_mfn = map_xenbus(value);
#else
	HYPERVISOR_start_info->store_mfn = value;
#endif
	uk_pr_debug("xenbus mfn(pfn?) = %lx\n",
				HYPERVISOR_start_info->store_mfn);
}

/*
 * Map device_tree (paddr) to FIX_FDT_START (vaddr)
 */
static void *map_fdt(paddr_t device_tree)
{
	/*
	 * FIXME: To deal with the 2M alignment, only 4KB space is usable
	 * because device_tree is aligned to a (2M - 4KB) address.
	 */
	set_pgt_entry(&boot_l1_pgtable[l1_pgt_idx(FIX_FDT_START)],
				  (to_phys(fixmap_pgtable) | L1_TABLE));
	set_pgt_entry(&fixmap_pgtable[l2_pgt_idx(FIX_FDT_START)],
				  ((device_tree & L2_MASK) | BLOCK_DEF_ATTR | L2_BLOCK));

	return (void *)(FIX_FDT_START + (device_tree & L2_OFFSET));
}

static inline void _dtb_get_cmdline(char *cmdline, size_t maxlen)
{
	int fdtchosen, len;
	const char *fdtcmdline;

	/* TODO: Proper error handling */
	fdtchosen = fdt_path_offset(HYPERVISOR_dtb, "/chosen");
	if (!fdtchosen)
		goto enocmdl;
	fdtcmdline = fdt_getprop(HYPERVISOR_dtb, fdtchosen, "bootargs", &len);
	if (!fdtcmdline || (len <= 0))
		goto enocmdl;

	strncpy(cmdline, fdtcmdline, MIN(maxlen, (unsigned int) len));
	/* ensure null termination */
	cmdline[((unsigned int) len - 1) <= (maxlen - 1) ?
			((unsigned int) len - 1) : (maxlen - 1)] = '\0';

	return;

enocmdl:
	uk_pr_info("No command line found\n");
	strcpy(cmdline, CONFIG_UK_NAME);
}

static inline void _dtb_init_mem(paddr_t physical_offset)
{
	size_t fdt_size;
	void *new_dtb;
	paddr_t start_pfn_p;
	paddr_t max_pfn_p;

	/* init physical address offset gathered by entry32.S */
	_libxenplat_paddr_offset = physical_offset;

	arch_mm_prepare(&start_pfn_p, &max_pfn_p);

	/* The device tree is probably in memory that we're about to hand over
	 * to the page allocator, so move it to the end and reserve that space.
	 */
	fdt_size = fdt_totalsize(HYPERVISOR_dtb);
	new_dtb = to_virt(((max_pfn_p << __PAGE_SHIFT) - fdt_size)
					  & __PAGE_MASK);
	if (new_dtb != HYPERVISOR_dtb)
		memmove(new_dtb, HYPERVISOR_dtb, fdt_size);
	HYPERVISOR_dtb = new_dtb;
	max_pfn_p = to_phys(new_dtb) >> __PAGE_SHIFT;

	arch_mm_prepare(&start_pfn_p, &max_pfn_p);
	/* Fill out mrd array
	 */
	/* heap */
	_libxenplat_mrd[0].base  = to_virt(start_pfn_p << __PAGE_SHIFT);
	_libxenplat_mrd[0].len   = (size_t) to_virt(max_pfn_p << __PAGE_SHIFT)
		- (size_t) to_virt(start_pfn_p << __PAGE_SHIFT);
	_libxenplat_mrd[0].flags = (UKPLAT_MEMRF_ALLOCATABLE);
#if CONFIG_UKPLAT_MEMRNAME
	_libxenplat_mrd[0].name  = "heap";
#endif
	/* dtb */
	_libxenplat_mrd[1].base  = HYPERVISOR_dtb;
	_libxenplat_mrd[1].len   = fdt_size;
	_libxenplat_mrd[1].flags = (UKPLAT_MEMRF_RESERVED
								| UKPLAT_MEMRF_READABLE);
#if CONFIG_UKPLAT_MEMRNAME
	_libxenplat_mrd[1].name  = "dtb";
#endif
	_libxenplat_mrd_num = 2;
}

/*
 * INITIAL C ENTRY POINT.
 */
void _libxenplat_armentry(void *dtb_pointer, paddr_t physical_offset)
{
	struct xen_add_to_physmap xatp;
	int r;

	memset(__bss_start, 0, _end - __bss_start);

	_libxenplat_paddr_offset = physical_offset;

	dtb_pointer = map_fdt((paddr_t) dtb_pointer);

	uk_pr_debug("Checking DTB at %p...\n", dtb_pointer);

	if ((r = fdt_check_header(dtb_pointer))) {
		uk_pr_debug("Invalid DTB from Xen: %s\n", fdt_strerror(r));
		BUG();
	}
	HYPERVISOR_dtb = dtb_pointer;

	_dtb_init_mem(physical_offset); /* relocates dtb */

	/* Map shared_info page */
	xatp.domid = DOMID_SELF;
	xatp.idx = 0;
	xatp.space = XENMAPSPACE_shared_info;
	xatp.gpfn = virt_to_pfn(shared_info_page);
	if (HYPERVISOR_memory_op(XENMEM_add_to_physmap, &xatp) != 0)
		BUG();
	HYPERVISOR_shared_info = (struct shared_info *)shared_info_page;

	/* Initialize interrupt controller */
	intctrl_init();

	/* Set up events. */
	init_events();
	/* Initialize logical boot CPU */
	r = lcpu_init(lcpu_get_bsp());
	if (unlikely(r))
		UK_CRASH("Failed to initialize bootstrapping CPU: %d\n", r);

#ifdef CONFIG_HAVE_SMP
	ret = lcpu_mp_init(CONFIG_UKPLAT_LCPU_RUN_IRQ,
			   CONFIG_UKPLAT_LCPU_WAKEUP_IRQ, _libkvmplat_cfg.dtb);
	if (unlikely(ret))
		UK_CRASH("SMP initialization failed: %d\n", ret);
#endif /* CONFIG_HAVE_SMP */

	/* Fill in start_info */
	get_console();
	get_xenbus();

	prepare_console();
	/* Init console */
	init_console();
	_dtb_get_cmdline(cmdline, sizeof(cmdline));

	ukplat_entry_argp(CONFIG_UK_NAME, cmdline, sizeof(cmdline));
}
