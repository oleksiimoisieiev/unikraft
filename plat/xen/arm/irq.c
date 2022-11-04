/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2020, OpenSynergy GmbH. All rights reserved.
 *
 * ARM Generic Interrupt Controller support v3 version
 * based on plat/drivers/gic/gic-v2.c:
 *
 * Authors: Wei Chen <Wei.Chen@arm.com>
 *          Jianyong Wu <Jianyong.Wu@arm.com>
 *
 * Copyright (c) 2018, Arm Ltd. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/* Moved from Mini-OS */

// ARM GIC implementation

#include <stdint.h>
#include <xen-arm/os.h>
#include <xen-arm/mm.h>
#include <xen/intctrl.h>
#include <common/hypervisor.h>
#include <libfdt.h>
#include <uk/bitops.h>
#include <uk/plat/irq.h>
#include <uk/plat/common/irq.h>
#include <uk/plat/time.h>

/* IRQ handlers declarations */
struct irq_handler {
	irq_handler_func_t func;
	void *arg;
};

extern lpae_t fixmap_pgtable[512];

static struct irq_handler irq_handlers[__MAX_IRQ]
				      [CONFIG_XEN_MAX_IRQ_HANDLER_ENTRIES];

static inline void set_pgt_entry(lpae_t *ptr, lpae_t val)
{
	*ptr = val;
	dsb(ishst);
	isb();
}

static inline struct irq_handler *allocate_handler(unsigned long irq)
{
	UK_ASSERT(irq < __MAX_IRQ);
	for (int i = 0; i < CONFIG_XEN_MAX_IRQ_HANDLER_ENTRIES; i++)
		if (irq_handlers[irq][i].func == NULL)
			return &irq_handlers[irq][i];
	return NULL;
}

int ukplat_irq_register(unsigned long irq, irq_handler_func_t func, void *arg)
{
	struct irq_handler *h;
	unsigned long flags;

	UK_ASSERT(func);
	if (irq >= __MAX_IRQ)
		return -EINVAL;

	flags = ukplat_lcpu_save_irqf();
	h = allocate_handler(irq);
	if (!h) {
		ukplat_lcpu_restore_irqf(flags);
		return -ENOMEM;
	}

	h->func = func;
	h->arg = arg;

	ukplat_lcpu_restore_irqf(flags);

	intctrl_clear_irq(irq);
	return 0;
}

void ukplat_irq_setup(uint64_t dist_addr, uint64_t rdist_addr,
		      uint64_t *vdist_addr, uint64_t *vrdist_addr)
{
#if defined(__arm__)
	*vdist_addr = to_virt((long) fdt64_to_cpu(dist_addr));
	*vrdist_addr = to_virt((long) fdt64_to_cpu(rdist_addr));
#else
	set_pgt_entry(&fixmap_pgtable[l2_pgt_idx(FIX_GIC_START)],
		      ((dist_addr & L2_MASK) | BLOCK_DEV_ATTR | L2_BLOCK));
	*vdist_addr = (FIX_GIC_START + (dist_addr & L2_OFFSET));
	*vrdist_addr = (FIX_GIC_START + (rdist_addr & L2_OFFSET));
#endif
	/* Setting memory barrier to get access to mapped pages */
	wmb();
}

/*
 * TODO: This is a temporary solution used to identify non TSC clock
 * interrupts in order to stop waiting for interrupts with deadline.
 */
extern unsigned long sched_have_pending_events;

void _ukplat_irq_handle(unsigned long irq __unused)
{
	struct irq_handler *h;
	int i;

	UK_ASSERT(irq < __MAX_IRQ);

	for (i = 0; i < CONFIG_XEN_MAX_IRQ_HANDLER_ENTRIES; i++) {
		if (irq_handlers[irq][i].func == NULL)
			break;
		h = &irq_handlers[irq][i];
		if (irq != ukplat_time_get_irq())
			/* ukplat_time_get_irq() gives the IRQ reserved
			 * for a timer, responsible to wake up cpu from halt,
			 * so it can check if it has something to do.
			 * Effectively it is OS ticks.
			 *
			 * If interrupt comes not from the timer, the
			 * chances are some work have just
			 * arrived. Let's kick the scheduler out of
			 * the halting loop, and let it take care of
			 * that work.
			 */
			__uk_test_and_set_bit(0, &sched_have_pending_events);

		if (h->func(h->arg) == 1)
			goto exit_ack;
	}
	/*
	 * Acknowledge interrupts even in the case when there was no handler for
	 * it. We do this to (1) compensate potential spurious interrupts of
	 * devices, and (2) to minimize impact on drivers that share one
	 * interrupt line that would then stay disabled.
	 */
	uk_pr_crit("Unhandled irq=%lu\n", irq);

exit_ack:
	intctrl_ack_irq(irq);
}

int ukplat_irq_init(struct uk_alloc *a __unused)
{
	UK_ASSERT(ukplat_lcpu_irqs_disabled());

	/* Nothing for now */
	return 0;
}
