// SPDX-License-Identifier: GPL-2.0

#include <linux/pfn.h>
#include <asm/xen/page.h>
#include <asm/xen/hypercall.h>
#include <xen/interface/memory.h>
#include <linux/vmalloc.h>

#include "multicalls.h"
#include "mmu.h"

unsigned long arbitrary_virt_to_mfn(void *vaddr)
{
	xmaddr_t maddr = arbitrary_virt_to_machine(vaddr);

	return PFN_DOWN(maddr.maddr);
}

xmaddr_t arbitrary_virt_to_machine(void *vaddr)
{
	unsigned long address = (unsigned long)vaddr;
	unsigned int level;
	pte_t *pte;
	unsigned offset;

	/*
	 * if the PFN is in the linear mapped vaddr range, we can just use
	 * the (quick) virt_to_machine() p2m lookup
	 */
	if (virt_addr_valid(vaddr))
		return virt_to_machine(vaddr);

	/* otherwise we have to do a (slower) full page-table walk */

	pte = lookup_address(address, &level);
	BUG_ON(pte == NULL);
	offset = address & ~PAGE_MASK;
	return XMADDR(((phys_addr_t)pte_mfn(*pte) << PAGE_SHIFT) + offset);
}
EXPORT_SYMBOL_GPL(arbitrary_virt_to_machine);

/* Returns: 0 success */
int xen_unmap_domain_gfn_range(struct vm_area_struct *vma,
			       int nr, struct page **pages)
{
	if (xen_feature(XENFEAT_auto_translated_physmap))
		return xen_xlate_unmap_gfn_range(vma, nr, pages);

	if (!pages)
		return 0;

	return -EINVAL;
}
EXPORT_SYMBOL_GPL(xen_unmap_domain_gfn_range);

/* Note: here 'mfn' is actually gfn!!! */
struct vm_struct * xen_remap_domain_mfn_range_in_kernel(unsigned long mfn,
		int nr, unsigned domid)
{
	struct vm_struct *area;
	struct remap_data rmd;
	struct mmu_update mmu_update[REMAP_BATCH_SIZE];
	int batch;
	unsigned long range, addr;
	pgprot_t prot;
	int err;

	WARN_ON(in_interrupt() || irqs_disabled());

	area = alloc_vm_area(nr << PAGE_SHIFT, NULL);
	if (!area)
		return NULL;

	addr = (unsigned long)area->addr;

	prot = __pgprot(pgprot_val(PAGE_KERNEL));
	rmd.pfn = &mfn;
	rmd.prot = prot;
	rmd.contiguous = true;
	rmd.no_translate = false;

	while (nr) {
		batch = min(REMAP_BATCH_SIZE, nr);
		range = (unsigned long)batch << PAGE_SHIFT;

		rmd.mmu_update = mmu_update;
		err = apply_to_page_range(&init_mm, addr, range,
					  remap_area_pfn_pte_fn, &rmd);
		if (err || HYPERVISOR_mmu_update(mmu_update, batch, NULL, domid) < 0)
			goto err;

		nr -= batch;
		addr += range;
	}

	xen_flush_tlb_all();
	return area;
err:
	free_vm_area(area);
	xen_flush_tlb_all();
	return NULL;
}
EXPORT_SYMBOL_GPL(xen_remap_domain_mfn_range_in_kernel);

void xen_unmap_domain_mfn_range_in_kernel(struct vm_struct *area, int nr,
		unsigned domid)
{
	struct remap_data rmd;
	struct mmu_update mmu_update;
	unsigned long range, addr = (unsigned long)area->addr;
#define INVALID_MFN (~0UL)
	unsigned long invalid_mfn = INVALID_MFN;
	int err;

	WARN_ON(in_interrupt() || irqs_disabled());

	rmd.prot = PAGE_NONE;
	rmd.no_translate = false;

	while (nr) {
		range = (unsigned long)(1 << PAGE_SHIFT);

		rmd.pfn = &invalid_mfn;
		rmd.mmu_update = &mmu_update;
		err = apply_to_page_range(&init_mm, addr, range,
					  remap_area_pfn_pte_fn, &rmd);
		BUG_ON(err);
		BUG_ON(HYPERVISOR_mmu_update(&mmu_update, 1, NULL, domid) < 0);

		nr--;
		addr += range;
	}

	free_vm_area(area);
	xen_flush_tlb_all();
}
EXPORT_SYMBOL_GPL(xen_unmap_domain_mfn_range_in_kernel);
