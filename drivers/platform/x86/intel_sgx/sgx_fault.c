// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.
//
// Authors:
//
// Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
// Suresh Siddha <suresh.b.siddha@intel.com>
// Serge Ayoun <serge.ayoun@intel.com>
// Shay Katz-zamir <shay.katz-zamir@intel.com>
// Sean Christopherson <sean.j.christopherson@intel.com>

#include <linux/highmem.h>
#include "sgx.h"

static int sgx_eldu(struct sgx_encl *encl,
		    struct sgx_encl_page *encl_page,
		    void *epc_page,
		    bool is_secs)
{
	struct sgx_pageinfo pginfo;
	unsigned long pcmd_offset;
	unsigned long va_offset;
	void *secs_ptr = NULL;
	struct page *backing;
	struct page *pcmd;
	void *epc_ptr;
	void *va_ptr;
	int ret;

	pcmd_offset = SGX_ENCL_PAGE_PCMD_OFFSET(encl_page);
	va_offset = SGX_ENCL_PAGE_VA_OFFSET(encl_page);

	backing = sgx_get_backing(encl, encl_page, false);
	if (IS_ERR(backing)) {
		ret = PTR_ERR(backing);
		sgx_warn(encl, "pinning the backing page for ELDU failed with %d\n",
			 ret);
		return ret;
	}

	pcmd = sgx_get_backing(encl, encl_page, true);
	if (IS_ERR(pcmd)) {
		ret = PTR_ERR(pcmd);
		sgx_warn(encl, "pinning the pcmd page for EWB failed with %d\n",
			 ret);
		goto out;
	}

	if (!is_secs)
		secs_ptr = sgx_get_page(encl->secs.epc_page);

	epc_ptr = sgx_get_page(epc_page);
	va_ptr = sgx_get_page(encl_page->va_page->epc_page);
	pginfo.srcpge = (unsigned long)kmap_atomic(backing);
	pginfo.pcmd = (unsigned long)kmap_atomic(pcmd) + pcmd_offset;
	pginfo.linaddr = is_secs ? 0 : SGX_ENCL_PAGE_ADDR(encl_page);
	pginfo.secs = (unsigned long)secs_ptr;

	ret = __eldu((unsigned long)&pginfo, (unsigned long)epc_ptr,
		     (unsigned long)va_ptr + va_offset);
	if (ret) {
		sgx_err(encl, "ELDU returned %d\n", ret);
		ret = -EFAULT;
	}

	kunmap_atomic((void *)(unsigned long)(pginfo.pcmd - pcmd_offset));
	kunmap_atomic((void *)(unsigned long)pginfo.srcpge);
	sgx_put_page(va_ptr);
	sgx_put_page(epc_ptr);

	if (!is_secs)
		sgx_put_page(secs_ptr);

	sgx_put_backing(pcmd, false);

out:
	sgx_put_backing(backing, false);

	if (!ret) {
		sgx_free_va_slot(encl_page->va_page, va_offset);
		list_move(&encl_page->va_page->list, &encl->va_pages);
		encl_page->desc &= ~SGX_VA_OFFSET_MASK;
	}

	return ret;
}

static struct sgx_encl_page *sgx_do_fault(struct vm_area_struct *vma,
					  unsigned long addr,
					  unsigned int flags)
{
	bool reserve = (flags & SGX_FAULT_RESERVE) != 0;
	struct sgx_encl *encl = vma->vm_private_data;
	struct sgx_encl_page *entry;
	void *secs_epc_page = NULL;
	void *epc_page = NULL;
	int rc = 0;

	/* If process was forked, VMA is still there but vm_private_data is set
	 * to NULL.
	 */
	if (!encl)
		return ERR_PTR(-EFAULT);

	mutex_lock(&encl->lock);

	entry = radix_tree_lookup(&encl->page_tree, addr >> PAGE_SHIFT);
	if (!entry) {
		rc = -EFAULT;
		goto out;
	}

	if (encl->flags & SGX_ENCL_DEAD) {
		rc = -EFAULT;
		goto out;
	}

	if (!(encl->flags & SGX_ENCL_INITIALIZED)) {
		sgx_dbg(encl, "cannot fault, unitialized\n");
		rc = -EFAULT;
		goto out;
	}

	if (reserve && (entry->desc & SGX_ENCL_PAGE_RESERVED)) {
		sgx_dbg(encl, "cannot fault, 0x%p is reserved\n",
			(void *)SGX_ENCL_PAGE_ADDR(entry));
		rc = -EBUSY;
		goto out;
	}

	/* Legal race condition, page is already faulted. */
	if (entry->desc & SGX_ENCL_PAGE_LOADED) {
		if (reserve)
			entry->desc |= SGX_ENCL_PAGE_RESERVED;
		goto out;
	}

	epc_page = sgx_alloc_page(SGX_ALLOC_ATOMIC);
	if (IS_ERR(epc_page)) {
		rc = PTR_ERR(epc_page);
		epc_page = NULL;
		goto out;
	}

	/* If SECS is evicted then reload it first */
	if (encl->flags & SGX_ENCL_SECS_EVICTED) {
		secs_epc_page = sgx_alloc_page(SGX_ALLOC_ATOMIC);
		if (IS_ERR(secs_epc_page)) {
			rc = PTR_ERR(secs_epc_page);
			secs_epc_page = NULL;
			goto out;
		}

		rc = sgx_eldu(encl, &encl->secs, secs_epc_page, true);
		if (rc)
			goto out;

		encl->secs.epc_page = secs_epc_page;
		encl->flags &= ~SGX_ENCL_SECS_EVICTED;
		/* Do not free */
		secs_epc_page = NULL;
	}

	rc = sgx_eldu(encl, entry, epc_page, false /* is_secs */);
	if (rc)
		goto out;

	encl->secs_child_cnt++;
	entry->epc_page = epc_page;
	entry->desc |= SGX_ENCL_PAGE_LOADED;
	if (reserve)
		entry->desc |= SGX_ENCL_PAGE_RESERVED;
	/* Do not free */
	epc_page = NULL;
	list_add_tail(&entry->list, &encl->load_list);

	rc = vm_insert_pfn(vma, addr, SGX_EPC_PFN(entry->epc_page));
	if (rc) {
		/* Kill the enclave if vm_insert_pfn fails; failure only occurs
		 * if there is a driver bug or an unrecoverable issue, e.g. OOM.
		 */
		sgx_crit(encl, "vm_insert_pfn returned %d\n", rc);
		sgx_invalidate(encl, true);
		goto out;
	}
	sgx_test_and_clear_young(entry, encl);
out:
	mutex_unlock(&encl->lock);
	if (epc_page)
		sgx_drv_free_page(epc_page, encl);
	if (secs_epc_page)
		sgx_drv_free_page(secs_epc_page, encl);
	return rc ? ERR_PTR(rc) : entry;
}

struct sgx_encl_page *sgx_fault_page(struct vm_area_struct *vma,
				     unsigned long addr,
				     unsigned int flags)
{
	struct sgx_encl_page *entry;

	do {
		entry = sgx_do_fault(vma, addr, flags);
		if (!(flags & SGX_FAULT_RESERVE))
			break;
	} while (PTR_ERR(entry) == -EBUSY);

	return entry;
}
