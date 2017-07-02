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

#include <linux/shmem_fs.h>
#include "sgx.h"

struct page *sgx_get_backing(struct sgx_encl *encl,
			     struct sgx_encl_page *entry,
			     bool pcmd)
{
	struct address_space *mapping;
	struct inode *inode;
	gfp_t gfpmask;
	pgoff_t index;

	if (pcmd)
		inode = encl->pcmd->f_path.dentry->d_inode;
	else
		inode = encl->backing->f_path.dentry->d_inode;

	mapping = inode->i_mapping;
	gfpmask = mapping_gfp_mask(mapping);

	if (pcmd)
		index = PFN_DOWN(entry->desc - encl->base) >> 5;
	else
		index = PFN_DOWN(entry->desc - encl->base);

	return shmem_read_mapping_page_gfp(mapping, index, gfpmask);
}

void sgx_put_backing(struct page *backing_page, bool write)
{
	if (write)
		set_page_dirty(backing_page);

	put_page(backing_page);
}

static void sgx_zap_tcs_ptes(struct sgx_encl *encl)
{
	struct sgx_encl_page *entry;
	struct radix_tree_iter iter;
	struct vm_area_struct *vma;
	unsigned long addr;
	void **slot;

	radix_tree_for_each_slot(slot, &encl->page_tree, &iter, 0) {
		entry = *slot;
		addr = SGX_ENCL_PAGE_ADDR(entry);

		/* Skip regular and unloaded TCS pages. */
		if (!entry->epc_page || !(entry->desc & SGX_ENCL_PAGE_TCS))
			continue;

		if (sgx_encl_find(encl->mm, addr, &vma))
			continue;

		zap_vma_ptes(vma, addr, PAGE_SIZE);
	}
}

/**
 * sgx_encl_invalidate - stop the enclave
 * @encl:	an enclave
 * @flush_cpus:	kick out the hardware threads.
 *
 * Removes all the TCS entries from an enclave and optionally flushes the
 * hardware threads. On suspend, we do not flush hardware threads because
 * nothing is running at that point.
 */
void sgx_invalidate(struct sgx_encl *encl, bool flush_cpus)
{
	sgx_zap_tcs_ptes(encl);

	encl->flags |= SGX_ENCL_DEAD;

	if (flush_cpus)
		sgx_flush_cpus(encl);
}

static void sgx_ipi_cb(void *info)
{
}

void sgx_flush_cpus(struct sgx_encl *encl)
{
	on_each_cpu_mask(mm_cpumask(encl->mm), sgx_ipi_cb, NULL, 1);
}

int sgx_get_key_hash(struct crypto_shash *tfm, const void *modulus, void *hash)
{
	SHASH_DESC_ON_STACK(shash, tfm);

	shash->tfm = tfm;
	shash->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

	return crypto_shash_digest(shash, modulus, SGX_MODULUS_SIZE, hash);
}

int sgx_get_key_hash_simple(const void *modulus, void *hash)
{
	struct crypto_shash *tfm;
	int ret;

	tfm = crypto_alloc_shash("sha256", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	ret = sgx_get_key_hash(tfm, modulus, hash);

	crypto_free_shash(tfm);
	return ret;
}
