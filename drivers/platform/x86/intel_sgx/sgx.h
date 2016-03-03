// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.
//
// Authors:
//
// Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
// Suresh Siddha <suresh.b.siddha@intel.com>
// Serge Ayoun <serge.ayoun@intel.com>
// Shay Katz-zamir <shay.katz-zamir@intel.com>

#ifndef __ARCH_INTEL_SGX_H__
#define __ARCH_INTEL_SGX_H__

#include <asm/sgx.h>
#include <asm/sgx_pr.h>
#include <crypto/hash.h>
#include <linux/mmu_notifier.h>
#include <linux/ratelimit.h>
#include <uapi/asm/sgx.h>

#define SGX_MAX_EPC_BANKS 8

#define SGX_EINIT_SPIN_COUNT	20
#define SGX_EINIT_SLEEP_COUNT	50
#define SGX_EINIT_SLEEP_TIME	20

#define SGX_VA_SLOT_COUNT 512
#define SGX_VA_OFFSET_MASK ((SGX_VA_SLOT_COUNT - 1) << 3)

#define SGX_EPC_BANK(epc_page) \
	(&sgx_epc_banks[(unsigned long)(epc_page) & ~PAGE_MASK])
#define SGX_EPC_PFN(epc_page) PFN_DOWN((unsigned long)(epc_page))
#define SGX_EPC_ADDR(epc_page) ((unsigned long)(epc_page) & PAGE_MASK)

enum sgx_alloc_flags {
	SGX_ALLOC_ATOMIC	= BIT(0),
};

struct sgx_va_page {
	void *epc_page;
	DECLARE_BITMAP(slots, SGX_VA_SLOT_COUNT);
	struct list_head list;
};

static inline unsigned int sgx_alloc_va_slot(struct sgx_va_page *page)
{
	int slot = find_first_zero_bit(page->slots, SGX_VA_SLOT_COUNT);

	if (slot < SGX_VA_SLOT_COUNT)
		set_bit(slot, page->slots);

	return slot << 3;
}

static inline void sgx_free_va_slot(struct sgx_va_page *page,
				    unsigned int offset)
{
	clear_bit(offset >> 3, page->slots);
}

static inline bool sgx_va_page_full(struct sgx_va_page *page)
{
	int slot = find_first_zero_bit(page->slots, SGX_VA_SLOT_COUNT);

	return slot == SGX_VA_SLOT_COUNT;
}

enum sgx_encl_page_flags {
	SGX_ENCL_PAGE_TCS	= BIT(0),
	SGX_ENCL_PAGE_RESERVED	= BIT(1),
	SGX_ENCL_PAGE_LOADED	= BIT(2),
};

#define SGX_ENCL_PAGE_ADDR(encl_page) ((encl_page)->desc & PAGE_MASK)
#define SGX_ENCL_PAGE_VA_OFFSET(encl_page) \
	((encl_page)->desc & SGX_VA_OFFSET_MASK)
#define SGX_ENCL_PAGE_PCMD_OFFSET(encl_page) \
	((PFN_DOWN((encl_page)->desc) & 31) * 128)

struct sgx_encl_page {
	unsigned long desc;
	union {
		void *epc_page;
		struct sgx_va_page *va_page;
	};
	struct list_head list;
};

struct sgx_tgid_ctx {
	struct pid *tgid;
	struct kref refcount;
	struct list_head encl_list;
	struct list_head list;
};

enum sgx_encl_flags {
	SGX_ENCL_INITIALIZED	= BIT(0),
	SGX_ENCL_DEBUG		= BIT(1),
	SGX_ENCL_SECS_EVICTED	= BIT(2),
	SGX_ENCL_SUSPEND	= BIT(3),
	SGX_ENCL_DEAD		= BIT(4),
};

struct sgx_encl {
	unsigned int flags;
	uint64_t attributes;
	uint64_t xfrm;
	unsigned int page_cnt;
	unsigned int secs_child_cnt;
	struct mutex lock;
	struct mm_struct *mm;
	struct file *backing;
	struct file *pcmd;
	struct list_head load_list;
	struct kref refcount;
	unsigned long base;
	unsigned long size;
	unsigned long ssaframesize;
	struct list_head va_pages;
	struct radix_tree_root page_tree;
	struct list_head add_page_reqs;
	struct work_struct add_page_work;
	struct sgx_encl_page secs;
	struct sgx_tgid_ctx *tgid_ctx;
	struct list_head encl_list;
	struct mmu_notifier mmu_notifier;
};

extern struct workqueue_struct *sgx_add_page_wq;
extern u64 sgx_encl_size_max_32;
extern u64 sgx_encl_size_max_64;
extern u64 sgx_xfrm_mask;
extern u32 sgx_misc_reserved;
extern u32 sgx_xsave_size_tbl[64];

extern const struct vm_operations_struct sgx_vm_ops;

int sgx_encl_find(struct mm_struct *mm, unsigned long addr,
		  struct vm_area_struct **vma);
void sgx_tgid_ctx_release(struct kref *ref);
struct sgx_encl *sgx_encl_alloc(struct sgx_secs *secs);
int sgx_encl_create(struct sgx_encl *encl, struct sgx_secs *secs);
int sgx_encl_add_page(struct sgx_encl *encl, unsigned long addr, void *data,
		      struct sgx_secinfo *secinfo, unsigned int mrmask);
int sgx_encl_init(struct sgx_encl *encl, struct sgx_sigstruct *sigstruct,
		  struct sgx_einittoken *einittoken);
void sgx_encl_release(struct kref *ref);

long sgx_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);
#ifdef CONFIG_COMPAT
long sgx_compat_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);
#endif

/* Utility functions */
int sgx_test_and_clear_young(struct sgx_encl_page *page, struct sgx_encl *encl);
struct page *sgx_get_backing(struct sgx_encl *encl,
			     struct sgx_encl_page *entry,
			     bool pcmd);
void sgx_put_backing(struct page *backing, bool write);
void sgx_insert_pte(struct sgx_encl *encl,
		    struct sgx_encl_page *encl_page,
		    void *epc_page,
		    struct vm_area_struct *vma);
int sgx_eremove(void *epc_page);
void sgx_invalidate(struct sgx_encl *encl, bool flush_cpus);
void sgx_flush_cpus(struct sgx_encl *encl);

enum sgx_fault_flags {
	SGX_FAULT_RESERVE	= BIT(0),
};

struct sgx_encl_page *sgx_fault_page(struct vm_area_struct *vma,
				     unsigned long addr,
				     unsigned int flags);


extern struct mutex sgx_tgid_ctx_mutex;
extern struct list_head sgx_tgid_ctx_list;
extern atomic_t sgx_va_pages_cnt;

int sgx_add_epc_bank(resource_size_t start, unsigned long size, int bank);
int sgx_page_cache_init(struct device *parent);
void sgx_page_cache_teardown(void);
void *sgx_alloc_page(unsigned int flags);
void sgx_drv_free_page(void *page, struct sgx_encl *encl);
void *sgx_get_page(void *page);
void sgx_put_page(void *ptr);

#endif /* __ARCH_X86_INTEL_SGX_H__ */
