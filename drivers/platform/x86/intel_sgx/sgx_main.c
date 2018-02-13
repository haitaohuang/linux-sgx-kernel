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

#include <linux/acpi.h>
#include <linux/cdev.h>
#include <linux/platform_device.h>
#include <linux/suspend.h>
#include "sgx.h"

#define DRV_DESCRIPTION "Intel SGX Driver"

MODULE_DESCRIPTION("Intel SGX Driver");
MODULE_AUTHOR("Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>");
MODULE_LICENSE("Dual BSD/GPL");

/*
 * Global data.
 */

struct workqueue_struct *sgx_add_page_wq;
u64 sgx_encl_size_max_32;
u64 sgx_encl_size_max_64;
u64 sgx_xfrm_mask = 0x3;
u32 sgx_misc_reserved;
u32 sgx_xsave_size_tbl[64];
bool sgx_unlocked_msrs;
u64 sgx_le_pubkeyhash[4];

static DECLARE_RWSEM(sgx_file_sem);

static int sgx_open(struct inode *inode, struct file *file)
{
	int ret;

	ret = sgx_le_start(&sgx_le_ctx);

	if (!ret)
		file->private_data = &sgx_le_ctx;

	return ret;
}

static int sgx_release(struct inode *inode, struct file *file)
{
	if (!file->private_data)
		return 0;

	sgx_le_stop(file->private_data);

	return 0;
}

#ifdef CONFIG_COMPAT
long sgx_compat_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	return sgx_ioctl(filep, cmd, arg);
}
#endif

static int sgx_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_ops = &sgx_vm_ops;
	vma->vm_flags |= VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP | VM_IO |
			 VM_DONTCOPY;

	return 0;
}

static unsigned long sgx_get_unmapped_area(struct file *file,
					   unsigned long addr,
					   unsigned long len,
					   unsigned long pgoff,
					   unsigned long flags)
{
	if (len < 2 * PAGE_SIZE || (len & (len - 1)))
		return -EINVAL;

	/* On 64-bit architecture, allow mmap() to exceed 32-bit encl
	 * limit only if the task is not running in 32-bit compatibility
	 * mode.
	 */
	if (len > sgx_encl_size_max_32)
#ifdef CONFIG_X86_64
		if (test_thread_flag(TIF_ADDR32))
			return -EINVAL;
#else
		return -EINVAL;
#endif

#ifdef CONFIG_X86_64
	if (len > sgx_encl_size_max_64)
		return -EINVAL;
#endif

	addr = current->mm->get_unmapped_area(file, addr, 2 * len, pgoff,
					      flags);
	if (IS_ERR_VALUE(addr))
		return addr;

	addr = (addr + (len - 1)) & ~(len - 1);

	return addr;
}

const struct file_operations sgx_fops = {
	.owner			= THIS_MODULE,
	.open			= sgx_open,
	.release		= sgx_release,
	.unlocked_ioctl		= sgx_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl		= sgx_compat_ioctl,
#endif
	.mmap			= sgx_mmap,
	.get_unmapped_area	= sgx_get_unmapped_area,
};

static int sgx_pm_suspend(struct device *dev)
{
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &ctx->encl_list, encl_list) {
			sgx_invalidate(encl, false);
			encl->flags |= SGX_ENCL_SUSPEND;
			flush_work(&encl->add_page_work);
		}
	}

	return 0;
}

static SIMPLE_DEV_PM_OPS(sgx_drv_pm, sgx_pm_suspend, NULL);

static struct bus_type sgx_bus_type = {
	.name	= "sgx",
};

struct sgx_context {
	struct device dev;
	struct cdev cdev;
};

static dev_t sgx_devt;

static void sgx_dev_release(struct device *dev)
{
	struct sgx_context *ctx = container_of(dev, struct sgx_context, dev);

	kfree(ctx);
}

static struct sgx_context *sgx_ctx_alloc(struct device *parent)
{
	struct sgx_context *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	device_initialize(&ctx->dev);

	ctx->dev.bus = &sgx_bus_type;
	ctx->dev.parent = parent;
	ctx->dev.devt = MKDEV(MAJOR(sgx_devt), 0);
	ctx->dev.release = sgx_dev_release;

	dev_set_name(&ctx->dev, "sgx");

	cdev_init(&ctx->cdev, &sgx_fops);
	ctx->cdev.owner = THIS_MODULE;

	dev_set_drvdata(parent, ctx);

	return ctx;
}

static struct sgx_context *sgxm_ctx_alloc(struct device *parent)
{
	struct sgx_context *ctx;
	int rc;

	ctx = sgx_ctx_alloc(parent);
	if (IS_ERR(ctx))
		return ctx;

	rc = devm_add_action_or_reset(parent, (void (*)(void *))put_device,
				      &ctx->dev);
	if (rc) {
		kfree(ctx);
		return ERR_PTR(rc);
	}

	return ctx;
}

static int sgx_init_msrs(void)
{
	unsigned long fc;
	u64 msrs[4];
	int ret;

	rdmsrl(MSR_IA32_FEATURE_CONTROL, fc);
	if (fc & FEATURE_CONTROL_SGX_LE_WR)
		sgx_unlocked_msrs = true;

	ret = sgx_get_key_hash_simple(sgx_le_ss.modulus, sgx_le_pubkeyhash);
	if (ret)
		return ret;

	if (sgx_unlocked_msrs)
		return 0;

	rdmsrl(MSR_IA32_SGXLEPUBKEYHASH0, msrs[0]);
	rdmsrl(MSR_IA32_SGXLEPUBKEYHASH1, msrs[1]);
	rdmsrl(MSR_IA32_SGXLEPUBKEYHASH2, msrs[2]);
	rdmsrl(MSR_IA32_SGXLEPUBKEYHASH3, msrs[3]);

	if ((sgx_le_pubkeyhash[0] != msrs[0]) ||
	    (sgx_le_pubkeyhash[1] != msrs[1]) ||
	    (sgx_le_pubkeyhash[2] != msrs[2]) ||
	    (sgx_le_pubkeyhash[3] != msrs[3])) {
		pr_err("IA32_SGXLEPUBKEYHASHn MSRs do not match to the launch enclave signing key\n");
		return -ENODEV;
	}

	return 0;
}

static int sgx_dev_init(struct device *parent)
{
	struct sgx_context *sgx_dev;
	unsigned int eax;
	unsigned int ebx;
	unsigned int ecx;
	unsigned int edx;
	int ret;
	int i;

	ret = sgx_init_msrs();
	if (ret)
		return ret;

	sgx_dev = sgxm_ctx_alloc(parent);

	cpuid_count(SGX_CPUID, SGX_CPUID_CAPABILITIES, &eax, &ebx, &ecx, &edx);
	/* Only allow misc bits supported by the driver. */
	sgx_misc_reserved = ~ebx | SGX_MISC_RESERVED_MASK;
#ifdef CONFIG_X86_64
	sgx_encl_size_max_64 = 1ULL << ((edx >> 8) & 0xFF);
#endif
	sgx_encl_size_max_32 = 1ULL << (edx & 0xFF);

	if (boot_cpu_has(X86_FEATURE_OSXSAVE)) {
		cpuid_count(SGX_CPUID, SGX_CPUID_ATTRIBUTES, &eax, &ebx, &ecx,
			    &edx);
		sgx_xfrm_mask = (((u64)edx) << 32) + (u64)ecx;

		for (i = 2; i < 64; i++) {
			cpuid_count(0x0D, i, &eax, &ebx, &ecx, &edx);
			if ((1 << i) & sgx_xfrm_mask)
				sgx_xsave_size_tbl[i] = eax + ebx;
		}
	}

	ret = sgx_page_cache_init(parent);
	if (ret)
		return ret;

	sgx_add_page_wq = alloc_workqueue("intel_sgx-add-page-wq",
					  WQ_UNBOUND | WQ_FREEZABLE, 1);
	if (!sgx_add_page_wq) {
		ret = -ENOMEM;
		goto out_page_cache;
	}

	ret = sgx_le_init(&sgx_le_ctx);
	if (ret)
		goto out_workqueue;

	ret = cdev_device_add(&sgx_dev->cdev, &sgx_dev->dev);
	if (ret)
		goto out_le;

	return 0;
out_le:
	sgx_le_exit(&sgx_le_ctx);
out_workqueue:
	destroy_workqueue(sgx_add_page_wq);
out_page_cache:
	sgx_page_cache_teardown();
	return ret;
}

static int sgx_drv_probe(struct platform_device *pdev)
{
	if (!sgx_enabled)
		return -ENODEV;

	return sgx_dev_init(&pdev->dev);
}

static int sgx_drv_remove(struct platform_device *pdev)
{
	struct sgx_context *ctx = dev_get_drvdata(&pdev->dev);

	cdev_device_del(&ctx->cdev, &ctx->dev);
	sgx_le_exit(&sgx_le_ctx);
	destroy_workqueue(sgx_add_page_wq);
	sgx_page_cache_teardown();

	return 0;
}

#ifdef CONFIG_ACPI
static struct acpi_device_id sgx_device_ids[] = {
	{"INT0E0C", 0},
	{"", 0},
};
MODULE_DEVICE_TABLE(acpi, sgx_device_ids);
#endif

static struct platform_driver sgx_drv = {
	.probe = sgx_drv_probe,
	.remove = sgx_drv_remove,
	.driver = {
		.name			= "intel_sgx",
		.pm			= &sgx_drv_pm,
		.acpi_match_table	= ACPI_PTR(sgx_device_ids),
	},
};

static int __init sgx_drv_subsys_init(void)
{
	int ret;

	ret = bus_register(&sgx_bus_type);
	if (ret)
		return ret;

	ret = alloc_chrdev_region(&sgx_devt, 0, 1, "sgx");
	if (ret < 0) {
		bus_unregister(&sgx_bus_type);
		return ret;
	}

	return 0;
}

static void sgx_drv_subsys_exit(void)
{
	bus_unregister(&sgx_bus_type);
	unregister_chrdev_region(sgx_devt, 1);
}

static int __init sgx_drv_init(void)
{
	int ret;

	ret = sgx_drv_subsys_init();
	if (ret)
		return ret;

	ret = platform_driver_register(&sgx_drv);
	if (ret)
		sgx_drv_subsys_exit();

	return ret;
}
module_init(sgx_drv_init);

static void __exit sgx_drv_exit(void)
{
	platform_driver_unregister(&sgx_drv);
	sgx_drv_subsys_exit();
}
module_exit(sgx_drv_exit);
