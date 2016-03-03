// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.
//
// Authors:
//
// Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
// Suresh Siddha <suresh.b.siddha@intel.com>

#ifndef _ASM_X86_SGX_H
#define _ASM_X86_SGX_H

#include <asm/sgx_arch.h>
#include <asm/asm.h>
#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/types.h>

#define SGX_CPUID 0x12

enum sgx_cpuid {
	SGX_CPUID_CAPABILITIES	= 0,
	SGX_CPUID_ATTRIBUTES	= 1,
	SGX_CPUID_EPC_BANKS	= 2,
};

enum sgx_commands {
	ECREATE	= 0x0,
	EADD	= 0x1,
	EINIT	= 0x2,
	EREMOVE	= 0x3,
	EDGBRD	= 0x4,
	EDGBWR	= 0x5,
	EEXTEND	= 0x6,
	ELDU	= 0x8,
	EBLOCK	= 0x9,
	EPA	= 0xA,
	EWB	= 0xB,
	ETRACK	= 0xC,
	EAUG	= 0xD,
	EMODPR	= 0xE,
	EMODT	= 0xF,
};

#ifdef CONFIG_X86_64
#define XAX "%%rax"
#else
#define XAX "%%eax"
#endif

#define __encls_ret(rax, rbx, rcx, rdx)			\
	({						\
	int ret;					\
	asm volatile(					\
	"1: .byte 0x0f, 0x01, 0xcf;\n\t"		\
	"2:\n"						\
	".section .fixup,\"ax\"\n"			\
	"3: mov $-14,"XAX"\n"				\
	"   jmp 2b\n"					\
	".previous\n"					\
	_ASM_EXTABLE(1b, 3b)				\
	: "=a"(ret)					\
	: "a"(rax), "b"(rbx), "c"(rcx), "d"(rdx)	\
	: "memory");					\
	ret;						\
	})

#define __encls(rax, rbx, rcx, rdx...)			\
	({						\
	int ret;					\
	asm volatile(					\
	"1: .byte 0x0f, 0x01, 0xcf;\n\t"		\
	"   xor "XAX","XAX"\n"				\
	"2:\n"						\
	".section .fixup,\"ax\"\n"			\
	"3: mov $-14,"XAX"\n"				\
	"   jmp 2b\n"					\
	".previous\n"					\
	_ASM_EXTABLE(1b, 3b)				\
	: "=a"(ret), "=b"(rbx), "=c"(rcx)		\
	: "a"(rax), "b"(rbx), "c"(rcx), rdx		\
	: "memory");					\
	ret;						\
	})

static inline unsigned long __ecreate(struct sgx_pageinfo *pginfo, void *secs)
{
	return __encls(ECREATE, pginfo, secs, "d"(0));
}

static inline int __eextend(void *secs, void *epc)
{
	return __encls(EEXTEND, secs, epc, "d"(0));
}

static inline int __eadd(struct sgx_pageinfo *pginfo, void *epc)
{
	return __encls(EADD, pginfo, epc, "d"(0));
}

static inline int __einit(void *sigstruct, struct sgx_einittoken *einittoken,
			  void *secs)
{
	return __encls_ret(EINIT, sigstruct, secs, einittoken);
}

static inline int __eremove(void *epc)
{
	unsigned long rbx = 0;
	unsigned long rdx = 0;

	return __encls_ret(EREMOVE, rbx, epc, rdx);
}

static inline int __edbgwr(unsigned long addr, unsigned long *data)
{
	return __encls(EDGBWR, *data, addr, "d"(0));
}

static inline int __edbgrd(unsigned long addr, unsigned long *data)
{
	unsigned long rbx = 0;
	int ret;

	ret = __encls(EDGBRD, rbx, addr, "d"(0));
	if (!ret)
		*(unsigned long *) data = rbx;

	return ret;
}

static inline int __etrack(void *epc)
{
	unsigned long rbx = 0;
	unsigned long rdx = 0;

	return __encls_ret(ETRACK, rbx, epc, rdx);
}

static inline int __eldu(unsigned long rbx, unsigned long rcx,
			 unsigned long rdx)
{
	return __encls_ret(ELDU, rbx, rcx, rdx);
}

static inline int __eblock(void *epc)
{
	unsigned long rbx = 0;
	unsigned long rdx = 0;

	return __encls_ret(EBLOCK, rbx, epc, rdx);
}

static inline int __epa(void *epc)
{
	unsigned long rbx = SGX_PAGE_TYPE_VA;

	return __encls(EPA, rbx, epc, "d"(0));
}

static inline int __ewb(struct sgx_pageinfo *pginfo, void *epc, void *va)
{
	return __encls_ret(EWB, pginfo, epc, va);
}

static inline int __eaug(struct sgx_pageinfo *pginfo, void *epc)
{
	return __encls(EAUG, pginfo, epc, "d"(0));
}

static inline int __emodpr(struct sgx_secinfo *secinfo, void *epc)
{
	unsigned long rdx = 0;

	return __encls_ret(EMODPR, secinfo, epc, rdx);
}

static inline int __emodt(struct sgx_secinfo *secinfo, void *epc)
{
	unsigned long rdx = 0;

	return __encls_ret(EMODT, secinfo, epc, rdx);
}

#endif /* _ASM_X86_SGX_H */
