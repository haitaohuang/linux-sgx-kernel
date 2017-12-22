// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.
//
// Authors:
//
// Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
// Suresh Siddha <suresh.b.siddha@intel.com>

#ifndef _ASM_X86_SGX_ARCH_H
#define _ASM_X86_SGX_ARCH_H

#include <linux/types.h>

#define SGX_SSA_GPRS_SIZE		182
#define SGX_SSA_MISC_EXINFO_SIZE	16

enum sgx_misc {
	SGX_MISC_EXINFO		= 0x01,
};

#define SGX_MISC_RESERVED_MASK 0xFFFFFFFFFFFFFFFEL

enum sgx_attribute {
	SGX_ATTR_DEBUG		= 0x02,
	SGX_ATTR_MODE64BIT	= 0x04,
	SGX_ATTR_PROVISIONKEY	= 0x10,
	SGX_ATTR_EINITTOKENKEY	= 0x20,
};

#define SGX_ATTR_RESERVED_MASK 0xFFFFFFFFFFFFFFC9L

#define SGX_SECS_RESERVED1_SIZE 24
#define SGX_SECS_RESERVED2_SIZE 32
#define SGX_SECS_RESERVED3_SIZE 96
#define SGX_SECS_RESERVED4_SIZE 3836

struct sgx_secs {
	uint64_t size;
	uint64_t base;
	uint32_t ssaframesize;
	uint32_t miscselect;
	uint8_t reserved1[SGX_SECS_RESERVED1_SIZE];
	uint64_t attributes;
	uint64_t xfrm;
	uint32_t mrenclave[8];
	uint8_t reserved2[SGX_SECS_RESERVED2_SIZE];
	uint32_t mrsigner[8];
	uint8_t	reserved3[SGX_SECS_RESERVED3_SIZE];
	uint16_t isvvprodid;
	uint16_t isvsvn;
	uint8_t reserved4[SGX_SECS_RESERVED4_SIZE];
};

enum sgx_tcs_flags {
	SGX_TCS_DBGOPTIN	= 0x01, /* cleared on EADD */
};

#define SGX_TCS_RESERVED_MASK 0xFFFFFFFFFFFFFFFEL

struct sgx_tcs {
	uint64_t state;
	uint64_t flags;
	uint64_t ossa;
	uint32_t cssa;
	uint32_t nssa;
	uint64_t oentry;
	uint64_t aep;
	uint64_t ofsbase;
	uint64_t ogsbase;
	uint32_t fslimit;
	uint32_t gslimit;
	uint64_t reserved[503];
};

struct sgx_pageinfo {
	uint64_t linaddr;
	uint64_t srcpge;
	union {
		uint64_t secinfo;
		uint64_t pcmd;
	};
	uint64_t secs;
} __attribute__((aligned(32)));


#define SGX_SECINFO_PERMISSION_MASK	0x0000000000000007L
#define SGX_SECINFO_PAGE_TYPE_MASK	0x000000000000FF00L
#define SGX_SECINFO_RESERVED_MASK	0xFFFFFFFFFFFF00F8L

enum sgx_page_type {
	SGX_PAGE_TYPE_SECS	= 0x00,
	SGX_PAGE_TYPE_TCS	= 0x01,
	SGX_PAGE_TYPE_REG	= 0x02,
	SGX_PAGE_TYPE_VA	= 0x03,
};

enum sgx_secinfo_flags {
	SGX_SECINFO_R		= 0x01,
	SGX_SECINFO_W		= 0x02,
	SGX_SECINFO_X		= 0x04,
	SGX_SECINFO_SECS	= (SGX_PAGE_TYPE_SECS << 8),
	SGX_SECINFO_TCS		= (SGX_PAGE_TYPE_TCS << 8),
	SGX_SECINFO_REG		= (SGX_PAGE_TYPE_REG << 8),
};

struct sgx_secinfo {
	uint64_t flags;
	uint64_t reserved[7];
} __attribute__((aligned(64)));

struct sgx_pcmd {
	struct sgx_secinfo secinfo;
	uint64_t enclave_id;
	uint8_t reserved[40];
	uint8_t mac[16];
};

#define SGX_MODULUS_SIZE 384

struct sgx_sigstruct_header {
	uint64_t header1[2];
	uint32_t vendor;
	uint32_t date;
	uint64_t header2[2];
	uint32_t swdefined;
	uint8_t reserved1[84];
};

struct sgx_sigstruct_body {
	uint32_t miscselect;
	uint32_t miscmask;
	uint8_t reserved2[20];
	uint64_t attributes;
	uint64_t xfrm;
	uint8_t attributemask[16];
	uint8_t mrenclave[32];
	uint8_t reserved3[32];
	uint16_t isvprodid;
	uint16_t isvsvn;
} __attribute__((__packed__));

struct sgx_sigstruct {
	struct sgx_sigstruct_header header;
	uint8_t modulus[SGX_MODULUS_SIZE];
	uint32_t exponent;
	uint8_t signature[SGX_MODULUS_SIZE];
	struct sgx_sigstruct_body body;
	uint8_t reserved4[12];
	uint8_t q1[SGX_MODULUS_SIZE];
	uint8_t q2[SGX_MODULUS_SIZE];
};

struct sgx_sigstruct_payload {
	struct sgx_sigstruct_header header;
	struct sgx_sigstruct_body body;
};

struct sgx_einittoken_payload {
	uint32_t valid;
	uint32_t reserved1[11];
	uint64_t attributes;
	uint64_t xfrm;
	uint8_t mrenclave[32];
	uint8_t reserved2[32];
	uint8_t mrsigner[32];
	uint8_t reserved3[32];
};

struct sgx_einittoken {
	struct sgx_einittoken_payload payload;
	uint8_t cpusvnle[16];
	uint16_t isvprodidle;
	uint16_t isvsvnle;
	uint8_t reserved2[24];
	uint32_t maskedmiscselectle;
	uint64_t maskedattributesle;
	uint64_t maskedxfrmle;
	uint8_t keyid[32];
	uint8_t mac[16];
};

struct sgx_report {
	uint8_t cpusvn[16];
	uint32_t miscselect;
	uint8_t reserved1[28];
	uint64_t attributes;
	uint64_t xfrm;
	uint8_t mrenclave[32];
	uint8_t reserved2[32];
	uint8_t mrsigner[32];
	uint8_t reserved3[96];
	uint16_t isvprodid;
	uint16_t isvsvn;
	uint8_t reserved4[60];
	uint8_t reportdata[64];
	uint8_t keyid[32];
	uint8_t mac[16];
};

struct sgx_targetinfo {
	uint8_t mrenclave[32];
	uint64_t attributes;
	uint64_t xfrm;
	uint8_t reserved1[4];
	uint32_t miscselect;
	uint8_t reserved2[456];
};

struct sgx_keyrequest {
	uint16_t keyname;
	uint16_t keypolicy;
	uint16_t isvsvn;
	uint16_t reserved1;
	uint8_t cpusvn[16];
	uint64_t attributemask;
	uint64_t xfrmmask;
	uint8_t keyid[32];
	uint32_t miscmask;
	uint8_t reserved2[436];
};

#endif /* _ASM_X86_SGX_ARCH_H */
