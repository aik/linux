// SPDX-License-Identifier: GPL-2.0-only

// Interface to PSP for CCP/SEV-TIO/SNP-VM

#include <linux/pci.h>
#include <linux/tsm.h>
#include <linux/psp.h>
#include <linux/file.h>
#include <linux/vmalloc.h>

#include <asm/sev-common.h>
#include <asm/sev.h>
#include <asm/page.h>

#include "psp-dev.h"
#include "sev-dev.h"
#include "sev-dev-tio.h"

static void *__prep_data_pg(struct tsm_dev_tio *dev_data, size_t len)
{
	void *r = dev_data->data_pg;

	if (snp_reclaim_pages(virt_to_phys(r), 1, false))
		return NULL;

	memset(r, 0, len);

	if (rmp_make_private(page_to_pfn(virt_to_page(r)), 0, PG_LEVEL_4K, 0, true))
		return NULL;

	return r;
}

#define prep_data_pg(type, tdev) ((type *) __prep_data_pg((tdev), sizeof(type)))

#define SLA_PAGE_TYPE_DATA	0
#define SLA_PAGE_TYPE_SCATTER	1
#define SLA_PAGE_SIZE_4K	0
#define SLA_PAGE_SIZE_2M	1
#define SLA_SZ(s)		((s).page_size == SLA_PAGE_SIZE_2M ? SZ_2M : SZ_4K)
#define SLA_SCATTER_LEN(s)	(SLA_SZ(s) / sizeof(struct sla_addr_t))
#define SLA_EOL			((struct sla_addr_t) { .pfn = 0xFFFFFFFFFFUL })
#define SLA_NULL		((struct sla_addr_t) { 0 })
#define IS_SLA_NULL(s)		((s).sla == SLA_NULL.sla)
#define IS_SLA_EOL(s)		((s).sla == SLA_EOL.sla)

/* the BUFFER Structure */
struct sla_buffer_hdr {
	u32 capacity_sz;
	u32 payload_sz; /* The size of BUFFER_PAYLOAD in bytes. Must be multiple of 32B */
	union {
		u32 flags;
		struct {
			u32 encryption:1;
		};
	};
	u32 reserved1;
	u8 iv[16];	/* IV used for the encryption of this buffer */
	u8 authtag[16]; /* Authentication tag for this buffer */
	u8 reserved2[16];
} __packed;

struct spdm_dobj_hdr {
	u32 id;     /* Data object type identifier */
	u32 length; /* Length of the data object, INCLUDING THIS HEADER. Must be a multiple of 32B */
	union {
		u16 ver; /* Version of the data object structure */
		struct {
			u8 minor;
			u8 major;
		} version;
	};
} __packed;

enum spdm_data_type_t {
	DOBJ_DATA_TYPE_SPDM = 0x1,
	DOBJ_DATA_TYPE_SECURE_SPDM = 0x2,
};

struct spdm_dobj_hdr_req {
	struct spdm_dobj_hdr hdr; /* hdr.id == SPDM_DOBJ_ID_REQ */
	u8 data_type; /* spdm_data_type_t */
	u8 reserved2[5];
} __packed;

struct spdm_dobj_hdr_resp {
	struct spdm_dobj_hdr hdr; /* hdr.id == SPDM_DOBJ_ID_RESP */
	u8 data_type; /* spdm_data_type_t */
	u8 reserved2[5];
} __packed;

struct spdm_dobj_hdr_cert {
	struct spdm_dobj_hdr hdr; /* hdr.id == SPDM_DOBJ_ID_CERTIFICATE */
	u8 reserved1[6];
	u16 device_id;
	u8 segment_id;
	u8 type; /* 1h: SPDM certificate. 0h, 2h–FFh: Reserved. */
	u8 reserved2[12];
} __packed;

struct spdm_dobj_hdr_meas {
	struct spdm_dobj_hdr hdr; /* hdr.id == SPDM_DOBJ_ID_MEASUREMENT */
	u8 reserved1[6];
	u16 device_id;
	u8 segment_id;
	u8 type; /* 1h: SPDM measurement. 0h, 2h–FFh: Reserved. */
	u8 reserved2[12];
} __packed;

struct spdm_dobj_hdr_report {
	struct spdm_dobj_hdr hdr; /* hdr.id == SPDM_DOBJ_ID_REPORT */
	u8 reserved1[6];
	u16 device_id;
	u8 segment_id;
	u8 type; /* 1h: TDISP interface report. 0h, 2h–FFh: Reserved */
	u8 reserved2[12];
} __packed;

/* Used in all SPDM-aware TIO commands */
struct spdm_ctrl {
	struct sla_addr_t req;
	struct sla_addr_t resp;
	struct sla_addr_t scratch;
	struct sla_addr_t output;
} __packed;

static size_t sla_dobj_id_to_size(u8 id)
{
	size_t n;

	BUILD_BUG_ON(sizeof(struct spdm_dobj_hdr_resp) != 0x10);
	switch (id) {
	case SPDM_DOBJ_ID_REQ:
		n = sizeof(struct spdm_dobj_hdr_req);
		break;
	case SPDM_DOBJ_ID_RESP:
		n = sizeof(struct spdm_dobj_hdr_resp);
		break;
	case SPDM_DOBJ_ID_CERTIFICATE:
		n = sizeof(struct spdm_dobj_hdr_cert);
		break;
	case SPDM_DOBJ_ID_MEASUREMENT:
		n = sizeof(struct spdm_dobj_hdr_meas);
		break;
	case SPDM_DOBJ_ID_REPORT:
		n = sizeof(struct spdm_dobj_hdr_report);
		break;
	default:
		WARN_ON(1);
		n = 0;
		break;
	}

	return n;
}

#define SPDM_DOBJ_HDR_SIZE(hdr)		sla_dobj_id_to_size((hdr)->id)
#define SPDM_DOBJ_DATA(hdr)		((u8 *)(hdr) + SPDM_DOBJ_HDR_SIZE(hdr))
#define SPDM_DOBJ_LEN(hdr)		((hdr)->length - SPDM_DOBJ_HDR_SIZE(hdr))

#define sla_to_dobj_resp_hdr(buf)	((struct spdm_dobj_hdr_resp *) \
					sla_to_dobj_hdr_check((buf), SPDM_DOBJ_ID_RESP))
#define sla_to_dobj_req_hdr(buf)	((struct spdm_dobj_hdr_req *) \
					sla_to_dobj_hdr_check((buf), SPDM_DOBJ_ID_REQ))

static struct spdm_dobj_hdr *sla_to_dobj_hdr(struct sla_buffer_hdr *buf)
{
	if (!buf)
		return NULL;

	return (struct spdm_dobj_hdr *) &buf[1];
}

static struct spdm_dobj_hdr *sla_to_dobj_hdr_check(struct sla_buffer_hdr *buf, u32 check_dobjid)
{
	struct spdm_dobj_hdr *hdr = sla_to_dobj_hdr(buf);

	if (hdr && hdr->id == check_dobjid)
		return hdr;

	pr_err("! ERROR: expected %d, found %d\n", check_dobjid, hdr->id);
	return NULL;
}

static void *sla_to_data(struct sla_buffer_hdr *buf, u32 dobjid)
{
	struct spdm_dobj_hdr *hdr = sla_to_dobj_hdr(buf);

	if (WARN_ON_ONCE(dobjid != SPDM_DOBJ_ID_REQ && dobjid != SPDM_DOBJ_ID_RESP))
		return NULL;

	if (!hdr)
		return NULL;

	return (u8 *) hdr + sla_dobj_id_to_size(dobjid);
}

/**
 * struct sev_tio_status - TIO_STATUS command's info_paddr buffer
 *
 * @length: Length of this structure in bytes.
 * @tio_init_done: Indicates TIO_INIT has been invoked
 * @tio_en: Indicates that SNP_INIT_EX initialized the RMP for SEV-TIO.
 * @spdm_req_size_min: Minimum SPDM request buffer size in bytes.
 * @spdm_req_size_max: Maximum SPDM request buffer size in bytes.
 * @spdm_scratch_size_min: Minimum  SPDM scratch buffer size in bytes.
 * @spdm_scratch_size_max: Maximum SPDM scratch buffer size in bytes.
 * @spdm_out_size_min: Minimum SPDM output buffer size in bytes
 * @spdm_out_size_max: Maximum for the SPDM output buffer size in bytes.
 * @spdm_rsp_size_min: Minimum SPDM response buffer size in bytes.
 * @spdm_rsp_size_max: Maximum SPDM response buffer size in bytes.
 * @devctx_size: Size of a device context buffer in bytes.
 * @tdictx_size: Size of a TDI context buffer in bytes.
 */
struct sev_tio_status {
	u32 length;
	union {
		u32 flags;
		struct {
			u32 tio_en:1;
			u32 tio_init_done:1;
		};
	};
	u32 spdm_req_size_min;
	u32 spdm_req_size_max;
	u32 spdm_scratch_size_min;
	u32 spdm_scratch_size_max;
	u32 spdm_out_size_min;
	u32 spdm_out_size_max;
	u32 spdm_rsp_size_min;
	u32 spdm_rsp_size_max;
	u32 devctx_size;
	u32 tdictx_size;
};

/**
 * struct sev_data_tio_status - SEV_CMD_TIO_STATUS command
 *
 * @length: Length of this command buffer in bytes
 * @status_paddr: SPA of the TIO_STATUS structure
 */
struct sev_data_tio_status {
	u32 length;
	u32 reserved;
	u64 status_paddr;
} __packed;

/* TIO_INIT */
struct sev_data_tio_init {
	u32 length;
	u32 reserved[3];
} __packed;

void sev_tio_cleanup(struct sev_device *sev)
{
	kfree(sev->tio_status);
	sev->tio_status = NULL;
}

/**
 * struct sev_data_tio_dev_create - TIO_DEV_CREATE command
 *
 * @length: Length in bytes of this command buffer.
 * @dev_ctx_sla: A scatter list address pointing to a buffer to be used as a device context buffer.
 * @device_id: The PCIe Routing Identifier of the device to connect to.
 * @root_port_id: FiXME: The PCIe Routing Identifier of the root port of the device.
 * @segment_id: The PCIe Segment Identifier of the device to connect to.
 */
struct sev_data_tio_dev_create {
	u32 length;
	u32 reserved1;
	struct sla_addr_t dev_ctx_sla;
	u16 device_id;
	u16 root_port_id;
	u8 segment_id;
	u8 reserved2[11];
} __packed;

/**
 * struct sev_data_tio_dev_connect - TIO_DEV_CONNECT
 *
 * @length: Length in bytes of this command buffer.
 * @spdm_ctrl: SPDM control structure defined in Section 5.1.
 * @device_id: The PCIe Routing Identifier of the device to connect to.
 * @root_port_id: The PCIe Routing Identifier of the root port of the device.
 * @segment_id: The PCIe Segment Identifier of the device to connect to.
 * @dev_ctx_sla: Scatter list address of the device context buffer.
 * @tc_mask: Bitmask of the traffic classes to initialize for SEV-TIO usage.
 *           Setting the kth bit of the TC_MASK to 1 indicates that the traffic
 *           class k will be initialized.
 * @cert_slot: Slot number of the certificate requested for constructing the SPDM session.
 * @ide_stream_id: IDE stream IDs to be associated with this device.
 *                 Valid only if corresponding bit in TC_MASK is set.
 */
struct sev_data_tio_dev_connect {
	u32 length;
	u32 reserved1;
	struct spdm_ctrl spdm_ctrl;
	u8 reserved2[8];
	struct sla_addr_t dev_ctx_sla;
	u8 tc_mask;
	u8 cert_slot;
	u8 reserved3[6];
	u8 ide_stream_id[8];
	u8 reserved4[8];
} __packed;

/**
 * struct sev_data_tio_dev_disconnect - TIO_DEV_DISCONNECT
 *
 * @length: Length in bytes of this command buffer.
 * @force: Force device disconnect without SPDM traffic.
 * @spdm_ctrl: SPDM control structure defined in Section 5.1.
 * @dev_ctx_sla: Scatter list address of the device context buffer.
 */
struct sev_data_tio_dev_disconnect {
	u32 length;
	union {
		u32 flags;
		struct {
			u32 force:1;
		};
	};
	struct spdm_ctrl spdm_ctrl;
	struct sla_addr_t dev_ctx_sla;
} __packed;

/**
 * struct sev_data_tio_dev_meas - TIO_DEV_MEASUREMENTS
 *
 * @length: Length in bytes of this command buffer
 * @raw_bitstream: 0: Requests the digest form of the attestation report
 *                 1: Requests the raw bitstream form of the attestation report
 * @spdm_ctrl: SPDM control structure defined in Section 5.1.
 * @dev_ctx_sla: Scatter list address of the device context buffer.
 */
struct sev_data_tio_dev_meas {
	u32 length;
	union {
		u32 flags;
		struct {
			u32 raw_bitstream:1;
		};
	};
	struct spdm_ctrl spdm_ctrl;
	struct sla_addr_t dev_ctx_sla;
	u8 meas_nonce[32];
} __packed;

/**
 * struct sev_data_tio_dev_certs - TIO_DEV_CERTIFICATES
 *
 * @length: Length in bytes of this command buffer
 * @spdm_ctrl: SPDM control structure defined in Section 5.1.
 * @dev_ctx_sla: Scatter list address of the device context buffer.
 */
struct sev_data_tio_dev_certs {
	u32 length;
	u32 reserved;
	struct spdm_ctrl spdm_ctrl;
	struct sla_addr_t dev_ctx_sla;
} __packed;

/**
 * struct sev_data_tio_dev_reclaim - TIO_DEV_RECLAIM command
 *
 * @length: Length in bytes of this command buffer
 * @dev_ctx_paddr: SPA of page donated by hypervisor
 */
struct sev_data_tio_dev_reclaim {
	u32 length;
	u32 reserved;
	struct sla_addr_t dev_ctx_sla;
} __packed;

/**
 * struct sev_tio_dev_status - sev_data_tio_dev_status::status_paddr of
 * TIO_DEV_STATUS command
 *
 */
struct sev_tio_dev_status {
	u32 length;
	u8 ctx_state;
	u8 reserved1;
	union {
		u8 p1;
		struct {
			u8 request_pending:1;
			u8 request_pending_tdi:1;
		};
	};
	u8 certs_slot;
	u16 device_id;
	u8 segment_id;
	u8 tc_mask;
	u16 request_pending_command;
	u16 reserved2;
	struct tdisp_interface_id request_pending_interface_id;
	union {
		u8 p2;
		struct {
			u8 meas_digest_valid:1;
			u8 no_fw_update:1;
		};
	};
	u8 reserved3[3];
	u8 ide_stream_id[8];
	u8 reserved4[8];
	u8 certs_digest[48];
	u8 meas_digest[48];
	u32 tdi_count;
	u32 bound_tdi_count;
	u8 reserved5[8];
} __packed;

/**
 * struct sev_data_tio_dev_status - TIO_DEV_STATUS command
 *
 * @length: Length in bytes of this command buffer
 * @dev_ctx_paddr: SPA of a device context page
 * @status_length: Length in bytes of the sev_tio_dev_status buffer
 * @status_paddr: SPA of the status buffer. See Table 16
 */
struct sev_data_tio_dev_status {
	u32 length;				/* In */
	u32 reserved;
	struct sla_addr_t dev_ctx_paddr;		/* In */
	u32 status_length;			/* In */
	u64 status_paddr;			/* In */
} __packed;

/**
 * struct sev_data_tio_tdi_create - TIO_TDI_CREATE command
 *
 * @length: Length in bytes of this command buffer
 * @spdm_ctrl: SPDM control structure
 * @dev_ctx_paddr: SPA of a device context page
 * @tdi_ctx_paddr: SPA of page donated by hypervisor
 * @interface_id: Interface ID of the TDI as defined by TDISP (host PCIID)
 */
struct sev_data_tio_tdi_create {
	u32 length;				/* In */
	u32 reserved;
	struct sla_addr_t dev_ctx_sla;			/* In */
	struct sla_addr_t tdi_ctx_sla;			/* In */
	struct tdisp_interface_id interface_id;	/* In */
	u8 reserved2[12];
} __packed;

struct sev_data_tio_tdi_reclaim {
	u32 length;				/* In */
	u32 reserved;
	struct sla_addr_t dev_ctx_sla;			/* In */
	struct sla_addr_t tdi_ctx_sla;			/* In */
	u64 reserved2;
} __packed;

/*
 * struct sev_data_tio_tdi_bind - TIO_TDI_BIND command
 *
 * @length: Length in bytes of this command buffer
 * @spdm_ctrl: SPDM control structure defined in Chapter 2.
 * @tdi_ctx_paddr: SPA of page donated by hypervisor
 * @guest_ctx_paddr: SPA of guest context page
 * @flags:
 *  4 ALL_REQUEST_REDIRECT Requires ATS translated requests to route through
 *                         the root complex. Must be 1.
 *  3 BIND_P2P Enables direct P2P. Must be 0
 *  2 LOCK_MSIX Lock the MSI-X table and PBA.
 *  1 CACHE_LINE_SIZE Indicates the cache line size. 0 indicates 64B. 1 indicates 128B.
 *                    Must be 0.
 *  0 NO_FW_UPDATE Indicates that no firmware updates are allowed while the interface
 *                 is locked.
 * @mmio_reporting_offset: Offset added to the MMIO range addresses in the interface
 *                         report.
 * @guest_interface_id: Hypervisor provided identifier used by the guest to identify
 *                      the TDI in guest messages
 */
struct sev_data_tio_tdi_bind {
	u32 length;				/* In */
	u32 reserved;
	struct spdm_ctrl spdm_ctrl;		/* In */
	struct sla_addr_t dev_ctx_sla;
	struct sla_addr_t tdi_ctx_sla;
	u64 gctx_paddr;
	u16 guest_device_id;
	union {
		u16 flags;
		/* These are TDISP's LOCK_INTERFACE_REQUEST flags */
		struct {
			u16 no_fw_update:1;
			u16 reservedf1:1;
			u16 lock_msix:1;
			u16 bind_p2p:1;
			u16 all_request_redirect:1;
		};
	} tdisp_lock_if;
	u16 run:1;
	u16 reserved2:15;
	u8 reserved3[2];
} __packed;

/*
 * struct sev_data_tio_tdi_unbind - TIO_TDI_UNBIND command
 *
 * @length: Length in bytes of this command buffer
 * @spdm_ctrl: SPDM control structure defined in Chapter 2.
 * @tdi_ctx_paddr: SPA of page donated by hypervisor
 */
struct sev_data_tio_tdi_unbind {
	u32 length;				/* In */
	u32 reserved;
	struct spdm_ctrl spdm_ctrl;		/* In */
	struct sla_addr_t dev_ctx_sla;
	struct sla_addr_t tdi_ctx_sla;
	u64 gctx_paddr;			/* In */
} __packed;

/*
 * struct sev_data_tio_tdi_report - TIO_TDI_REPORT command
 *
 * @length: Length in bytes of this command buffer
 * @spdm_ctrl: SPDM control structure defined in Chapter 2.
 * @dev_ctx_sla: Scatter list address of the device context buffer
 * @tdi_ctx_paddr: Scatter list address of a TDI context buffer
 * @guest_ctx_paddr: System physical address of a guest context page
 */
struct sev_data_tio_tdi_report {
	u32 length;
	u32 reserved;
	struct spdm_ctrl spdm_ctrl;
	struct sla_addr_t dev_ctx_sla;
	struct sla_addr_t tdi_ctx_sla;
	u64 gctx_paddr;
} __packed;

struct sev_data_tio_asid_fence_clear {
	u32 length;				/* In */
	u32 reserved1;
	u64 gctx_paddr;			/* In */
	u16 device_id;
	u8 segment_id;
	u8 reserved[13];
} __packed;

struct sev_data_tio_asid_fence_status {
	u32 length;				/* In */
	u32 asid;				/* In */
	u64 status_pa;
	u16 device_id;
	u8 segment_id;
	u8 reserved[13];
} __packed;

/**
 * struct sev_data_tio_guest_request - TIO_GUEST_REQUEST command
 *
 * @length: Length in bytes of this command buffer
 * @spdm_ctrl: SPDM control structure defined in Chapter 2.
 * @gctx_paddr: system physical address of guest context page
 * @tdi_ctx_paddr: SPA of page donated by hypervisor
 * @req_paddr: system physical address of request page
 * @res_paddr: system physical address of response page
 */
struct sev_data_tio_guest_request {
	u32 length;				/* In */
	u32 reserved;
	struct spdm_ctrl spdm_ctrl;		/* In */
	struct sla_addr_t dev_ctx_sla;
	struct sla_addr_t tdi_ctx_sla;
	u64 gctx_paddr;
	u64 req_paddr;				/* In */
	u64 res_paddr;				/* In */
} __packed;

struct sev_data_tio_roll_key {
	u32 length;				/* In */
	u32 reserved;
	struct spdm_ctrl spdm_ctrl;		/* In */
	struct sla_addr_t dev_ctx_sla;			/* In */
} __packed;

static struct sla_buffer_hdr *sla_buffer_map(struct sla_addr_t sla)
{
	struct sla_buffer_hdr *buf;

	BUILD_BUG_ON(sizeof(struct sla_buffer_hdr) != 0x40);
	if (IS_SLA_NULL(sla))
		return NULL;

	if (sla.page_type == SLA_PAGE_TYPE_SCATTER) {
		struct sla_addr_t *scatter = __va((u64)sla.pfn << PAGE_SHIFT);
		unsigned int i, npages = 0;
		struct page **pp;

		for (i = 0; i < SLA_SCATTER_LEN(sla); ++i) {
			if (WARN_ON_ONCE(SLA_SZ(scatter[i]) > SZ_4K))
				return NULL;

			if (WARN_ON_ONCE(scatter[i].page_type == SLA_PAGE_TYPE_SCATTER))
				return NULL;

			if (IS_SLA_EOL(scatter[i])) {
				npages = i;
				break;
			}
		}
		if (WARN_ON_ONCE(!npages))
			return NULL;

		pp = kmalloc_array(npages, sizeof(pp[0]), GFP_KERNEL);
		if (!pp)
			return NULL;

		for (i = 0; i < npages; ++i)
			pp[i] = pfn_to_page(scatter[i].pfn);

		buf = vm_map_ram(pp, npages, 0);
		kfree(pp);
	} else {
		struct page *pg = pfn_to_page(sla.pfn);

		buf = vm_map_ram(&pg, 1, 0);
	}

	return buf;
}

static void sla_buffer_unmap(struct sla_addr_t sla, struct sla_buffer_hdr *buf)
{
	if (!buf)
		return;

	if (sla.page_type == SLA_PAGE_TYPE_SCATTER) {
		struct sla_addr_t *scatter = __va((u64)sla.pfn << PAGE_SHIFT);
		unsigned int i, npages = 0;

		for (i = 0; i < SLA_SCATTER_LEN(sla); ++i) {
			if (IS_SLA_EOL(scatter[i])) {
				npages = i;
				break;
			}
		}
		if (!npages)
			return;

		vm_unmap_ram(buf, npages);
	} else {
		vm_unmap_ram(buf, 1);
	}
}

static void dobj_response_init(struct sla_buffer_hdr *buf)
{
	struct spdm_dobj_hdr *dobj = sla_to_dobj_hdr(buf);

	dobj->id = SPDM_DOBJ_ID_RESP;
	dobj->version.major = 0x1;
	dobj->version.minor = 0;
	dobj->length = 0;
	buf->payload_sz = sla_dobj_id_to_size(dobj->id) + dobj->length;
}

static void sla_free(struct sla_addr_t sla, size_t len, bool firmware_state)
{
	unsigned int npages = PAGE_ALIGN(len) >> PAGE_SHIFT;
	struct sla_addr_t *scatter = NULL;
	int ret = 0, i;

	if (IS_SLA_NULL(sla))
		return;

	if (firmware_state) {
		if (sla.page_type == SLA_PAGE_TYPE_SCATTER) {
			scatter = __va((u64)sla.pfn << PAGE_SHIFT);

			for (i = 0; i < npages; ++i) {
				if (IS_SLA_EOL(scatter[i]))
					break;

				ret = snp_reclaim_pages((u64)scatter[i].pfn << PAGE_SHIFT, 1, false);
				if (ret)
					break;
			}
		} else {
			pr_err("Reclaiming %llx\n", (u64)sla.pfn << PAGE_SHIFT);
			ret = snp_reclaim_pages((u64)sla.pfn << PAGE_SHIFT, 1, false);
		}
	}

	if (WARN_ON(ret))
		return;

	if (scatter) {
		for (i = 0; i < npages; ++i) {
			if (IS_SLA_EOL(scatter[i]))
				break;
			free_page((unsigned long)__va((u64)scatter[i].pfn << PAGE_SHIFT));
		}
	}

	free_page((unsigned long)__va((u64)sla.pfn << PAGE_SHIFT));
}

static struct sla_addr_t sla_alloc(size_t len, bool firmware_state)
{
	unsigned long i, npages = PAGE_ALIGN(len) >> PAGE_SHIFT;
	struct sla_addr_t *scatter = NULL;
	struct sla_addr_t ret = SLA_NULL;
	struct sla_buffer_hdr *buf;
	struct page *pg;

	if (npages == 0)
		return ret;

	if (WARN_ON_ONCE(npages > ((PAGE_SIZE / sizeof(struct sla_addr_t)) + 1)))
		return ret;

	BUILD_BUG_ON(PAGE_SIZE < SZ_4K);

	if (npages > 1) {
		pg = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!pg)
			return SLA_NULL;

		ret.pfn = page_to_pfn(pg);
		ret.page_size = SLA_PAGE_SIZE_4K;
		ret.page_type = SLA_PAGE_TYPE_SCATTER;

		scatter = page_to_virt(pg);
		for (i = 0; i < npages; ++i) {
			pg = alloc_page(GFP_KERNEL | __GFP_ZERO);
			if (!pg)
				goto no_reclaim_exit;

			scatter[i].pfn = page_to_pfn(pg);
			scatter[i].page_type = SLA_PAGE_TYPE_DATA;
			scatter[i].page_size = SLA_PAGE_SIZE_4K;
		}
		scatter[i] = SLA_EOL;
	} else {
		pg = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!pg)
			return SLA_NULL;

		ret.pfn = page_to_pfn(pg);
		ret.page_size = SLA_PAGE_SIZE_4K;
		ret.page_type = SLA_PAGE_TYPE_DATA;
	}

	buf = sla_buffer_map(ret);
	if (!buf)
		goto no_reclaim_exit;

	buf->capacity_sz = (npages << PAGE_SHIFT);
	sla_buffer_unmap(ret, buf);

	if (firmware_state) {
		if (scatter) {
			for (i = 0; i < npages; ++i) {
				if (rmp_make_private(scatter[i].pfn, 0, PG_LEVEL_4K, 0, true))
					goto free_exit;
			}
		} else {
			if (rmp_make_private(ret.pfn, 0, PG_LEVEL_4K, 0, true))
				goto no_reclaim_exit;
		}
	}

	return ret;

no_reclaim_exit:
	firmware_state = false;
free_exit:
	sla_free(ret, len, firmware_state);
	return SLA_NULL;
}

/* Expands a buffer, only firmware owned buffers allowed for now */
static int sla_expand(struct sla_addr_t *sla, size_t *len)
{
	struct sla_buffer_hdr *oldbuf = sla_buffer_map(*sla), *newbuf;
	struct sla_addr_t oldsla = *sla, newsla;
	size_t oldlen = *len, newlen;

	if (!oldbuf)
		return -EFAULT;

	newlen = oldbuf->capacity_sz;
	if (oldbuf->capacity_sz == oldlen) {
		/* This buffer does not require expansion, must be another buffer */
		sla_buffer_unmap(oldsla, oldbuf);
		return 1;
	}

	pr_notice("Expanding BUFFER from %ld to %ld bytes\n", oldlen, newlen);

	newsla = sla_alloc(newlen, true);
	if (IS_SLA_NULL(newsla))
		return -ENOMEM;

	newbuf = sla_buffer_map(newsla);
	if (!newbuf) {
		sla_free(newsla, newlen, true);
		return -EFAULT;;
	}

	memcpy(newbuf, oldbuf, oldlen);

	sla_buffer_unmap(newsla, newbuf);
	sla_free(oldsla, oldlen, true);
	*sla = newsla;
	*len = newlen;

	return 0;
}

void tio_save_output(struct tsm_blob **blob, struct sla_addr_t sla, u32 check_dobjid)
{
	struct sla_buffer_hdr *buf;
	struct spdm_dobj_hdr *hdr;

	tsm_blob_free(*blob);
	*blob = NULL;

	buf = sla_buffer_map(sla);
	if (!buf)
		return;

	hdr = sla_to_dobj_hdr_check(buf, check_dobjid);
	if (hdr)
		*blob = tsm_blob_new(SPDM_DOBJ_DATA(hdr), hdr->length);

	sla_buffer_unmap(sla, buf);
}

static int sev_tio_do_cmd(int cmd, void *data, size_t data_len, int *psp_ret,
			  struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm)
{
	int rc;

	*psp_ret = 0;
	rc = sev_do_cmd(cmd, data, psp_ret);

	if (WARN_ON(!spdm && !rc && *psp_ret == SEV_RET_SPDM_REQUEST))
		return -EIO;

	if (rc == 0 && *psp_ret == SEV_RET_EXPAND_BUFFER_LENGTH_REQUEST) {
		int rc1, rc2;

		rc1 = sla_expand(&dev_data->output, &dev_data->output_len);
		if (rc1 < 0)
			return rc1;

		rc2 = sla_expand(&dev_data->scratch, &dev_data->scratch_len);
		if (rc2 < 0)
			return rc2;

		if (!rc1 && !rc2)
			/* Neither buffer requires expansion, this is wrong */
			return -EFAULT;

		*psp_ret = 0;
		rc = sev_do_cmd(cmd, data, psp_ret);
	}

	if (spdm && (rc == 0 || rc == -EIO) && *psp_ret == SEV_RET_SPDM_REQUEST) {
		struct spdm_dobj_hdr_resp *resp_hdr;
		struct spdm_dobj_hdr_req *req_hdr;
		size_t resp_len = dev_data->tio_status->spdm_req_size_max -
			(sla_dobj_id_to_size(SPDM_DOBJ_ID_RESP) + sizeof(struct sla_buffer_hdr));

		if (!dev_data->cmd) {
			if (WARN_ON_ONCE(!data_len || (data_len != *(u32 *) data)))
				return -EINVAL;
			if (WARN_ON(data_len > sizeof(dev_data->cmd_data)))
				return -EFAULT;
			memcpy(dev_data->cmd_data, data, data_len);
			memset(&dev_data->cmd_data[data_len], 0xFF,
			       sizeof(dev_data->cmd_data) - data_len);
			dev_data->cmd = cmd;
		}

		req_hdr = sla_to_dobj_req_hdr(dev_data->reqbuf);
		resp_hdr = sla_to_dobj_resp_hdr(dev_data->respbuf);
		switch (req_hdr->data_type) {
		case DOBJ_DATA_TYPE_SPDM:
			rc = TSM_PROTO_CMA_SPDM;
			break;
		case DOBJ_DATA_TYPE_SECURE_SPDM:
			rc = TSM_PROTO_SECURED_CMA_SPDM;
			break;
		default:
			rc = -EINVAL;
			return rc;
		}
		resp_hdr->data_type = req_hdr->data_type;
		spdm->req_len = req_hdr->hdr.length;
		spdm->rsp_len = resp_len;
	} else if (dev_data && dev_data->cmd) {
		/* For either error or success just stop the bouncing */
		memset(dev_data->cmd_data, 0, sizeof(dev_data->cmd_data));
		dev_data->cmd = 0;
	}

	return rc;
}

int sev_tio_continue(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm)
{
	struct spdm_dobj_hdr_resp *resp_hdr;
	int ret;

	if (!dev_data || !dev_data->cmd)
		return -EINVAL;

	resp_hdr = sla_to_dobj_resp_hdr(dev_data->respbuf);
	resp_hdr->hdr.length = ALIGN(sla_dobj_id_to_size(SPDM_DOBJ_ID_RESP) + spdm->rsp_len, 32);
	dev_data->respbuf->payload_sz = resp_hdr->hdr.length;

	ret = sev_tio_do_cmd(dev_data->cmd, dev_data->cmd_data, 0,
			     &dev_data->psp_ret, dev_data, spdm);

	return ret;
}

static int spdm_ctrl_init(struct tsm_spdm *spdm, struct spdm_ctrl *ctrl,
			  struct tsm_dev_tio *dev_data)
{
	ctrl->req = dev_data->req;
	ctrl->resp = dev_data->resp;
	ctrl->scratch = dev_data->scratch;
	ctrl->output = dev_data->output;

	spdm->req = sla_to_data(dev_data->reqbuf, SPDM_DOBJ_ID_REQ);
	spdm->rsp = sla_to_data(dev_data->respbuf, SPDM_DOBJ_ID_RESP);
	if (!spdm->req || !spdm->rsp)
		return -EFAULT;

	return 0;
}

static void spdm_ctrl_free(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm)
{
	size_t len = dev_data->tio_status->spdm_req_size_max -
		(sla_dobj_id_to_size(SPDM_DOBJ_ID_RESP) +
		 sizeof(struct sla_buffer_hdr));

	sla_buffer_unmap(dev_data->resp, dev_data->respbuf);
	sla_buffer_unmap(dev_data->req, dev_data->reqbuf);
	spdm->rsp = NULL;
	spdm->req = NULL;
	sla_free(dev_data->req, len, true);
	sla_free(dev_data->resp, len, false);
	sla_free(dev_data->scratch, dev_data->tio_status->spdm_scratch_size_max, true);

	dev_data->req.sla = 0;
	dev_data->resp.sla = 0;
	dev_data->scratch.sla = 0;
	dev_data->respbuf = NULL;
	dev_data->reqbuf = NULL;
	sla_free(dev_data->output, dev_data->tio_status->spdm_out_size_max, true);
}

static int spdm_ctrl_alloc(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm)
{
	struct sev_tio_status *tio_status = dev_data->tio_status;
	int ret;

	dev_data->req = sla_alloc(tio_status->spdm_req_size_max, true);
	dev_data->resp = sla_alloc(tio_status->spdm_req_size_max, false);
	dev_data->scratch_len = tio_status->spdm_scratch_size_max;
	dev_data->scratch = sla_alloc(dev_data->scratch_len, true);
	dev_data->output_len = tio_status->spdm_out_size_max;
	dev_data->output = sla_alloc(dev_data->output_len, true);

	if (IS_SLA_NULL(dev_data->req) || IS_SLA_NULL(dev_data->resp) ||
	    IS_SLA_NULL(dev_data->scratch) || IS_SLA_NULL(dev_data->dev_ctx)) {
		ret = -ENOMEM;
		goto free_spdm_exit;
	}

	dev_data->reqbuf = sla_buffer_map(dev_data->req);
	dev_data->respbuf = sla_buffer_map(dev_data->resp);
	if (!dev_data->reqbuf || !dev_data->respbuf) {
		ret = -EFAULT;
		goto free_spdm_exit;
	}

	dobj_response_init(dev_data->respbuf);

	return 0;

free_spdm_exit:
	spdm_ctrl_free(dev_data, spdm);
	return ret;
}

int sev_tio_status(struct sev_device *sev)
{
	struct sev_data_tio_status data_status = {
		.length = sizeof(data_status),
	};
	struct sev_tio_status *tio_status;
	int ret = 0, psp_ret = 0;

	if (!sev_version_greater_or_equal(1, 55))
		return -EPERM;

	WARN_ON(tio_status);

	tio_status = snp_alloc_firmware_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!tio_status)
		return -ENOMEM;

	data_status.status_paddr = __psp_pa(tio_status);
	ret = sev_do_cmd(SEV_CMD_TIO_STATUS, &data_status, &psp_ret);
	if (ret)
		goto err_msg_exit;

	if (tio_status->flags & 0xFFFFFF00) {
		ret = -EFAULT;
		goto err_msg_exit;
	}

	if (!tio_status->tio_en && !tio_status->tio_init_done) {
		ret = -ENOENT;
		goto err_msg_exit;
	}

	if (tio_status->tio_en && !tio_status->tio_init_done) {
		struct sev_data_tio_init ti = { .length = sizeof(ti) };

		ret = sev_do_cmd(SEV_CMD_TIO_INIT, &ti, &psp_ret);
		if (ret)
			goto err_msg_exit;

		ret = sev_do_cmd(SEV_CMD_TIO_STATUS, &data_status, &psp_ret);
		if (ret)
			goto err_msg_exit;

		print_hex_dump(KERN_INFO, "TIO_ST ", DUMP_PREFIX_OFFSET, 16, 1, tio_status,
			       sizeof(*tio_status), false);
	}

	sev->tio_status = kmemdup(tio_status, sizeof(*tio_status), GFP_KERNEL);
	if (!sev->tio_status) {
		ret = -ENOMEM;
		goto err_msg_exit;
	}

	pr_notice("SEV-TIO status: EN=%d INIT_DONE=%d rq=%d..%d rs=%d..%d scr=%d..%d out=%d..%d dev=%d tdi=%d\n",
		  tio_status->tio_en, tio_status->tio_init_done,
		  tio_status->spdm_req_size_min, tio_status->spdm_req_size_max,
		  tio_status->spdm_rsp_size_min, tio_status->spdm_rsp_size_max,
		  tio_status->spdm_scratch_size_min, tio_status->spdm_scratch_size_max,
		  tio_status->spdm_out_size_min, tio_status->spdm_out_size_max,
		  tio_status->devctx_size, tio_status->tdictx_size);

	goto free_exit;

err_msg_exit:
	pr_err("Failed to enable SEV-TIO: ret=%d en=%d initdone=%d SEV=%d\n",
	       ret, tio_status->tio_en, tio_status->tio_init_done,
	       boot_cpu_has(X86_FEATURE_SEV));
	pr_err("Check BIOS for: SMEE, SEV Control, SEV-ES ASID Space Limit=99,\n"
	       "SNP Memory (RMP Table) Coverage, RMP Coverage for 64Bit MMIO Ranges\n"
	       "SEV-SNP Support, SEV-TIO Support, PCIE IDE Capability\n");
	if (cc_platform_has(CC_ATTR_MEM_ENCRYPT))
		pr_err("mem_encrypt=on is currently broken\n");

free_exit:
	snp_free_firmware_page(tio_status);
	return ret;
}

int sev_tio_dev_create(struct tsm_dev_tio *dev_data, u16 device_id,
		       u16 root_port_id, u8 segment_id)
{
	struct sev_tio_status *tio_status = dev_data->tio_status;
	struct sev_data_tio_dev_create create = {
		.length = sizeof(create),
		.device_id = device_id,
		.root_port_id = root_port_id,
		.segment_id = segment_id,
	};
	void *data_pg;
	int ret;

	dev_data->dev_ctx = sla_alloc(tio_status->devctx_size, true);
	if (IS_SLA_NULL(dev_data->dev_ctx))
		return -ENOMEM;

	/* Alloc data page for TDI_STATUS, TDI_INFO, the PSP or prep_data_pg() will zero it */
	data_pg = snp_alloc_firmware_page(GFP_KERNEL_ACCOUNT);
	if (!data_pg) {
		ret = -ENOMEM;
		goto free_ctx_exit;
	}

	create.dev_ctx_sla = dev_data->dev_ctx;
	ret = sev_tio_do_cmd(SEV_CMD_TIO_DEV_CREATE, &create, sizeof(create),
			     &dev_data->psp_ret, dev_data, NULL);
	if (ret)
		goto free_data_pg_exit;

	dev_data->data_pg = data_pg;

	return ret;

free_data_pg_exit:
	snp_free_firmware_page(data_pg);
free_ctx_exit:
	sla_free(create.dev_ctx_sla, tio_status->devctx_size, true);
	return ret;
}

int sev_tio_dev_reclaim(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm)
{
	struct sev_tio_status *tio_status = dev_data->tio_status;
	struct sev_data_tio_dev_reclaim r = {
		.length = sizeof(r),
		.dev_ctx_sla = dev_data->dev_ctx,
	};
	int ret;

	if (dev_data->data_pg) {
		snp_free_firmware_page(dev_data->data_pg);
		dev_data->data_pg = NULL;
	}

	if (IS_SLA_NULL(dev_data->dev_ctx))
		return 0;

	ret = sev_do_cmd(SEV_CMD_TIO_DEV_RECLAIM, &r, &dev_data->psp_ret);

	sla_free(dev_data->dev_ctx, tio_status->devctx_size, true);
	dev_data->dev_ctx = SLA_NULL;

	spdm_ctrl_free(dev_data, spdm);

	return ret;
}

int sev_tio_dev_connect(struct tsm_dev_tio *dev_data, u8 tc_mask, u8 ids[8], u8 cert_slot,
			struct tsm_spdm *spdm)
{
	struct sev_data_tio_dev_connect connect = {
		.length = sizeof(connect),
		.tc_mask = tc_mask,
		.cert_slot = cert_slot,
		.dev_ctx_sla = dev_data->dev_ctx,
		.ide_stream_id = {
			ids[0], ids[1], ids[2], ids[3],
			ids[4], ids[5], ids[6], ids[7]
		},
	};
	int ret;

	if (WARN_ON(IS_SLA_NULL(dev_data->dev_ctx)))
		return -EFAULT;
	if (!(tc_mask & 1))
		return -EINVAL;

	ret = spdm_ctrl_alloc(dev_data, spdm);
	if (ret)
		return ret;
	ret = spdm_ctrl_init(spdm, &connect.spdm_ctrl, dev_data);
	if (ret)
		return ret;

	ret = sev_tio_do_cmd(SEV_CMD_TIO_DEV_CONNECT, &connect, sizeof(connect),
			     &dev_data->psp_ret, dev_data, spdm);

	return ret;
}

int sev_tio_dev_disconnect(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm)
{
	struct sev_data_tio_dev_disconnect dc = {
		.length = sizeof(dc),
		.dev_ctx_sla = dev_data->dev_ctx,
	};
	int ret;

	if (WARN_ON_ONCE(IS_SLA_NULL(dev_data->dev_ctx)))
		return -EFAULT;

	ret = spdm_ctrl_init(spdm, &dc.spdm_ctrl, dev_data);
	if (ret)
		return ret;

	ret = sev_tio_do_cmd(SEV_CMD_TIO_DEV_DISCONNECT, &dc, sizeof(dc),
			     &dev_data->psp_ret, dev_data, spdm);

	return ret;
}

int sev_tio_dev_measurements(struct tsm_dev_tio *dev_data, void *nonce, size_t nonce_len,
			     struct tsm_spdm *spdm)
{
	struct sev_data_tio_dev_meas meas = {
		.length = sizeof(meas),
		.raw_bitstream = 1,
	};

	if (nonce_len > sizeof(meas.meas_nonce))
		return -EINVAL;

	if (WARN_ON(IS_SLA_NULL(dev_data->dev_ctx)))
		return -EFAULT;

	spdm_ctrl_init(spdm, &meas.spdm_ctrl, dev_data);
	meas.dev_ctx_sla = dev_data->dev_ctx;
	memcpy(meas.meas_nonce, nonce, nonce_len);

	return sev_tio_do_cmd(SEV_CMD_TIO_DEV_MEASUREMENTS, &meas, sizeof(meas),
			      &dev_data->psp_ret, dev_data, spdm);
}

int sev_tio_dev_certificates(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm)
{
	struct sev_data_tio_dev_certs c = {
		.length = sizeof(c),
	};

	if (WARN_ON(IS_SLA_NULL(dev_data->dev_ctx)))
		return -EFAULT;

	spdm_ctrl_init(spdm, &c.spdm_ctrl, dev_data);
	c.dev_ctx_sla = dev_data->dev_ctx;

	return sev_tio_do_cmd(SEV_CMD_TIO_DEV_CERTIFICATES, &c, sizeof(c),
			      &dev_data->psp_ret, dev_data, spdm);
}

int sev_tio_dev_status(struct tsm_dev_tio *dev_data, struct tsm_dev_status *s)
{
	struct sev_tio_dev_status *status =
		prep_data_pg(struct sev_tio_dev_status, dev_data);
	struct sev_data_tio_dev_status data_status = {
		.length = sizeof(data_status),
		.dev_ctx_paddr = dev_data->dev_ctx,
		.status_length = sizeof(*status),
		.status_paddr = __psp_pa(status),
	};
	int ret;

	if (!dev_data)
		return -ENODEV;

	if (IS_SLA_NULL(dev_data->dev_ctx))
		return -ENXIO;

	ret = sev_do_cmd(SEV_CMD_TIO_DEV_STATUS, &data_status, &dev_data->psp_ret);
	if (ret)
		return ret;

	s->ctx_state = status->ctx_state;
	s->device_id = status->device_id;
	s->tc_mask = status->tc_mask;
	memcpy(s->ide_stream_id, status->ide_stream_id, sizeof(status->ide_stream_id));
	s->certs_slot = status->certs_slot;
	s->no_fw_update = status->no_fw_update;

	return 0;
}

int sev_tio_ide_refresh(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm)
{
	struct sev_data_tio_roll_key rk = {
		.length = sizeof(rk),
		.dev_ctx_sla = dev_data->dev_ctx,
	};
	int ret;

	if (WARN_ON(IS_SLA_NULL(dev_data->dev_ctx)))
		return -EFAULT;

	ret = spdm_ctrl_init(spdm, &rk.spdm_ctrl, dev_data);
	if (ret)
		return ret;

	ret = sev_tio_do_cmd(SEV_CMD_TIO_ROLL_KEY, &rk, sizeof(rk),
			     &dev_data->psp_ret, dev_data, spdm);

	return ret;
}

int sev_tio_tdi_create(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data, u16 dev_id,
		       u8 rseg, u8 rseg_valid)
{
	struct sev_tio_status *tio_status = dev_data->tio_status;
	struct sev_data_tio_tdi_create c = {
		.length = sizeof(c),
	};
	int ret;

	if (!dev_data || !tdi_data) /* Device is not "connected" */
		return -EPERM;

	if (WARN_ON_ONCE(IS_SLA_NULL(dev_data->dev_ctx) || !IS_SLA_NULL(tdi_data->tdi_ctx)))
		return -EFAULT;

	tdi_data->tdi_ctx = sla_alloc(tio_status->tdictx_size, true);
	if (IS_SLA_NULL(tdi_data->tdi_ctx))
		return -ENOMEM;

	c.dev_ctx_sla = dev_data->dev_ctx;
	c.tdi_ctx_sla = tdi_data->tdi_ctx;
	c.interface_id.function_id =
		FIELD_PREP(TSM_TDISP_IID_REQUESTER_ID, dev_id) |
		FIELD_PREP(TSM_TDISP_IID_RSEG, rseg) |
		FIELD_PREP(TSM_TDISP_IID_RSEG_VALID, rseg_valid);

	ret = sev_do_cmd(SEV_CMD_TIO_TDI_CREATE, &c, &dev_data->psp_ret);
	if (ret)
		goto free_exit;

	return 0;

free_exit:
	sla_free(tdi_data->tdi_ctx, tio_status->tdictx_size, true);
	tdi_data->tdi_ctx = SLA_NULL;
	return ret;
}

void sev_tio_tdi_reclaim(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data)
{
	struct sev_tio_status *tio_status = dev_data->tio_status;
	struct sev_data_tio_tdi_reclaim r = {
		.length = sizeof(r),
	};

	if (WARN_ON(!dev_data || !tdi_data))
		return;
	if (IS_SLA_NULL(dev_data->dev_ctx) || IS_SLA_NULL(tdi_data->tdi_ctx))
		return;

	r.dev_ctx_sla = dev_data->dev_ctx;
	r.tdi_ctx_sla = tdi_data->tdi_ctx;

	sev_do_cmd(SEV_CMD_TIO_TDI_RECLAIM, &r, &dev_data->psp_ret);

	sla_free(tdi_data->tdi_ctx, tio_status->tdictx_size, true);
	tdi_data->tdi_ctx = SLA_NULL;
}

int sev_tio_tdi_bind(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data,
		     u32 guest_rid, u64 gctx_paddr, u32 asid, bool force_run,
		     struct tsm_spdm *spdm)
{
	struct sev_data_tio_tdi_bind b = {
		.length = sizeof(b),
	};

	if (WARN_ON_ONCE(IS_SLA_NULL(dev_data->dev_ctx) || IS_SLA_NULL(tdi_data->tdi_ctx)))
		return -EFAULT;

	spdm_ctrl_init(spdm, &b.spdm_ctrl, dev_data);
	b.dev_ctx_sla = dev_data->dev_ctx;
	b.tdi_ctx_sla = tdi_data->tdi_ctx;
	b.guest_device_id = guest_rid;
	b.gctx_paddr = gctx_paddr;
	b.run = force_run;

	tdi_data->gctx_paddr = gctx_paddr;
	tdi_data->asid = asid;

	return sev_tio_do_cmd(SEV_CMD_TIO_TDI_BIND, &b, sizeof(b),
			      &dev_data->psp_ret, dev_data, spdm);
}

int sev_tio_tdi_unbind(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data,
		       struct tsm_spdm *spdm)
{
	struct sev_data_tio_tdi_unbind ub = {
		.length = sizeof(ub),
	};

	if (WARN_ON(!tdi_data || !dev_data))
		return 0;

	if (WARN_ON(!tdi_data->gctx_paddr))
		return -EFAULT;

	spdm_ctrl_init(spdm, &ub.spdm_ctrl, dev_data);
	ub.dev_ctx_sla = dev_data->dev_ctx;
	ub.tdi_ctx_sla = tdi_data->tdi_ctx;
	ub.gctx_paddr = tdi_data->gctx_paddr;

	return sev_tio_do_cmd(SEV_CMD_TIO_TDI_UNBIND, &ub, sizeof(ub),
			      &dev_data->psp_ret, dev_data, spdm);
}

int sev_tio_tdi_report(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data,
		       struct tsm_spdm *spdm)
{
	struct sev_data_tio_tdi_report r = {
		.length = sizeof(r),
		.dev_ctx_sla = dev_data->dev_ctx,
		.tdi_ctx_sla = tdi_data->tdi_ctx,
		.gctx_paddr = tdi_data->gctx_paddr,
	};

	if (WARN_ON_ONCE(IS_SLA_NULL(dev_data->dev_ctx) || IS_SLA_NULL(tdi_data->tdi_ctx)))
		return -EFAULT;

	spdm_ctrl_init(spdm, &r.spdm_ctrl, dev_data);

	return sev_tio_do_cmd(SEV_CMD_TIO_TDI_REPORT, &r, sizeof(r),
			      &dev_data->psp_ret, dev_data, spdm);
}

int sev_tio_asid_fence_clear(u16 device_id, u8 segment_id, u64 gctx_paddr, int *psp_ret)
{
	struct sev_data_tio_asid_fence_clear c = {
		.length = sizeof(c),
		.gctx_paddr = gctx_paddr,
		.device_id = device_id,
		.segment_id = segment_id,
	};

	return sev_do_cmd(SEV_CMD_TIO_ASID_FENCE_CLEAR, &c, psp_ret);
}

int sev_tio_asid_fence_status(struct tsm_dev_tio *dev_data, u16 device_id, u8 segment_id,
			      u32 asid, bool *fenced)
{
	u64 *status = prep_data_pg(u64, dev_data);
	struct sev_data_tio_asid_fence_status s = {
		.length = sizeof(s),
		.asid = asid,
		.status_pa = __psp_pa(status),
		.device_id = device_id,
		.segment_id = segment_id,
	};
	int ret;

	ret = sev_do_cmd(SEV_CMD_TIO_ASID_FENCE_STATUS, &s, &dev_data->psp_ret);

	if (ret == SEV_RET_SUCCESS) {
		switch (*status) {
		case 0:
			*fenced = false;
			break;
		case 1:
			*fenced = true;
			break;
		default:
			pr_err("%04x:%x:%x.%d: undefined fence state %#llx\n",
			       segment_id, PCI_BUS_NUM(device_id),
			       PCI_SLOT(device_id), PCI_FUNC(device_id), *status);
			*fenced = true;
			break;
		}
	}

	return ret;
}

int sev_tio_guest_request(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data,
			  void *req, void *res, struct tsm_spdm *spdm)
{
	struct sev_data_tio_guest_request gr = {
		.length = sizeof(gr),
		.dev_ctx_sla = dev_data->dev_ctx,
		.tdi_ctx_sla = tdi_data->tdi_ctx,
		.gctx_paddr = tdi_data->gctx_paddr,
		.req_paddr = __psp_pa(req),
		.res_paddr = __psp_pa(res),
	};
	int ret;

	if (WARN_ON(!tdi_data || !dev_data))
		return -EINVAL;

	spdm_ctrl_init(spdm, &gr.spdm_ctrl, dev_data);

	ret = sev_tio_do_cmd(SEV_CMD_TIO_GUEST_REQUEST, &gr, sizeof(gr),
			     &dev_data->psp_ret, dev_data, spdm);

	return ret;
}

struct sev_tio_tdi_info_data {
	u32 length;
	struct tdisp_interface_id interface_id;
	union {
		u32 p1;
		struct {
			u32 meas_digest_valid:1;
			u32 meas_digest_fresh:1;
			u32 tdi_status:2; /* 0: TDI_UNBOUND 1: TDI_BIND_LOCKED 2: TDI_BIND_RUN */
		};
	};
	union {
		u32 p2;
		struct {
			u32 no_fw_update:1;
			u32 cache_line_size:1;
			u32 lock_msix:1;
			u32 bind_p2p:1;
			u32 all_request_redirect:1;
		};
	};
	u64 spdm_algos;
	u8 certs_digest[48];
	u8 meas_digest[48];
	u8 interface_report_digest[48];
	u64 intf_report_counter;
	u32 asid; /* ASID of the guest that this device is assigned to. Valid if CTX_STATE=1 */
	u8 reserved2[4];
} __packed;

struct sev_data_tio_tdi_info {
	u32 length;
	u32 reserved1;
	struct sla_addr_t dev_ctx_sla;
	struct sla_addr_t tdi_ctx_sla;
	u64 status_paddr;
	u8 reserved2[16];
} __packed;

int sev_tio_tdi_info(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data,
		     struct tsm_tdi_status *ts)
{
	struct sev_tio_tdi_info_data *data =
		prep_data_pg(struct sev_tio_tdi_info_data, dev_data);
	struct sev_data_tio_tdi_info info = {
		.length = sizeof(info),
		.dev_ctx_sla = dev_data->dev_ctx,
		.tdi_ctx_sla = tdi_data->tdi_ctx,
		.status_paddr = __psp_pa(data),
	};
	int ret;

	if (IS_SLA_NULL(dev_data->dev_ctx) || IS_SLA_NULL(tdi_data->tdi_ctx))
		return -ENXIO;

	ret = sev_do_cmd(SEV_CMD_TIO_TDI_INFO, &info, &dev_data->psp_ret);
	if (ret)
		return ret;

	ts->id = data->interface_id;
	ts->meas_digest_valid = data->meas_digest_valid;
	ts->meas_digest_fresh = data->meas_digest_fresh;
	ts->no_fw_update = data->no_fw_update;
	ts->cache_line_size = data->cache_line_size == 0 ? 64 : 128;
	ts->lock_msix = data->lock_msix;
	ts->bind_p2p = data->bind_p2p;
	ts->all_request_redirect = data->all_request_redirect;

#define __ALGO(x, n, y) \
	((((x) & (0xFFULL << (n))) == TIO_SPDM_ALGOS_##y) ? \
	 (1ULL << TSM_SPDM_ALGOS_##y) : 0)
	ts->spdm_algos =
		__ALGO(data->spdm_algos, 0, DHE_SECP256R1) |
		__ALGO(data->spdm_algos, 0, DHE_SECP384R1) |
		__ALGO(data->spdm_algos, 8, AEAD_AES_128_GCM) |
		__ALGO(data->spdm_algos, 8, AEAD_AES_256_GCM) |
		__ALGO(data->spdm_algos, 16, ASYM_TPM_ALG_RSASSA_3072) |
		__ALGO(data->spdm_algos, 16, ASYM_TPM_ALG_ECDSA_ECC_NIST_P256) |
		__ALGO(data->spdm_algos, 16, ASYM_TPM_ALG_ECDSA_ECC_NIST_P384) |
		__ALGO(data->spdm_algos, 24, HASH_TPM_ALG_SHA_256) |
		__ALGO(data->spdm_algos, 24, HASH_TPM_ALG_SHA_384) |
		__ALGO(data->spdm_algos, 32, KEY_SCHED_SPDM_KEY_SCHEDULE);
#undef __ALGO
	memcpy(ts->certs_digest, data->certs_digest, sizeof(ts->certs_digest));
	memcpy(ts->meas_digest, data->meas_digest, sizeof(ts->meas_digest));
	memcpy(ts->interface_report_digest, data->interface_report_digest,
	       sizeof(ts->interface_report_digest));
	ts->intf_report_counter = data->intf_report_counter;
	ts->valid = true;

	return 0;
}

struct sev_tio_tdi_status_data {
	u32 length;
	u8 tdisp_state;
	u8 reserved1[3];
} __packed;

struct sev_data_tio_tdi_status {
	u32 length;
	u32 reserved1;
	struct spdm_ctrl spdm_ctrl;
	struct sla_addr_t dev_ctx_sla;
	struct sla_addr_t tdi_ctx_sla;
	u64 status_paddr;
} __packed;

int sev_tio_tdi_status(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data,
		       struct tsm_spdm *spdm)
{
	struct sev_tio_tdi_status_data *data =
		prep_data_pg(struct sev_tio_tdi_status_data, dev_data);
	struct sev_data_tio_tdi_status status = {
		.length = sizeof(status),
		.dev_ctx_sla = dev_data->dev_ctx,
		.tdi_ctx_sla = tdi_data->tdi_ctx,
		.status_paddr = __psp_pa(data),
	};

	if (IS_SLA_NULL(dev_data->dev_ctx) || IS_SLA_NULL(tdi_data->tdi_ctx))
		return -ENXIO;

	spdm_ctrl_init(spdm, &status.spdm_ctrl, dev_data);

	return sev_tio_do_cmd(SEV_CMD_TIO_TDI_STATUS, &status, sizeof(status),
			      &dev_data->psp_ret, dev_data, spdm);
}

#define TIO_TDISP_STATE_CONFIG_UNLOCKED	0
#define TIO_TDISP_STATE_CONFIG_LOCKED	1
#define TIO_TDISP_STATE_RUN		2
#define TIO_TDISP_STATE_ERROR		3

int sev_tio_tdi_status_fin(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data,
			   enum tsm_tdisp_state *state)
{
	struct sev_tio_tdi_status_data *data = (struct sev_tio_tdi_status_data *) dev_data->data_pg;

	switch (data->tdisp_state) {
#define __TDISP_STATE(y) case TIO_TDISP_STATE_##y: *state = TDISP_STATE_##y; break
	__TDISP_STATE(CONFIG_UNLOCKED);
	__TDISP_STATE(CONFIG_LOCKED);
	__TDISP_STATE(RUN);
	__TDISP_STATE(ERROR);
#undef __TDISP_STATE
	}

	return 0;
}

int sev_tio_cmd_buffer_len(int cmd)
{
	switch (cmd) {
	case SEV_CMD_TIO_STATUS:		return sizeof(struct sev_data_tio_status);
	case SEV_CMD_TIO_INIT:			return sizeof(struct sev_data_tio_init);
	case SEV_CMD_TIO_DEV_CREATE:		return sizeof(struct sev_data_tio_dev_create);
	case SEV_CMD_TIO_DEV_RECLAIM:		return sizeof(struct sev_data_tio_dev_reclaim);
	case SEV_CMD_TIO_DEV_CONNECT:		return sizeof(struct sev_data_tio_dev_connect);
	case SEV_CMD_TIO_DEV_DISCONNECT:	return sizeof(struct sev_data_tio_dev_disconnect);
	case SEV_CMD_TIO_DEV_STATUS:		return sizeof(struct sev_data_tio_dev_status);
	case SEV_CMD_TIO_DEV_MEASUREMENTS:	return sizeof(struct sev_data_tio_dev_meas);
	case SEV_CMD_TIO_DEV_CERTIFICATES:	return sizeof(struct sev_data_tio_dev_certs);
	case SEV_CMD_TIO_TDI_CREATE:		return sizeof(struct sev_data_tio_tdi_create);
	case SEV_CMD_TIO_TDI_RECLAIM:		return sizeof(struct sev_data_tio_tdi_reclaim);
	case SEV_CMD_TIO_TDI_BIND:		return sizeof(struct sev_data_tio_tdi_bind);
	case SEV_CMD_TIO_TDI_UNBIND:		return sizeof(struct sev_data_tio_tdi_unbind);
	case SEV_CMD_TIO_TDI_REPORT:		return sizeof(struct sev_data_tio_tdi_report);
	case SEV_CMD_TIO_TDI_STATUS:		return sizeof(struct sev_data_tio_tdi_status);
	case SEV_CMD_TIO_GUEST_REQUEST:		return sizeof(struct sev_data_tio_guest_request);
	case SEV_CMD_TIO_ASID_FENCE_CLEAR:	return sizeof(struct sev_data_tio_asid_fence_clear);
	case SEV_CMD_TIO_ASID_FENCE_STATUS: return sizeof(struct sev_data_tio_asid_fence_status);
	case SEV_CMD_TIO_TDI_INFO:		return sizeof(struct sev_data_tio_tdi_info);
	case SEV_CMD_TIO_ROLL_KEY:		return sizeof(struct sev_data_tio_roll_key);
	default:				return 0;
	}
}
