// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bitfield.h>
#include <linux/pci.h>
#include <linux/psp-sev.h>
#include <linux/tsm.h>
#include <crypto/gcm.h>
#include <uapi/linux/sev-guest.h>

#include <asm/svm.h>
#include <asm/sev.h>

#define TIO_MESSAGE_VERSION	1

ulong tsm_vtom = 0x7fffffff;
module_param(tsm_vtom, ulong, 0644);
MODULE_PARM_DESC(tsm_vtom, "SEV TIO vTOM value");

#define tdi_to_pci_dev(tdi) (to_pci_dev(tdi->dev.parent))

/*
 * Status codes from TIO_MSG_SDTE_WRITE_RSP
 */
enum sdte_write_status {
	SDTE_WRITE_SUCCESS = 0,
	SDTE_WRITE_INVALID_TDI = 1,
	SDTE_WRITE_TDI_NOT_BOUND = 2,
	SDTE_WRITE_RESERVED = 3,
};

/*
 * Status codes from TIO_MSG_MMIO_VALIDATE_REQ
 */
enum mmio_validate_status {
	MMIO_VALIDATE_SUCCESS = 0,
	MMIO_VALIDATE_INVALID_TDI = 1,
	MMIO_VALIDATE_TDI_UNBOUND = 2,
	MMIO_VALIDATE_NOT_ASSIGNED = 3, /* At least one page is not assigned to the guest */
	MMIO_VALIDATE_NOT_UNIFORM = 4,  /* The Validated bit is not uniformly set for
					   the MMIO subrange */
	MMIO_VALIDATE_NOT_IMMUTABLE = 5,/* At least one page does not have immutable bit set
					   when validated bit is clear */
	MMIO_VALIDATE_NOT_MAPPED = 6,   /* At least one page is not mapped to the expected GPA */
	MMIO_VALIDATE_NOT_REPORTED = 7, /* The provided MMIO range ID is not reported in
					   the interface report */
	MMIO_VALIDATE_OUT_OF_RANGE = 8, /* The subrange is out the MMIO range in
					   the interface report */
};

/*
 * Status codes from TIO_MSG_MMIO_CONFIG_REQ
 */
enum mmio_config_status {
	MMIO_CONFIG_SUCCESS = 0,
	MMIO_CONFIG_INVALID_TDI = 1,
	MMIO_CONFIG_TDI_UNBOUND = 2,
	MMIO_CONFIG_NOT_REPORTED = 3, /* The provided MMIO range ID is not reported in
					   the interface report */
	MMIO_CONFIG_COULD_NOT_CHANGE = 4, /* One or more attributes could not be changed */
};

static int handle_tio_guest_request(struct snp_guest_dev *snp_dev, u8 type,
				   void *req_buf, size_t req_sz, void *resp_buf, u32 resp_sz,
				   void *pt, u64 *npages, u64 *bdfn, u64 *param, u64 *fw_err)
{
	struct snp_msg_desc *mdesc = snp_dev->msg_desc;
	struct snp_guest_req req = {
		.msg_version = TIO_MESSAGE_VERSION,
	};
	u64 exitinfo2 = 0;
	int ret;

	req.msg_type = type;
	req.vmpck_id = mdesc->vmpck_id;
	req.req_buf = req_buf;
	req.req_sz = req_sz;
	req.resp_buf = resp_buf;
	req.resp_sz = resp_sz;
	req.exit_code = SVM_VMGEXIT_SEV_TIO_GUEST_REQUEST;

	req.input.guest_rid = 0;
	req.input.param = 0;

	if (pt && npages) {
		req.data = pt;
		req.input.data_npages = *npages;
	}
	if (bdfn)
		req.input.guest_rid = *bdfn;
	if (param)
		req.input.param = *param;

	ret = snp_send_guest_request(mdesc, &req, &exitinfo2);

	if (param)
		*param = req.input.param;

	*fw_err = exitinfo2;

	return ret;
}

static int guest_request_tio_data(struct snp_guest_dev *snp_dev, u8 type,
				   void *req_buf, size_t req_sz, void *resp_buf, u32 resp_sz,
				   u64 bdfn, enum tsm_tdisp_state *state,
				   struct tsm_blob **certs, struct tsm_blob **meas,
				   struct tsm_blob **report, u64 *fw_err)
{
	u64 npages = SZ_32K >> PAGE_SHIFT, c1, param = 0;
	struct tio_blob_table_entry *pt;
	int rc;

	pt = snp_alloc_shared_pages(npages << PAGE_SHIFT);
	if (!pt)
		return -ENOMEM;

	c1 = npages;
	rc = handle_tio_guest_request(snp_dev, type, req_buf, req_sz, resp_buf, resp_sz,
				      pt, &c1, &bdfn, state ? &param : NULL, fw_err);

	if (c1 > SZ_32K) {
		snp_free_shared_pages(pt, npages);
		npages = c1;
		pt = snp_alloc_shared_pages(npages << PAGE_SHIFT);
		if (!pt)
			return -ENOMEM;

		rc = handle_tio_guest_request(snp_dev, type, req_buf, req_sz, resp_buf, resp_sz,
					      pt, &c1, &bdfn, state ? &param : NULL, fw_err);
	}
	if (rc)
		return rc;

	tsm_blob_free(*meas);
	tsm_blob_free(*certs);
	tsm_blob_free(*report);
	*meas = NULL;
	*certs = NULL;
	*report = NULL;

	for (unsigned int i = 0; i < 3; ++i) {
		u8 *ptr = ((u8 *) pt) + pt[i].offset;
		size_t len = pt[i].length;
		struct tsm_blob *b;

		if (guid_is_null(&pt[i].guid))
			break;

		if (!len)
			continue;

		b = tsm_blob_new(ptr, len);
		if (!b)
			break;

		if (guid_equal(&pt[i].guid, &TIO_GUID_MEASUREMENTS))
			*meas = b;
		else if (guid_equal(&pt[i].guid, &TIO_GUID_CERTIFICATES))
			*certs = b;
		else if (guid_equal(&pt[i].guid, &TIO_GUID_REPORT))
			*report = b;
	}
	snp_free_shared_pages(pt, npages);

	if (state)
		*state = param;

	return 0;
}

struct tio_msg_tdi_info_req {
	__u16 guest_device_id;
	__u8 reserved[14];
} __packed;

struct tio_msg_tdi_info_rsp {
	__u16 guest_device_id;
	__u16 status;
	__u8 reserved1[12];
	union {
		u32 meas_flags;
		struct {
			u32 meas_digest_valid : 1;
			u32 meas_digest_fresh : 1;
		};
	};
	union {
		u32 tdisp_lock_flags;
		/* These are TDISP's LOCK_INTERFACE_REQUEST flags */
		struct {
			u32 no_fw_update : 1;
			u32 cache_line_size : 1;
			u32 lock_msix : 1;
			u32 bind_p2p : 1;
			u32 all_request_redirect : 1;
		};
	};
	__u64 spdm_algos;
	__u8 certs_digest[48];
	__u8 meas_digest[48];
	__u8 interface_report_digest[48];
	__u64 tdi_report_count;
	__u64 reserved2;
} __packed;

static int tio_tdi_status(struct tsm_tdi *tdi, struct snp_guest_dev *snp_dev,
			  struct tsm_tdi_status *ts)
{
	struct snp_msg_desc *mdesc = snp_dev->msg_desc;
	size_t resp_len = sizeof(struct tio_msg_tdi_info_rsp) + mdesc->ctx->authsize;
	struct tio_msg_tdi_info_rsp *rsp = kzalloc(resp_len, GFP_KERNEL);
	struct tio_msg_tdi_info_req req = {
		.guest_device_id = pci_dev_id(tdi_to_pci_dev(tdi)),
	};
	u64 fw_err = 0;
	int rc;
	enum tsm_tdisp_state state = 0;

	dev_notice(&tdi->dev, "TDI info");
	if (!rsp)
		return -ENOMEM;

	rc = guest_request_tio_data(snp_dev, TIO_MSG_TDI_INFO_REQ, &req,
				     sizeof(req), rsp, resp_len,
				     pci_dev_id(tdi_to_pci_dev(tdi)), &state,
				     &tdi->tdev->certs, &tdi->tdev->meas,
				     &tdi->report, &fw_err);
	if (rc)
		goto free_exit;

	ts->meas_digest_valid = rsp->meas_digest_valid;
	ts->meas_digest_fresh = rsp->meas_digest_fresh;
	ts->no_fw_update = rsp->no_fw_update;
	ts->cache_line_size = rsp->cache_line_size == 0 ? 64 : 128;
	ts->lock_msix = rsp->lock_msix;
	ts->bind_p2p = rsp->bind_p2p;
	ts->all_request_redirect = rsp->all_request_redirect;
#define __ALGO(x, n, y) \
	((((x) & (0xFFUL << (n))) == TIO_SPDM_ALGOS_##y) ? \
	 (1ULL << TSM_SPDM_ALGOS_##y) : 0)
	ts->spdm_algos =
		__ALGO(rsp->spdm_algos, 0, DHE_SECP256R1) |
		__ALGO(rsp->spdm_algos, 0, DHE_SECP384R1) |
		__ALGO(rsp->spdm_algos, 8, AEAD_AES_128_GCM) |
		__ALGO(rsp->spdm_algos, 8, AEAD_AES_256_GCM) |
		__ALGO(rsp->spdm_algos, 16, ASYM_TPM_ALG_RSASSA_3072) |
		__ALGO(rsp->spdm_algos, 16, ASYM_TPM_ALG_ECDSA_ECC_NIST_P256) |
		__ALGO(rsp->spdm_algos, 16, ASYM_TPM_ALG_ECDSA_ECC_NIST_P384) |
		__ALGO(rsp->spdm_algos, 24, HASH_TPM_ALG_SHA_256) |
		__ALGO(rsp->spdm_algos, 24, HASH_TPM_ALG_SHA_384) |
		__ALGO(rsp->spdm_algos, 32, KEY_SCHED_SPDM_KEY_SCHEDULE);
#undef __ALGO
	memcpy(ts->certs_digest, rsp->certs_digest, sizeof(ts->certs_digest));
	memcpy(ts->meas_digest, rsp->meas_digest, sizeof(ts->meas_digest));
	memcpy(ts->interface_report_digest, rsp->interface_report_digest,
	       sizeof(ts->interface_report_digest));
	ts->intf_report_counter = rsp->tdi_report_count;

	ts->valid = true;
	ts->state = state;
	/* The response buffer contains the sensitive data, explicitly clear it. */
free_exit:
	memzero_explicit(&rsp, sizeof(resp_len));
	kfree(rsp);
	return rc;
}

struct tio_msg_mmio_validate_req {
	__u16 guest_device_id; /* Hypervisor provided identifier used by the guest
				  to identify the TDI in guest messages */
	__u16 reserved1;
	__u8 reserved2[12];
	__u64 subrange_base;
	__u32 subrange_page_count;
	__u32 range_offset;
	union {
		__u16 flags;
		struct {
			__u16 validated:1; /* Desired value to set RMP.Validated for the range */
			/* Force validated:
			 * 0: If subrange does not have RMP.Validated set uniformly, fail.
			 * 1: If subrange does not have RMP.Validated set uniformly, force
			 *    to requested value
			 */
			__u16 force_validated:1;
		};
	};
	__u16 range_id;
	__u8 reserved3[12];
} __packed;

struct tio_msg_mmio_validate_rsp {
	__u16 guest_interface_id;
	__u16 status; /* MMIO_VALIDATE_xxx */
	__u8 reserved1[12];
	__u64 subrange_base;
	__u32 subrange_page_count;
	__u32 range_offset;
	union {
		__u16 flags;
		struct {
			__u16 changed:1; /* Indicates that the Validated bit has changed
					    due to this operation */
		};
	};
	__u16 range_id;
	__u8 reserved2[12];
} __packed;

static int mmio_validate_range(struct snp_guest_dev *snp_dev, struct pci_dev *pdev,
			       unsigned int range_id, resource_size_t start, resource_size_t size,
			       bool invalidate, u64 *fw_err, u16 *status)
{
	struct snp_msg_desc *mdesc = snp_dev->msg_desc;
	size_t resp_len = sizeof(struct tio_msg_mmio_validate_rsp) + mdesc->ctx->authsize;
	struct tio_msg_mmio_validate_rsp *rsp = kzalloc(resp_len, GFP_KERNEL);
	struct tio_msg_mmio_validate_req req = { 0 };
	u64 bdfn = pci_dev_id(pdev);
	u64 mmio_val = MMIO_MK_VALIDATE(start, size, range_id, !invalidate);
	int rc;

	if (!rsp)
		return -ENOMEM;

	if (!invalidate)
		req = (struct tio_msg_mmio_validate_req) {
			.guest_device_id = pci_dev_id(pdev),
			.subrange_base = start,
			.subrange_page_count = size >> PAGE_SHIFT,
			.range_offset = 0,
			.validated = 1, /* Desired value to set RMP.Validated for the range */
			.force_validated = 0,
			.range_id = range_id,
		};

	rc = handle_tio_guest_request(snp_dev, TIO_MSG_MMIO_VALIDATE_REQ,
			       &req, sizeof(req), rsp, resp_len,
			       NULL, NULL, &bdfn, &mmio_val, fw_err);
	if (rc)
		goto free_exit;

	*status = rsp->status;

free_exit:
	/* The response buffer contains the sensitive data, explicitly clear it. */
	memzero_explicit(&rsp, sizeof(resp_len));
	kfree(rsp);
	return rc;
}

struct tio_msg_mmio_config_req {
	__u16 guest_device_id;
	__u16 reserved1;
	struct {
		__u32 reserved2:2;
		__u32 is_non_tee_mem:1;
		__u32 reserved3:13;
		__u32 range_id:16;
	};
	struct {
		__u32 write:1; /* 0: read; 1: Write configuration of range */
		__u32 reserved4:31;
	};
	__u8 reserved5[4];
} __packed;

struct tio_msg_mmio_config_rsp {
	__u16 guest_device_id;
	__u16 status; /* mmio_config_status */
	struct {
		__u32 msix_table:1;
		__u32 msix_pba:1;
		__u32 is_non_tee_mem:1;
		__u32 is_mem_attr_updateable:1;
		__u32 reserved1:12;
		__u32 range_id:16;
	};
	struct {
		__u32 write:1; /* 0: read; 1: Write configuration of range */
		__u32 reserved2:31;
	};
	__u8 reserved3[4];
} __packed;

static int mmio_config_get(struct snp_guest_dev *snp_dev, struct pci_dev *pdev,
			   unsigned int range_id, bool *updateable, bool *is_non_tee,
			   u64 *fw_err, u16 *status)
{
	struct snp_msg_desc *mdesc = snp_dev->msg_desc;
	size_t resp_len = sizeof(struct tio_msg_mmio_config_rsp) + mdesc->ctx->authsize;
	struct tio_msg_mmio_config_rsp *rsp = kzalloc(resp_len, GFP_KERNEL);
	struct tio_msg_mmio_config_req req = {
		.guest_device_id = pci_dev_id(pdev),
		.is_non_tee_mem = 0,
		.range_id = range_id,
		.write = 0,
	};
	u64 bdfn = pci_dev_id(pdev);
	int rc;

	if (!rsp)
		return -ENOMEM;

	rc = handle_tio_guest_request(snp_dev, TIO_MSG_MMIO_CONFIG_REQ,
			       &req, sizeof(req), rsp, resp_len,
			       NULL, NULL, &bdfn, NULL, fw_err);
	if (rc)
		goto free_exit;

	*status = rsp->status;
	*updateable = rsp->is_mem_attr_updateable;
	*is_non_tee = rsp->is_non_tee_mem;

free_exit:
	/* The response buffer contains the sensitive data, explicitly clear it. */
	memzero_explicit(&rsp, sizeof(resp_len));
	kfree(rsp);
	return rc;
}

static int mmio_config_range(struct snp_guest_dev *snp_dev, struct pci_dev *pdev,
			     unsigned int range_id, resource_size_t start, resource_size_t size,
			     bool tee, u64 *fw_err, u16 *status)
{
	struct snp_msg_desc *mdesc = snp_dev->msg_desc;
	size_t resp_len = sizeof(struct tio_msg_mmio_config_rsp) + mdesc->ctx->authsize;
	struct tio_msg_mmio_config_rsp *rsp = kzalloc(resp_len, GFP_KERNEL);
	struct tio_msg_mmio_config_req req = {
		.guest_device_id = pci_dev_id(pdev),
//		We kinda want these but the spec does not define them (yet?)
//		.subrange_base = start,
//		.subrange_page_count = size >> PAGE_SHIFT,
//		.range_offset = 0,
		.is_non_tee_mem = !tee,
		.range_id = range_id,
		.write = 1,
	};
	u64 bdfn = pci_dev_id(pdev);
	u64 mmio_val = MMIO_MK_VALIDATE(start, size, range_id, tee);
	int rc;

	if (!rsp)
		return -ENOMEM;

	if (tee)
		mmio_val |= MMIO_CONFIG_TEE;

	rc = handle_tio_guest_request(snp_dev, TIO_MSG_MMIO_CONFIG_REQ,
			       &req, sizeof(req), rsp, resp_len,
			       NULL, NULL, &bdfn, &mmio_val, fw_err);
	if (rc)
		goto free_exit;

	*status = rsp->status;

free_exit:
	/* The response buffer contains the sensitive data, explicitly clear it. */
	memzero_explicit(&rsp, sizeof(resp_len));
	kfree(rsp);
	return rc;
}

static int tio_tdi_mmio_validate(struct tsm_tdi *tdi, struct snp_guest_dev *snp_dev,
				 bool invalidate)
{
	struct pci_dev *pdev = tdi_to_pci_dev(tdi);
	struct tdi_report_mmio_range mr;
	struct resource *r;
	unsigned range_id;
	u16 mmio_status;
	u64 fw_err = 0;
	int i = 0, rc;

	pci_notice(pdev, "MMIO validate");

	if (WARN_ON_ONCE(!tdi->report || !tdi->report->data))
		return -EFAULT;

	for (i = 0; i < TDI_REPORT_MR_NUM(tdi->report); ++i) {
		mr = TDI_REPORT_MR(tdi->report, i);
		range_id = FIELD_GET(TSM_TDI_REPORT_MMIO_RANGE_ID, mr.range_attributes);
		r = pci_resource_n(pdev, range_id);

		if (r->end == r->start || ((r->end - r->start + 1) & ~PAGE_MASK) || !mr.num) {
			pci_warn(pdev, "Skipping broken range [%d] #%d %d pages, %llx..%llx\n",
				i, range_id, mr.num, r->start, r->end);
			continue;
		}

		if (FIELD_GET(TSM_TDI_REPORT_MMIO_IS_NON_TEE, mr.range_attributes)) {
			pci_info(pdev, "Skipping non-TEE range [%d] #%d %d pages, %llx..%llx\n",
				 i, range_id, mr.num, r->start, r->end);
			continue;
		}

		/* Currently not supported */
		if (FIELD_GET(TSM_TDI_REPORT_MMIO_MSIX_TABLE, mr.range_attributes) ||
		    FIELD_GET(TSM_TDI_REPORT_MMIO_PBA, mr.range_attributes)) {
			pci_info(pdev, "Skipping MSIX (%ld/%ld) range [%d] #%d %d pages, %llx..%llx\n",
				 FIELD_GET(TSM_TDI_REPORT_MMIO_MSIX_TABLE, mr.range_attributes),
				 FIELD_GET(TSM_TDI_REPORT_MMIO_PBA, mr.range_attributes),
				 i, range_id, mr.num, r->start, r->end);
			continue;
		}

		mmio_status = 0;
		rc = mmio_validate_range(snp_dev, pdev, range_id,
					 r->start, r->end - r->start + 1, invalidate, &fw_err,
					 &mmio_status);
		if (rc || fw_err != SEV_RET_SUCCESS || mmio_status != MMIO_VALIDATE_SUCCESS) {
			pci_err(pdev, "MMIO #%d %llx..%llx validation failed 0x%llx %d\n",
				range_id, r->start, r->end, fw_err, mmio_status);
			continue;
		}

		rc = encrypt_resource(pci_resource_n(pdev, range_id),
				      invalidate ? 0 : IORESOURCE_VALIDATED);
		if (rc) {
			pci_err(pdev, "MMIO #%d %llx..%llx failed to reserve\n",
				range_id, r->start, r->end);
			continue;
		}

		/* Try to make MMIO shared */
		if (invalidate) {
			bool updateable = false, is_non_tee = false;
			u16 status = 0;

			rc = mmio_config_get(snp_dev, pdev, range_id, &updateable, &is_non_tee,
					     &fw_err, &status);
			if (rc || fw_err) {
				pci_err(pdev, "MMIO #%d %llx..%llx failed to get config\n",
					range_id, r->start, r->end);
				continue;
			}

			pci_notice(pdev, "[%d] #%d: updateable=%d is_non_tee=%d\n",
				   i, range_id, updateable, is_non_tee);

			if (!updateable || is_non_tee)
				continue;

			rc = mmio_config_range(snp_dev, pdev, range_id, r->start, r->end - r->start + 1,
					       false, &fw_err, &status);
			if (rc) {
				pci_err(pdev, "MMIO #%d %llx..%llx failed to set config\n",
					range_id, r->start, r->end);
				continue;
			}

			pci_notice(pdev, "[%d] #%d: setting config rc=%d status=%d\n",
				   i, range_id, rc, status);
		}

		pci_notice(pdev, "MMIO #%d %llx..%llx %s\n",  range_id, r->start, r->end,
			   invalidate ? "invalidated" : "validated");
	}

	return rc;
}

struct sdte {
	__u64 v                  : 1;
	__u64 reserved           : 3;
	__u64 cxlio              : 3;
	__u64 reserved1          : 45;
	__u64 ppr                : 1;
	__u64 reserved2          : 1;
	__u64 giov               : 1;
	__u64 gv                 : 1;
	__u64 glx                : 2;
	__u64 gcr3_tbl_rp0       : 3;
	__u64 ir                 : 1;
	__u64 iw                 : 1;
	__u64 reserved3          : 1;
	__u16 domain_id;
	__u16 gcr3_tbl_rp1;
	__u32 interrupt          : 1;
	__u32 reserved4          : 5;
	__u32 ex                 : 1;
	__u32 sd                 : 1;
	__u32 reserved5          : 2;
	__u32 sats               : 1;
	__u32 gcr3_tbl_rp2       : 21;
	__u64 giv                : 1;
	__u64 gint_tbl_len       : 4;
	__u64 reserved6          : 1;
	__u64 gint_tbl           : 46;
	__u64 reserved7          : 2;
	__u64 gpm                : 2;
	__u64 reserved8          : 3;
	__u64 hpt_mode           : 1;
	__u64 reserved9          : 4;
	__u32 asid               : 12;
	__u32 reserved10         : 3;
	__u32 viommu_en          : 1;
	__u32 guest_device_id    : 16;
	__u32 guest_id           : 15;
	__u32 guest_id_mbo       : 1;
	__u32 reserved11         : 1;
	__u32 vmpl               : 2;
	__u32 reserved12         : 3;
	__u32 attrv              : 1;
	__u32 reserved13         : 1;
	__u32 sa                 : 8;
	__u8 ide_stream_id[8];
	__u32 vtom_en            : 1;
	__u32 vtom               : 31;
	__u32 rp_id              : 5;
	__u32 reserved14         : 27;
	__u8  reserved15[0x40-0x30];
} __packed;

struct tio_msg_sdte_write_req {
	__u16 guest_device_id;
	__u8 reserved[14];
	struct sdte sdte;
} __packed;

struct tio_msg_sdte_write_rsp {
	__u16 guest_device_id;
	__u16 status; /* SDTE_WRITE_xxx */
	__u8 reserved[12];
} __packed;

static int tio_tdi_sdte_write(struct tsm_tdi *tdi, struct snp_guest_dev *snp_dev, bool invalidate)
{
	struct snp_msg_desc *mdesc = snp_dev->msg_desc;
	size_t resp_len = sizeof(struct tio_msg_sdte_write_rsp) + mdesc->ctx->authsize;
	struct tio_msg_sdte_write_rsp *rsp = kzalloc(resp_len, GFP_KERNEL);
	struct tio_msg_sdte_write_req req;
	u64 fw_err = 0;
	u64 bdfn = pci_dev_id(tdi_to_pci_dev(tdi));
	int rc;

	BUILD_BUG_ON(sizeof(struct sdte) * 8 != 512);

	if (!invalidate)
		req = (struct tio_msg_sdte_write_req) {
			.guest_device_id = pci_dev_id(tdi_to_pci_dev(tdi)),
			.sdte.vmpl = 0,
			.sdte.vtom = tsm_vtom,
			.sdte.vtom_en = 1,
			.sdte.iw = 1,
			.sdte.ir = 1,
			.sdte.v = 1,
		};
	else
		req = (struct tio_msg_sdte_write_req) {
			.guest_device_id = pci_dev_id(tdi_to_pci_dev(tdi)),
		};

	dev_notice(&tdi->dev, "SDTE write vTOM=%lx", (unsigned long) req.sdte.vtom << 21);

	if (!rsp)
		return -ENOMEM;

	rc = handle_tio_guest_request(snp_dev, TIO_MSG_SDTE_WRITE_REQ,
			       &req, sizeof(req), rsp, resp_len,
			       NULL, NULL, &bdfn, NULL, &fw_err);
	if (rc) {
		dev_err(&tdi->dev, "SDTE write failed with 0x%llx\n", fw_err);
		goto free_exit;
	}

free_exit:
	/* The response buffer contains the sensitive data, explicitly clear it. */
	memzero_explicit(&rsp, sizeof(resp_len));
	kfree(rsp);
	return rc;
}

static int sev_guest_tdi_status(struct tsm_tdi *tdi, void *private_data, struct tsm_tdi_status *ts)
{
	struct snp_guest_dev *snp_dev = private_data;

	return tio_tdi_status(tdi, snp_dev, ts);
}

static int sev_guest_tdi_validate(struct tsm_tdi *tdi, unsigned featuremask, bool invalidate, void *private_data)
{
	struct snp_guest_dev *snp_dev = private_data;
	struct tsm_tdi_status ts = { 0 };
	int ret;

	if (!tdi->report) {
		ret = tio_tdi_status(tdi, snp_dev, &ts);

		if (ret || !tdi->report) {
			dev_err(&tdi->dev, "No report available, ret=%d", ret);
			if (!ret && tdi->report)
				ret = -EIO;
			return ret;
		}

		if (ts.state != TDISP_STATE_RUN) {
			dev_err(&tdi->dev, "Not in RUN state, state=%d instead", ts.state);
			return -EIO;
		}
	}

	ret = tio_tdi_sdte_write(tdi, snp_dev, invalidate);
	if (ret)
		return ret;

	/* MMIO validation result is stored as IORESOURCE_VALIDATED */
	tio_tdi_mmio_validate(tdi, snp_dev, invalidate);

	return 0;
}

struct tsm_vm_ops sev_guest_tsm_ops = {
	.tdi_validate = sev_guest_tdi_validate,
	.tdi_status = sev_guest_tdi_status,
};

void sev_guest_tsm_set_ops(bool set, struct snp_guest_dev *snp_dev)
{
#if defined(CONFIG_PCI_TSM) || defined(CONFIG_PCI_TSM_MODULE)
	if (set) {
		snp_dev->tsm = tsm_guest_register(snp_dev->dev, &sev_guest_tsm_ops, snp_dev);
		snp_dev->tsm_bus = pci_tsm_register((struct tsm_subsys *) snp_dev->tsm);
	} else {
		if (snp_dev->tsm_bus)
			pci_tsm_unregister(snp_dev->tsm_bus);
		if (snp_dev->tsm)
			tsm_unregister((struct tsm_subsys *) snp_dev->tsm);
		snp_dev->tsm_bus = NULL;
		snp_dev->tsm = NULL;
	}
#endif
}
