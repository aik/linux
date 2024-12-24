// SPDX-License-Identifier: GPL-2.0-only

// Interface to CCP/SEV-TIO for generic PCIe TDISP module

#include <linux/pci.h>
#include <linux/device.h>
#include <linux/tsm.h>

#include <asm/sev-common.h>
#include <asm/sev.h>

#include "psp-dev.h"
#include "sev-dev.h"
#include "sev-dev-tio.h"

#define tdi_to_pci_dev(tdi) (to_pci_dev(tdi->dev.parent))

static void pr_ide_state(struct pci_dev *pdev, struct pci_ide *ide)
{
	struct pci_dev *rp = pcie_find_root_port(pdev);
	u32 devst = 0xffffffff, rcst = 0xffffffff;
	int ret = pci_ide_stream_state(pdev, ide, &devst, &rcst);

	pci_notice(pdev, "%x%s <-> %s: %x%s ret=%d",
		   devst,
		   PCI_IDE_SEL_STS_STATUS(devst) == 2 ? "=SECURE" : "",
		   pci_name(rp),
		   rcst,
		   PCI_IDE_SEL_STS_STATUS(rcst) == 2 ? "=SECURE" : "",
		   ret);
}

static int mkret(int ret, struct tsm_dev_tio *dev_data)
{
	if (ret)
		return ret;

	if (dev_data->psp_ret == SEV_RET_SUCCESS)
		return 0;

	pr_err("PSP returned an error %d\n", dev_data->psp_ret);
	return -EINVAL;
}

static int ide_refresh(struct tsm_dev *tdev)
{
	struct tsm_dev_tio *dev_data = tdev->data;
	int ret;

	if (dev_data->cmd == 0) {
		ret = sev_tio_ide_refresh(dev_data, &tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret)
			return ret;
	}

	if (dev_data->cmd == SEV_CMD_TIO_ROLL_KEY) {
		ret = sev_tio_continue(dev_data, &tdev->spdm);
		ret = mkret(ret, dev_data);
	}

	return ret;
}

static int dev_create(struct tsm_dev *tdev, void *private_data)
{
	struct pci_dev *pdev = to_pci_dev(tdev->physdev);
	u8 segment_id = pdev->bus ? pci_domain_nr(pdev->bus) : 0;
	struct pci_dev *rootport = pdev->bus->self;
	struct sev_device *sev = private_data;
	u16 device_id = pci_dev_id(pdev);
	struct tsm_dev_tio *dev_data;
	struct page *req_page;
	u16 root_port_id;
	u32 lnkcap = 0;
	int ret;

	if (pci_read_config_dword(rootport, pci_pcie_cap(rootport) + PCI_EXP_LNKCAP,
				  &lnkcap))
		return -ENODEV;

	root_port_id = FIELD_GET(PCI_EXP_LNKCAP_PN, lnkcap);

	dev_data = kzalloc(sizeof(*dev_data), GFP_KERNEL);
	if (!dev_data)
		return -ENOMEM;

	dev_data->tio_status = sev->tio_status;

	req_page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!req_page) {
		ret = -ENOMEM;
		goto free_dev_data_exit;
	}
	dev_data->guest_req_buf = page_address(req_page);

	dev_data->guest_resp_buf = snp_alloc_firmware_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!dev_data->guest_resp_buf) {
		ret = -EIO;
		goto free_req_exit;
	}

	ret = sev_tio_dev_create(dev_data, device_id, root_port_id, segment_id);
	if (ret)
		goto free_resp_exit;

	tdev->data = dev_data;

	return 0;

free_resp_exit:
	snp_free_firmware_page(dev_data->guest_resp_buf);
free_req_exit:
	__free_page(req_page);
free_dev_data_exit:
	kfree(dev_data);
	return ret;
}

static int dev_connect(struct tsm_dev *tdev, void *private_data)
{
	struct pci_dev *pdev = to_pci_dev(tdev->physdev);
	struct tsm_dev_tio *dev_data = tdev->data;
	u8 tc_mask = 1, ids[8] = { 0 };
	int ret;

	if (tdev->connected)
		return ide_refresh(tdev);

	if (!dev_data) {
		struct pci_ide ide1 = { 0 };
		struct pci_ide *ide = &ide1;

		pci_ide_stream_probe(pdev, ide);
		ide->stream_id = ids[0];
		ide->nr_mem = 1;
		ide->mem[0] = (struct range) { 0, 0xFFFFFFFFFFF00000ULL };
		ide->dev_sel_ctl = FIELD_PREP(PCI_IDE_SEL_CTL_TEE_LIMITED, 1);
		ide->rootport_sel_ctl = FIELD_PREP(PCI_IDE_SEL_CTL_CFG_EN, 1);
		ide->devid_start = 0;
		ide->devid_end = 0xffff;
		ide->rpid_start = 0;
		ide->rpid_end = 0xffff;

		ret = pci_ide_stream_setup(pdev, ide, PCI_IDE_SETUP_ROOT_PORT);
		if (ret)
			return ret;

		pci_ide_enable_stream(pdev, ide);
		pr_ide_state(pdev, ide);

		ret = dev_create(tdev, private_data);
		if (ret)
			return ret;

		dev_data = tdev->data;
		dev_data->ide = *ide;
	}

	if (dev_data->cmd == 0) {
		ret = sev_tio_dev_connect(dev_data, tc_mask, ids, tdev->cert_slot, &tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret > 0)
			return ret;
		if (ret < 0)
			goto free_exit;

		tio_save_output(&tdev->certs, dev_data->output, SPDM_DOBJ_ID_CERTIFICATE);
	}

	if (dev_data->cmd == SEV_CMD_TIO_DEV_CONNECT) {
		ret = sev_tio_continue(dev_data, &tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret > 0)
			return ret;
		if (ret < 0)
			goto free_exit;

		tio_save_output(&tdev->certs, dev_data->output, SPDM_DOBJ_ID_CERTIFICATE);
	}

	if (dev_data->cmd == 0) {
		ret = sev_tio_dev_measurements(dev_data, tdev->nonce, tdev->nonce_len, &tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret > 0)
			return ret;
		if (ret < 0) {
			pci_warn(pdev, "Reading measurements failed ret=%d\n", ret);
			ret = 0;
		}
		else {
			tio_save_output(&tdev->meas, dev_data->output, SPDM_DOBJ_ID_MEASUREMENT);
		}
	}

	if (dev_data->cmd == SEV_CMD_TIO_DEV_MEASUREMENTS) {
		ret = sev_tio_continue(dev_data, &tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret > 0)
			return ret;
		if (ret < 0) {
			pci_warn(pdev, "Reading measurements failed ret=%d\n", ret);
			ret = 0;
		}
		else {
			tio_save_output(&tdev->meas, dev_data->output, SPDM_DOBJ_ID_MEASUREMENT);
		}
	}
#if 0
	/* Uncomment to verify SEV_CMD_TIO_DEV_CERTIFICATES work */
	if (dev_data->cmd == 0) {
		ret = sev_tio_dev_certificates(dev_data, &tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret > 0)
			return ret;
		if (ret < 0)
			goto free_exit;

		tio_save_output(&tdev->certs, dev_data->output, SPDM_DOBJ_ID_CERTIFICATE);
	}

	if (dev_data->cmd == SEV_CMD_TIO_DEV_CERTIFICATES) {
		ret = sev_tio_continue(dev_data, &tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret > 0)
			return ret;
		if (ret < 0)
			goto free_exit;

		tio_save_output(&tdev->certs, dev_data->output, SPDM_DOBJ_ID_CERTIFICATE);
	}
#endif
	ret = tsm_register_ide_stream(tdev, &dev_data->ide);
	if (ret)
		goto free_exit;

	try_module_get(THIS_MODULE);
	pr_ide_state(pdev, &dev_data->ide);
	return 0;

free_exit:
	sev_tio_dev_reclaim(dev_data, &tdev->spdm);
	kfree(dev_data);
	tdev->data = NULL;
	if (ret > 0)
		ret = -EFAULT;

	return ret;
}

static int dev_disconnect(struct tsm_dev *tdev)
{
	struct tsm_dev_tio *dev_data = tdev->data;
	int ret;

	if (!dev_data)
		return -ENODEV;

	if (dev_data->cmd == 0) {
		ret = sev_tio_dev_disconnect(dev_data, &tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret)
			return ret;
	} else if (dev_data->cmd == SEV_CMD_TIO_DEV_DISCONNECT) {
		ret = sev_tio_continue(dev_data, &tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret)
			return ret;
	} else {
		dev_err(&tdev->dev, "Wrong state, cmd 0x%x in flight\n",
			dev_data->cmd);
	}

	ret = sev_tio_dev_reclaim(dev_data, &tdev->spdm);
	ret = mkret(ret, dev_data);

	tsm_blob_free(tdev->meas);
	tdev->meas = NULL;
	tsm_blob_free(tdev->certs);
	tdev->certs = NULL;
	kfree(tdev->data);
	tdev->data = NULL;

	if (dev_data->guest_resp_buf)
		snp_free_firmware_page(dev_data->guest_resp_buf);

	if (dev_data->guest_req_buf)
		__free_page(virt_to_page(dev_data->guest_req_buf));

	dev_data->guest_req_buf = NULL;
	dev_data->guest_resp_buf = NULL;

	struct pci_dev *pdev = to_pci_dev(tdev->physdev);
	struct pci_ide *ide = &dev_data->ide;

	pr_ide_state(pdev, &dev_data->ide);
	pci_ide_disable_stream(pdev, ide);
	tsm_unregister_ide_stream(tdev, ide);
	pci_ide_stream_teardown(pdev, ide);
	pr_ide_state(pdev, &dev_data->ide);

	module_put(THIS_MODULE);

	return ret;
}

static int dev_status(struct tsm_dev *tdev, struct tsm_dev_status *s)
{
	struct tsm_dev_tio *dev_data = tdev->data;
	int ret;

	if (!dev_data)
		return -ENODEV;

	ret = sev_tio_dev_status(dev_data, s);
	ret = mkret(ret, dev_data);
	if (!ret)
		WARN_ON(s->device_id != pci_dev_id(to_pci_dev(tdev->physdev)));

	return ret;
}

static int dev_measurements(struct tsm_dev *tdev)
{
	struct tsm_dev_tio *dev_data = tdev->data;
	int ret;

	if (!dev_data)
		return -ENODEV;

	if (dev_data->cmd == 0) {
		ret = sev_tio_dev_measurements(dev_data, tdev->nonce, tdev->nonce_len, &tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret > 0)
			return ret;
		if (ret < 0)
			return ret;

		tio_save_output(&tdev->meas, dev_data->output, SPDM_DOBJ_ID_MEASUREMENT);
	}

	if (dev_data->cmd == SEV_CMD_TIO_DEV_MEASUREMENTS) {
		ret = sev_tio_continue(dev_data, &tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret > 0)
			return ret;
		if (ret < 0)
			return ret;

		tio_save_output(&tdev->meas, dev_data->output, SPDM_DOBJ_ID_MEASUREMENT);
	}

	return 0;
}

static void tdi_share_mmio(struct pci_dev *pdev);

static int tdi_unbind(struct tsm_tdi *tdi)
{
	struct tsm_dev_tio *dev_data;
	int ret;

	if (!tdi->data)
		return -ENODEV;

	dev_data = tdi->tdev->data;
	if (tdi->kvm) {
		if (dev_data->cmd == 0) {
			ret = sev_tio_tdi_unbind(tdi->tdev->data, tdi->data, &tdi->tdev->spdm);
			ret = mkret(ret, dev_data);
			if (ret)
				return ret;
		} else if (dev_data->cmd == SEV_CMD_TIO_TDI_UNBIND) {
			ret = sev_tio_continue(dev_data, &tdi->tdev->spdm);
			ret = mkret(ret, dev_data);
			if (ret)
				return ret;
		}
	}

	/* The hunk to verify transitioning to CONFIG_UNLOCKED */
	if (dev_data->cmd == 0) {
		ret = sev_tio_tdi_status(tdi->tdev->data, tdi->data, &tdi->tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret > 0)
			return ret;

	} else if (dev_data->cmd == SEV_CMD_TIO_TDI_STATUS) {
		enum tsm_tdisp_state state = TDISP_STATE_CONFIG_UNLOCKED;
		const char *sstate[] = {"CONFIG_UNLOCKED", "CONFIG_LOCKED", "RUN", "ERROR"};

		ret = sev_tio_continue(dev_data, &tdi->tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret > 0)
			return ret;

		if (ret) {
			dev_err(&tdi->dev, "TDI status failed to read, ret=%d\n", ret);
		} else {
			ret = sev_tio_tdi_status_fin(tdi->tdev->data, tdi->data, &state);
			dev_notice(&tdi->dev, "TDI status %d=\"%s\"\n",
				   state, state < ARRAY_SIZE(sstate) ? sstate[state] : sstate[0]);
		}
	}

	/* Reclaim TDI if DEV is connected */
	if (tdi->tdev->data) {
		struct tsm_tdi_tio *tdi_data = tdi->data;
		struct tsm_dev *tdev = tdi->tdev;
		struct pci_dev *pdev = to_pci_dev(tdev->physdev);
		struct pci_dev *rootport = pdev->bus->self;
		u8 segment_id = pci_domain_nr(rootport->bus);
		u16 device_id = pci_dev_id(rootport);
		bool fenced = false;

		sev_tio_tdi_reclaim(tdi->tdev->data, tdi->data);

		if (!sev_tio_asid_fence_status(dev_data, device_id, segment_id,
					       tdi_data->asid, &fenced)) {
			if (fenced) {
				ret = sev_tio_asid_fence_clear(device_id, segment_id,
							       tdi_data->gctx_paddr, &dev_data->psp_ret);
				pci_notice(rootport, "Unfenced VM=%llx ASID=%d ret=%d %d",
					   tdi_data->gctx_paddr, tdi_data->asid, ret,
					   dev_data->psp_ret);
			}
		}

		tsm_blob_free(tdi->report);
		tdi->report = NULL;
	}

	pr_ide_state(to_pci_dev(tdi->tdev->physdev), &dev_data->ide);
	kfree(tdi->data);
	tdi->data = NULL;

	tdi_share_mmio(tdi_to_pci_dev(tdi));

	return 0;
}

static int tdi_create(struct tsm_tdi *tdi)
{
	struct tsm_tdi_tio *tdi_data = tdi->data;
	int ret;

	if (tdi_data)
		return -EBUSY;

	tdi_data = kzalloc(sizeof(*tdi_data), GFP_KERNEL);
	if (!tdi_data)
		return -ENOMEM;

	ret = sev_tio_tdi_create(tdi->tdev->data, tdi_data, pci_dev_id(tdi_to_pci_dev(tdi)),
				 tdi->rseg, tdi->rseg_valid);
	if (ret)
		kfree(tdi_data);
	else
		tdi->data = tdi_data;

	return ret;
}

static int tdi_bind(struct tsm_tdi *tdi, u32 bdfn, u64 vmid)
{
	enum tsm_tdisp_state state = TDISP_STATE_CONFIG_UNLOCKED;
	struct tsm_dev_tio *dev_data = tdi->tdev->data;
	u64 gctx = __psp_pa(vmid & PAGE_MASK); /* see SVM's sev_tio_vmid() */
	u32 asid = vmid & ~PAGE_MASK;
	int ret = 0;

	if (dev_data->cmd == SEV_CMD_TIO_TDI_UNBIND) {
		ret = sev_tio_continue(dev_data, &tdi->tdev->spdm);
		return mkret(ret, dev_data);
	}

	if (!tdi->data) {
		ret = tdi_create(tdi);
		if (ret)
			return ret;
	}

	if (dev_data->cmd == 0) {
		ret = sev_tio_tdi_bind(dev_data, tdi->data, bdfn, gctx, asid,
				       false, &tdi->tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret < 0) {
			ret = sev_tio_tdi_bind(dev_data, tdi->data, bdfn, gctx, asid,
					       true, &tdi->tdev->spdm);
			ret = mkret(ret, dev_data);
		}
		if (ret < 0)
			goto error_exit;
		if (ret)
			return ret;

		tio_save_output(&tdi->report, dev_data->output, SPDM_DOBJ_ID_REPORT);
	}

	if (dev_data->cmd == SEV_CMD_TIO_TDI_BIND) {
		ret = sev_tio_continue(dev_data, &tdi->tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret < 0)
			goto error_exit;
		if (ret)
			return ret;

		tio_save_output(&tdi->report, dev_data->output, SPDM_DOBJ_ID_REPORT);
	}

	if (dev_data->cmd == 0) {
		ret = sev_tio_tdi_status(tdi->tdev->data, tdi->data, &tdi->tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret)
			return ret;

		ret = sev_tio_tdi_status_fin(tdi->tdev->data, tdi->data, &state);
	} else if (dev_data->cmd == SEV_CMD_TIO_TDI_STATUS) {
		ret = sev_tio_continue(dev_data, &tdi->tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret)
			return ret;

		ret = sev_tio_tdi_status_fin(tdi->tdev->data, tdi->data, &state);
	}

	if (ret < 0)
		goto error_exit;
	if (ret)
		return ret;

	if (dev_data->cmd == 0 && state == TDISP_STATE_CONFIG_LOCKED) {
		ret = sev_tio_tdi_bind(dev_data, tdi->data, bdfn, gctx, asid,
				       true, &tdi->tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret < 0)
			goto error_exit;
		if (ret)
			return ret;

		tio_save_output(&tdi->report, dev_data->output, SPDM_DOBJ_ID_REPORT);
	}

	pr_ide_state(to_pci_dev(tdi->tdev->physdev), &dev_data->ide);

	return ret;

error_exit:
	return sev_tio_tdi_unbind(tdi->tdev->data, tdi->data, &tdi->tdev->spdm);
}

static int guest_request(struct tsm_tdi *tdi, u8 __user *req, size_t reqlen,
			 u8 __user *rsp, size_t rsplen, int *fw_err)
{
	struct tsm_dev_tio *dev_data = tdi->tdev->data;
	int ret;

	if (!tdi->data)
		return -EFAULT;

	if (dev_data->cmd == 0) {
		ret = copy_from_user(dev_data->guest_req_buf, req, reqlen);
		if (ret)
			return ret;

		ret = sev_tio_guest_request(dev_data, tdi->data, dev_data->guest_req_buf,
					    dev_data->guest_resp_buf, &tdi->tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret > 0)
			return ret;
		*fw_err = dev_data->psp_ret;
		ret = copy_to_user(rsp, dev_data->guest_resp_buf, rsplen);

	} else if (dev_data->cmd == SEV_CMD_TIO_GUEST_REQUEST) {
		ret = sev_tio_continue(dev_data, &tdi->tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret > 0)
			return ret;
		*fw_err = dev_data->psp_ret;
		ret = copy_to_user(rsp, dev_data->guest_resp_buf, rsplen);
	}

	return ret;
}

static int tdi_status(struct tsm_tdi *tdi, struct tsm_tdi_status *ts)
{
	struct tsm_dev_tio *dev_data = tdi->tdev->data;
	int ret;

	if (!tdi->data)
		return -ENODEV;

	if (dev_data->cmd == 0) {
		ret = sev_tio_tdi_info(tdi->tdev->data, tdi->data, ts);
		ret = mkret(ret, dev_data);
		if (ret)
			return ret;
	}

	if (dev_data->cmd == 0) {
		ret = sev_tio_tdi_status(tdi->tdev->data, tdi->data, &tdi->tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret)
			return ret;

		ret = sev_tio_tdi_status_fin(tdi->tdev->data, tdi->data, &ts->state);
	} else if (dev_data->cmd == SEV_CMD_TIO_TDI_STATUS) {
		ret = sev_tio_continue(dev_data, &tdi->tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret)
			return ret;

		ret = sev_tio_tdi_status_fin(tdi->tdev->data, tdi->data, &ts->state);
	} else {
		dev_err(tdi->dev.parent, "Wrong state, cmd 0x%x in flight\n",
			dev_data->cmd);
	}

	return ret;
}

struct tsm_hv_ops sev_tsm_ops = {
	.dev_connect = dev_connect,
	.dev_disconnect = dev_disconnect,
	.dev_status = dev_status,
	.dev_measurements = dev_measurements,
	.tdi_bind = tdi_bind,
	.tdi_unbind = tdi_unbind,
	.guest_request = guest_request,
	.tdi_status = tdi_status,
};

void sev_tsm_init(struct sev_device *sev)
{
	int ret;

	if (!sev->tio_en)
		return;

	ret = sev_tio_status(sev);
	if (ret) {
		pr_warn("SEV-TIO STATUS failed with %d\n", ret);
		return;
	}

	sev->tsm = tsm_host_register(sev->dev, &sev_tsm_ops, sev);
	sev->tsm_bus = pci_tsm_register((struct tsm_subsys *) sev->tsm);
}

void sev_tsm_uninit(struct sev_device *sev)
{
	if (!sev->tio_en)
		return;
	if (sev->tsm_bus)
		pci_tsm_unregister(sev->tsm_bus);
	if (sev->tsm)
		tsm_unregister((struct tsm_subsys *) sev->tsm);
	sev->tsm_bus = NULL;
	sev->tsm = NULL;
	sev_tio_cleanup(sev);
	sev->tio_en = false;
}


static int rmpupdate(u64 pfn, struct rmp_state *state)
{
	unsigned long paddr = pfn << PAGE_SHIFT;
	int ret, level;

	if (!cc_platform_has(CC_ATTR_HOST_SEV_SNP))
		return -ENODEV;

	level = RMP_TO_PG_LEVEL(state->pagesize);

	do {
		/* Binutils version 2.36 supports the RMPUPDATE mnemonic. */
		asm volatile(".byte 0xF2, 0x0F, 0x01, 0xFE"
			     : "=a" (ret)
			     : "a" (paddr), "c" ((unsigned long)state)
			     : "memory", "cc");
	} while (ret == RMPUPDATE_FAIL_OVERLAP);

	if (ret) {
		pr_err("MMIO RMPUPDATE failed for PFN %llx, pg_level: %d, ret: %d\n",
		       pfn, level, ret);
		return -EFAULT;
	}

	return 0;
}

static void tdi_share_mmio(struct pci_dev *pdev)
{
	struct resource *res;

	pci_dev_for_each_resource(pdev, res) {
		if (!res)
			continue;

		pr_err("___K___ %s %u: Sharing %s %llx..%llx\n", __func__, __LINE__,
			res->name ? res->name : "(null)", res->start, res->end);
		for (resource_size_t off = res->start; off < res->end; off += PAGE_SIZE) {
			struct rmp_state state = {};

			state.pagesize = PG_LEVEL_TO_RMP(PG_LEVEL_4K);
			rmpupdate(off >> PAGE_SHIFT, &state);
		}
	}
}
