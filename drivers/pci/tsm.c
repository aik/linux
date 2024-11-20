// SPDX-License-Identifier: GPL-2.0
/*
 * TEE Security Manager for the TEE Device Interface Security Protocol
 * (TDISP, PCIe r6.1 sec 11)
 *
 * Copyright(c) 2024 Intel Corporation. All rights reserved.
 */

#define dev_fmt(fmt) "TSM: " fmt

#include <linux/pci.h>
#include <linux/pci-doe.h>
#include <linux/sysfs.h>
#include <linux/xarray.h>
#include <linux/module.h>
#include <linux/pci-ide.h>
#include <linux/tsm.h>

#define DRIVER_VERSION	"0.1"
#define DRIVER_AUTHOR	"aik@amd.com"
#define DRIVER_DESC	"TSM TDISP library"

static bool is_physical_endpoint(struct pci_dev *pdev)
{
	if (!pci_is_pcie(pdev))
		return false;

	if (pdev->is_virtfn)
		return false;

	if (pci_pcie_type(pdev) != PCI_EXP_TYPE_ENDPOINT)
		return false;

	return true;
}

static bool is_endpoint(struct pci_dev *pdev)
{
	if (!pci_is_pcie(pdev))
		return false;

	if (pci_pcie_type(pdev) != PCI_EXP_TYPE_ENDPOINT)
		return false;

	return true;
}

struct tsm_pci_dev_data
{
	struct pci_doe_mb *doe_mb;
	struct pci_doe_mb *doe_mb_sec;
};

#define tsm_dev_to_pcidata(tdev) ((struct tsm_pci_dev_data *)tsm_dev_to_bdata(tdev))

static int tsm_pci_dev_spdm_forward(struct tsm_spdm *spdm, u8 type)
{
	struct tsm_dev *tdev = container_of(spdm, struct tsm_dev, spdm);
	struct tsm_pci_dev_data *tdata = tsm_dev_to_pcidata(tdev);
	struct pci_doe_mb *doe_mb;
	int rc;

	if (type == TSM_PROTO_SECURED_CMA_SPDM)
		doe_mb = tdata->doe_mb_sec;
	else if (type == TSM_PROTO_CMA_SPDM)
		doe_mb = tdata->doe_mb;
	else
		return -EINVAL;

	if (!doe_mb)
		return -EFAULT;

	rc = pci_doe(doe_mb, PCI_VENDOR_ID_PCI_SIG, type,
		     spdm->req, spdm->req_len, spdm->rsp, spdm->rsp_len);
	if (rc >= 0)
		spdm->rsp_len = rc;

	return rc;
}

static struct tsm_bus_ops tsm_pci_ops = {
	.spdm_forward = tsm_pci_dev_spdm_forward,
};

static int tsm_pci_dev_init(struct tsm_bus_subsys *tsm_bus, struct pci_dev *pdev, struct tsm_dev **ptdev)
{
	struct tsm_pci_dev_data *tdata;
	int ret = tsm_dev_init(tsm_bus, &pdev->dev, sizeof(*tdata), ptdev);

	if (ret)
		return ret;

	tdata = tsm_dev_to_bdata(*ptdev);

	tdata->doe_mb = pci_find_doe_mailbox(pdev,
					     PCI_VENDOR_ID_PCI_SIG,
					     PCI_DOE_PROTOCOL_CMA_SPDM);
	tdata->doe_mb_sec = pci_find_doe_mailbox(pdev,
						 PCI_VENDOR_ID_PCI_SIG,
						 PCI_DOE_PROTOCOL_SECURED_CMA_SPDM);

	if (tdata->doe_mb || tdata->doe_mb_sec)
		pci_notice(pdev, "DOE SPDM=%s SecuredSPDM=%s\n",
			   tdata->doe_mb ? "yes":"no", tdata->doe_mb_sec ? "yes":"no");

	return ret;
}

static int tsm_pci_alloc_device(struct tsm_bus_subsys *tsm_bus,
				struct pci_dev *pdev)
{
	int ret = 0;

	/* Set up TDIs for HV (physical functions) and VM (all functions) */
	if ((pdev->devcap & PCI_EXP_DEVCAP_TEE) &&
	    (((pdev->is_physfn && (PCI_FUNC(pdev->devfn) == 0)) ||
	      (!pdev->is_physfn && !pdev->is_virtfn)))) {

		struct tsm_dev *tdev = NULL;

		if (!is_physical_endpoint(pdev))
			return 0;

		ret = tsm_pci_dev_init(tsm_bus, pdev, &tdev);
		if (ret)
			return ret;

		ret = tsm_tdi_init(tdev, &pdev->dev);
		tsm_dev_put(tdev);
		return ret;
	}

	/* Set up TDIs for HV (virtual functions), should do nothing in VMs */
	if (pdev->is_virtfn) {
		struct pci_dev *pf0 = pci_get_slot(pdev->physfn->bus,
						   pdev->physfn->devfn & ~7);

		if (pf0 && (pf0->devcap & PCI_EXP_DEVCAP_TEE)) {
			struct tsm_dev *tdev = tsm_dev_get(&pf0->dev);

			if (!is_endpoint(pdev))
				return 0;

			ret = tsm_tdi_init(tdev, &pdev->dev);
			tsm_dev_put(tdev);
			return ret;
		}
	}

	return 0;
}

static void tsm_pci_dev_free(struct pci_dev *pdev)
{
	struct tsm_tdi *tdi = tsm_tdi_get(&pdev->dev);

	if (tdi) {
		tsm_tdi_put(tdi);
		tsm_tdi_free(tdi);
	}

	struct tsm_dev *tdev = tsm_dev_get(&pdev->dev);

	if (tdev) {
		tsm_dev_put(tdev);
		tsm_dev_free(tdev);
	}

	WARN_ON(!tdi && tdev);
}

static int tsm_pci_bus_notifier(struct notifier_block *nb, unsigned long action, void *data)
{
	struct tsm_bus_subsys *tsm_bus = container_of(nb, struct tsm_bus_subsys, notifier);

	switch (action) {
	case BUS_NOTIFY_ADD_DEVICE:
		tsm_pci_alloc_device(tsm_bus, to_pci_dev(data));
		break;
	case BUS_NOTIFY_DEL_DEVICE:
		tsm_pci_dev_free(to_pci_dev(data));
		break;
	}

	return NOTIFY_OK;
}

struct tsm_bus_subsys *pci_tsm_register(struct tsm_subsys *tsm)
{
	struct tsm_bus_subsys *tsm_bus = kzalloc(sizeof(*tsm_bus), GFP_KERNEL);
	struct pci_dev *pdev = NULL;

	pr_info("Scan TSM PCI\n");
	tsm_bus->ops = &tsm_pci_ops;
	tsm_bus->tsm = tsm;
	tsm_bus->notifier.notifier_call = tsm_pci_bus_notifier;
	for_each_pci_dev(pdev)
		tsm_pci_alloc_device(tsm_bus, pdev);
	bus_register_notifier(&pci_bus_type, &tsm_bus->notifier);
	return tsm_bus;
}
EXPORT_SYMBOL_GPL(pci_tsm_register);

void pci_tsm_unregister(struct tsm_bus_subsys *subsys)
{
	struct pci_dev *pdev = NULL;

	pr_info("Shut down TSM PCI\n");
	bus_unregister_notifier(&pci_bus_type, &subsys->notifier);
	for_each_pci_dev(pdev)
		tsm_pci_dev_free(pdev);
}
EXPORT_SYMBOL_GPL(pci_tsm_unregister);

static int __init tsm_pci_init(void)
{
	pr_info(DRIVER_DESC " version: " DRIVER_VERSION "\n");
	return 0;
}

static void __exit tsm_pci_cleanup(void)
{
	pr_info(DRIVER_DESC " version: " DRIVER_VERSION " unload\n");
}

module_init(tsm_pci_init);
module_exit(tsm_pci_cleanup);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
