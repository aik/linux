// SPDX-License-Identifier: GPL-2.0+
/*
 * A helper to disable NVLinks between GPUs on IBM Withersponn platform.
 *
 * Copyright (C) 2019 IBM Corp.  All rights reserved.
 *     Author: Alexey Kardashevskiy <aik@ozlabs.ru>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/device.h>
#include <linux/of.h>
#include <linux/iommu.h>
#include <linux/pci.h>

static int nvlinkgpu_is_ph_in_group(struct device *dev, void *data)
{
	return dev->of_node->phandle == *(phandle *) data;
}

static u32 nvlinkgpu_get_disable_mask(struct device *dev)
{
	int npu, peer;
	u32 mask;
	struct device_node *dn;
	struct iommu_group *group;

	dn = dev->of_node;
	if (!of_find_property(dn, "ibm,nvlink-peers", NULL))
		return 0;

	group = iommu_group_get(dev);
	if (!group)
		return 0;

	/*
	 * Collect links to keep which includes links to NPU and links to
	 * other GPUs in the same IOMMU group.
	 */
	for (npu = 0, mask = 0; ; ++npu) {
		u32 npuph = 0;

		if (of_property_read_u32_index(dn, "ibm,npu", npu, &npuph))
			break;

		for (peer = 0; ; ++peer) {
			u32 peerph = 0;

			if (of_property_read_u32_index(dn, "ibm,nvlink-peers",
					peer, &peerph))
				break;

			if (peerph != npuph &&
				!iommu_group_for_each_dev(group, &peerph,
					nvlinkgpu_is_ph_in_group))
				continue;

			mask |= 1 << (peer + 16);
		}
	}
	iommu_group_put(group);

	/* Disabling mechanism takes links to disable so invert it here */
	mask = ~mask & 0x3F0000;

	return mask;
}

void pnv_try_isolate_nvidia_v100(struct pci_dev *bridge)
{
	u32 mask, val;
	void __iomem *bar0_0, *bar0_120000, *bar0_a00000;
	struct pci_dev *pdev;
	u16 cmd = 0, cmdmask = PCI_COMMAND_MEMORY;

	if (!bridge->subordinate)
		return;

	pdev = list_first_entry_or_null(&bridge->subordinate->devices,
			struct pci_dev, bus_list);
	if (!pdev)
		return;

	if (pdev->vendor != PCI_VENDOR_ID_NVIDIA)
		return;

	mask = nvlinkgpu_get_disable_mask(&pdev->dev);
	if (!mask)
		return;

	bar0_0 = pci_iomap_range(pdev, 0, 0, 0x10000);
	if (!bar0_0) {
		pci_err(pdev, "Error mapping BAR0 @0\n");
		return;
	}
	bar0_120000 = pci_iomap_range(pdev, 0, 0x120000, 0x10000);
	if (!bar0_120000) {
		pci_err(pdev, "Error mapping BAR0 @120000\n");
		goto bar0_0_unmap;
	}
	bar0_a00000 = pci_iomap_range(pdev, 0, 0xA00000, 0x10000);
	if (!bar0_a00000) {
		pci_err(pdev, "Error mapping BAR0 @A00000\n");
		goto bar0_120000_unmap;
	}

	pci_restore_state(pdev);
	pci_read_config_word(pdev, PCI_COMMAND, &cmd);
	if ((cmd & cmdmask) != cmdmask)
		pci_write_config_word(pdev, PCI_COMMAND, cmd | cmdmask);

	/*
	 * The sequence is from "Tesla P100 and V100 SXM2 NVLink Isolation on
	 * Multi-Tenant Systems".
	 * The register names are not provided there either, hence raw values.
	 */
	iowrite32(0x4, bar0_120000 + 0x4C);
	iowrite32(0x2, bar0_120000 + 0x2204);
	val = ioread32(bar0_0 + 0x200);
	val |= 0x02000000;
	iowrite32(val, bar0_0 + 0x200);
	val = ioread32(bar0_a00000 + 0x148);
	val |= mask;
	iowrite32(val, bar0_a00000 + 0x148);

	if ((cmd | cmdmask) != cmd)
		pci_write_config_word(pdev, PCI_COMMAND, cmd);

	pci_iounmap(pdev, bar0_a00000);
bar0_120000_unmap:
	pci_iounmap(pdev, bar0_120000);
bar0_0_unmap:
	pci_iounmap(pdev, bar0_0);
}
