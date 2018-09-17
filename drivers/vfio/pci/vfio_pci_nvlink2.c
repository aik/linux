// SPDX-License-Identifier: GPL-2.0+
/*
 * VFIO PCI NVIDIA Whitherspoon GPU support a.k.a. NVLink2.
 *
 * Copyright (C) 2018 IBM Corp.  All rights reserved.
 *     Author: Alexey Kardashevskiy <aik@ozlabs.ru>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Register an on-GPU RAM region for cacheable access.
 *
 * Derived from original vfio_pci_igd.c:
 * Copyright (C) 2016 Red Hat, Inc.  All rights reserved.
 *	Author: Alex Williamson <alex.williamson@redhat.com>
 */

#include <linux/io.h>
#include <linux/pci.h>
#include <linux/uaccess.h>
#include <linux/vfio.h>
#include <linux/sched/mm.h>
#include <linux/mmu_context.h>

#include "vfio_pci_private.h"

struct vfio_pci_nvlink2_data {
	unsigned long gpu_hpa;
	unsigned long useraddr;
	unsigned long size;
	struct mm_struct *mm;
	struct mm_iommu_table_group_mem_t *mem;
};

static size_t vfio_pci_nvlink2_rw(struct vfio_pci_device *vdev,
		char __user *buf, size_t count, loff_t *ppos, bool iswrite)
{
	unsigned int i = VFIO_PCI_OFFSET_TO_INDEX(*ppos) - VFIO_PCI_NUM_REGIONS;
	void *base = vdev->region[i].data;
	loff_t pos = *ppos & VFIO_PCI_OFFSET_MASK;

	if (pos >= vdev->region[i].size)
		return -EINVAL;

	count = min(count, (size_t)(vdev->region[i].size - pos));

	if (iswrite) {
		if (copy_from_user(base + pos, buf, count))
			return -EFAULT;
	} else {
		if (copy_to_user(buf, base + pos, count))
			return -EFAULT;
	}
	*ppos += count;

	return count;
}

static void vfio_pci_nvlink2_release(struct vfio_pci_device *vdev,
		struct vfio_pci_region *region)
{
	struct vfio_pci_nvlink2_data *data = region->data;
	long ret;

	/* If there were any mappings at all... */
	if (data->mm) {
		ret = mm_iommu_put(data->mm, data->mem);
		WARN_ON(ret);

		mmdrop(data->mm);
	}
	kfree(data);

	/* FIXME: iounmap */
}

static int vfio_pci_nvlink2_mmap_fault(struct vm_fault *vmf)
{
	int ret;
	struct vm_area_struct *vma = vmf->vma;
	struct vfio_pci_region *region = vma->vm_private_data;
	struct vfio_pci_nvlink2_data *data = region->data;
	unsigned long vmf_off = (vmf->address - vma->vm_start) >> PAGE_SHIFT;
	unsigned long nv2pg = data->gpu_hpa >> PAGE_SHIFT;
	unsigned long vm_pgoff = vma->vm_pgoff &
		((1U << (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT)) - 1);
	unsigned long pfn = nv2pg + vm_pgoff + vmf_off;

	ret = vm_insert_pfn(vma, vmf->address, pfn);
	/* TODO: make it a tracepoint */
	pr_debug("NVLink2: vmf=%lx hpa=%lx ret=%d\n",
		 vmf->address, pfn << PAGE_SHIFT, ret);
	if (ret)
		return VM_FAULT_SIGSEGV;

	return VM_FAULT_NOPAGE;
}

static const struct vm_operations_struct vfio_pci_nvlink2_mmap_vmops = {
	.fault = vfio_pci_nvlink2_mmap_fault,
};

static int vfio_pci_nvlink2_mmap(struct vfio_pci_device *vdev,
		struct vfio_pci_region *region, struct vm_area_struct *vma)
{
	long ret;
	struct vfio_pci_nvlink2_data *data = region->data;

	if (data->useraddr)
		return -EPERM;

	if (vma->vm_end - vma->vm_start > data->size)
		return -EINVAL;

	vma->vm_private_data = region;
	vma->vm_flags |= VM_PFNMAP;
	vma->vm_ops = &vfio_pci_nvlink2_mmap_vmops;

	/*
	 * Calling mm_iommu_newdev() here once as the region is not
	 * registered yet and therefore right initialization will happen now.
	 * Other places will use mm_iommu_find() which returns
	 * registered @mem and does not go gup().
	 */
	data->useraddr = vma->vm_start;
	data->mm = current->mm;
	atomic_inc(&data->mm->mm_count);
	ret = mm_iommu_newdev(data->mm, data->useraddr,
			(vma->vm_end - vma->vm_start) >> PAGE_SHIFT,
			data->gpu_hpa, &data->mem);

	pr_debug("VFIO NVLINK2 mmap: useraddr=%lx hpa=%lx size=%lx ret=%ld\n",
			data->useraddr, data->gpu_hpa,
			vma->vm_end - vma->vm_start, ret);

	return ret;
}

static const struct vfio_pci_regops vfio_pci_nvlink2_regops = {
	.rw = vfio_pci_nvlink2_rw,
	.release = vfio_pci_nvlink2_release,
	.mmap = vfio_pci_nvlink2_mmap,
};

int vfio_pci_nvlink2_init(struct vfio_pci_device *vdev)
{
	int len = 0, ret;
	struct device_node *npu_node, *mem_node;
	struct pci_dev *npu_dev;
	uint32_t *mem_phandle, *val;
	struct vfio_pci_nvlink2_data *data;

	npu_dev = pnv_pci_get_npu_dev(vdev->pdev, 0);
	if (!npu_dev)
		return -EINVAL;

	npu_node = pci_device_to_OF_node(npu_dev);
	if (!npu_node)
		return -EINVAL;

	mem_phandle = (void *) of_get_property(npu_node, "memory-region", NULL);
	if (!mem_phandle)
		return -EINVAL;

	mem_node = of_find_node_by_phandle(be32_to_cpu(*mem_phandle));
	if (!mem_node)
		return -EINVAL;

	val = (uint32_t *) of_get_property(mem_node, "reg", &len);
	if (!val || len != 2 * sizeof(uint64_t))
		return -EINVAL;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->gpu_hpa = ((uint64_t)be32_to_cpu(val[0]) << 32) |
			be32_to_cpu(val[1]);
	data->size = ((uint64_t)be32_to_cpu(val[2]) << 32) |
			be32_to_cpu(val[3]);

	dev_dbg(&vdev->pdev->dev, "%lx..%lx\n", data->gpu_hpa,
			data->gpu_hpa + data->size - 1);

	ret = vfio_pci_register_dev_region(vdev,
			PCI_VENDOR_ID_NVIDIA | VFIO_REGION_TYPE_PCI_VENDOR_TYPE,
			VFIO_REGION_SUBTYPE_NVIDIA_NVLINK2_RAM,
			&vfio_pci_nvlink2_regops, data->size,
			VFIO_REGION_INFO_FLAG_READ, data);
	if (ret)
		kfree(data);

	return ret;
}

/*
 * IBM NPU2 ATSD registers mapping
 */
struct vfio_pci_nvlink2_atsd_data {
	unsigned long mmio_atsd;
};

static int vfio_pci_npu2_mmap(struct vfio_pci_device *vdev,
		struct vfio_pci_region *region, struct vm_area_struct *vma)
{
	int ret;
	struct vfio_pci_nvlink2_atsd_data *data = region->data;
	unsigned long req_len = vma->vm_end - vma->vm_start;

	if (req_len != PAGE_SIZE)
		return -EINVAL;

	vma->vm_flags |= VM_PFNMAP;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	ret = remap_pfn_range(vma, vma->vm_start, data->mmio_atsd >> PAGE_SHIFT,
			req_len, vma->vm_page_prot);
	pr_debug("VFIO NPU2 mmap: %lx %lx size=%lx ret=%d\n",
			vma->vm_start, data->mmio_atsd,
			vma->vm_end - vma->vm_start, ret);

	return ret;
}

static void vfio_pci_npu2_release(struct vfio_pci_device *vdev,
		struct vfio_pci_region *region)
{
	struct vfio_pci_nvlink2_atsd_data *data = region->data;

	/* FIXME: iounmap */

	kfree(data);
}

static const struct vfio_pci_regops vfio_pci_npu2_regops = {
	.mmap = vfio_pci_npu2_mmap,
	.release = vfio_pci_npu2_release,
};

int vfio_pci_npu2_init(struct vfio_pci_device *vdev)
{
	int ret, i;
	u32 nvlink_index = 0;
	struct pci_dev *npdev = vdev->pdev;
	struct pci_controller *hose = pci_bus_to_host(npdev->bus);
	u64 mmio_atsd = 0;
	bool found = false;
	struct vfio_pci_nvlink2_atsd_data *data;

	/*
	 * FIXME: there normally should be 8 registers but somehow
	 * there is just one so we just use that.
	 */
/*
	struct device_node *nvlink_dn;

	nvlink_dn = of_parse_phandle(npdev->dev.of_node, "ibm,nvlink", 0);
	if (WARN_ON(of_property_read_u32(nvlink_dn, "ibm,npu-link-index",
			&nvlink_index)))
		return -ENODEV;
*/

	for (i = 0; !of_property_read_u64_index(hose->dn, "ibm,mmio-atsd",
				i, &mmio_atsd); i++) {
		if (i == nvlink_index) {
			found = true;
			break;
		}
	}

	if (!found) {
		dev_warn(&vdev->pdev->dev, "No ATSD found\n");
		return -EFAULT;
	}

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->mmio_atsd = mmio_atsd;

	ret = vfio_pci_register_dev_region(vdev,
			PCI_VENDOR_ID_IBM | VFIO_REGION_TYPE_PCI_VENDOR_TYPE,
			VFIO_REGION_SUBTYPE_IBM_NVLINK2_ATSD,
			&vfio_pci_npu2_regops, PAGE_SIZE,
			VFIO_REGION_INFO_FLAG_READ,
			data);

	if (ret)
		kfree(data);

	return ret;
}
