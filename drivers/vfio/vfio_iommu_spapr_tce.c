/*
 * VFIO: IOMMU DMA mapping support for TCE on POWER
 *
 * Copyright (C) 2013 IBM Corp.  All rights reserved.
 *     Author: Alexey Kardashevskiy <aik@ozlabs.ru>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Derived from original vfio_iommu_type1.c:
 * Copyright (C) 2012 Red Hat, Inc.  All rights reserved.
 *     Author: Alex Williamson <alex.williamson@redhat.com>
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/err.h>
#include <linux/vfio.h>
#include <asm/iommu.h>
#include <asm/tce.h>

#define DRIVER_VERSION  "0.1"
#define DRIVER_AUTHOR   "aik@ozlabs.ru"
#define DRIVER_DESC     "VFIO IOMMU SPAPR TCE"

static void tce_iommu_detach_group(void *iommu_data,
		struct iommu_group *iommu_group);

#define IOMMU_TABLE_PAGES(tbl) \
		(((tbl)->it_size << (tbl)->it_page_shift) >> PAGE_SHIFT)

static long try_increment_locked_vm(long npages)
{
	long ret = 0, locked, lock_limit;

	if (!current || !current->mm)
		return -ESRCH; /* process exited */

	down_write(&current->mm->mmap_sem);
	locked = current->mm->locked_vm + npages;
	lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
	if (locked > lock_limit && !capable(CAP_IPC_LOCK)) {
		pr_warn("[%d] RLIMIT_MEMLOCK (%ld) exceeded\n",
				current->pid, rlimit(RLIMIT_MEMLOCK));
		ret = -ENOMEM;
	} else {
		current->mm->locked_vm += npages;
	}
	pr_debug("[%d] RLIMIT_MEMLOCK+ %ld pages\n", current->pid,
			current->mm->locked_vm);
	up_write(&current->mm->mmap_sem);

	return ret;
}

static void decrement_locked_vm(long npages)
{
	if (!current || !current->mm)
		return; /* process exited */

	down_write(&current->mm->mmap_sem);
	if (npages > current->mm->locked_vm)
		npages = current->mm->locked_vm;
	current->mm->locked_vm -= npages;
	pr_debug("[%d] RLIMIT_MEMLOCK- %ld pages\n", current->pid,
			current->mm->locked_vm);
	up_write(&current->mm->mmap_sem);
}

/*
 * VFIO IOMMU fd for SPAPR_TCE IOMMU implementation
 *
 * This code handles mapping and unmapping of user data buffers
 * into DMA'ble space using the IOMMU
 */

/*
 * The container descriptor supports only a single group per container.
 * Required by the API as the container is not supplied with the IOMMU group
 * at the moment of initialization.
 */
struct tce_container {
	struct mutex lock;
	bool enabled;
	struct list_head mem_list;
	struct iommu_table tables[POWERPC_IOMMU_MAX_TABLES];
	struct list_head group_list;
};

struct tce_iommu_group {
	struct list_head next;
	struct iommu_group *grp;
};

struct tce_memory {
	struct list_head next;
	struct rcu_head rcu;
	__u64 vaddr;
	__u64 size;
};

static void tce_unpin_pages(__u64 vaddr, __u64 size)
{
	__u64 off;
	struct page *page = NULL;

	if (!current || !current->mm)
		return; /* process exited */

	for (off = 0; off < size; off += PAGE_SIZE) {
		if (1 != get_user_pages_fast(vaddr + off,
					1/* pages */, 1/* iswrite */,
					&page))
			continue;

		put_page(page);
		put_page(page);
	}
}

static void release_tce_memory(struct rcu_head *head)
{
	struct tce_memory *mem = container_of(head, struct tce_memory, rcu);
	kfree(mem);
}

static void tce_do_unregister_pages(struct tce_memory *mem)
{
	tce_unpin_pages(mem->vaddr, mem->size);
	decrement_locked_vm(mem->size);
	list_del_rcu(&mem->next);
	call_rcu_sched(&mem->rcu, release_tce_memory);
}

static long tce_unregister_pages(struct tce_container *container,
		__u64 vaddr, __u64 size)
{
	struct tce_memory *mem, *memtmp;

	if (container->enabled)
		return -EBUSY;

	if ((vaddr & ~PAGE_MASK) || (size & ~PAGE_MASK))
		return -EINVAL;

	list_for_each_entry_safe(mem, memtmp, &container->mem_list, next) {
		if ((mem->vaddr == vaddr) && (mem->size == size)) {
			tce_do_unregister_pages(mem);
			return 0;
		}
	}

	return -ENOENT;
}

static long tce_pin_pages(__u64 vaddr, __u64 size)
{
	__u64 off;
	struct page *page = NULL;

	for (off = 0; off < size; off += PAGE_SIZE) {
		if (1 != get_user_pages_fast(vaddr + off,
					1/* pages */, 1/* iswrite */, &page)) {
			tce_unpin_pages(vaddr, off);
			return -EFAULT;
		}
	}

	return 0;
}

static long tce_register_pages(struct tce_container *container,
		__u64 vaddr, __u64 size)
{
	long ret;
	struct tce_memory *mem;

	if (container->enabled)
		return -EBUSY;

	if ((vaddr & ~PAGE_MASK) || (size & ~PAGE_MASK) ||
			((vaddr + size) < vaddr))
		return -EINVAL;

	/* Any overlap with registered chunks? */
	rcu_read_lock();
	list_for_each_entry_rcu(mem, &container->mem_list, next) {
		if ((mem->vaddr < (vaddr + size)) &&
				(vaddr < (mem->vaddr + mem->size))) {
			ret = -EBUSY;
			goto unlock_exit;
		}
	}

	ret = try_increment_locked_vm(size >> PAGE_SHIFT);
	if (ret)
		goto unlock_exit;

	mem = kzalloc(sizeof(*mem), GFP_KERNEL);
	if (!mem)
		goto unlock_exit;

	if (tce_pin_pages(vaddr, size))
		goto free_exit;

	mem->vaddr = vaddr;
	mem->size = size;

	list_add_rcu(&mem->next, &container->mem_list);
	rcu_read_unlock();

	return 0;

free_exit:
	kfree(mem);

unlock_exit:
	decrement_locked_vm(size >> PAGE_SHIFT);
	rcu_read_unlock();

	return ret;
}

static inline bool tce_preregistered(struct tce_container *container)
{
	return !list_empty(&container->mem_list);
}

static bool tce_pinned(struct tce_container *container,
		__u64 vaddr, __u64 size)
{
	struct tce_memory *mem;
	bool ret = false;

	rcu_read_lock();
	list_for_each_entry_rcu(mem, &container->mem_list, next) {
		if ((mem->vaddr <= vaddr) &&
				(vaddr + size <= mem->vaddr + mem->size)) {
			ret = true;
			break;
		}
	}
	rcu_read_unlock();

	return ret;
}

static inline bool tce_groups_attached(struct tce_container *container)
{
	return !list_empty(&container->group_list);
}

static struct iommu_table *spapr_tce_find_table(
		struct tce_container *container,
		phys_addr_t ioba)
{
	long i;
	struct iommu_table *ret = NULL;

	mutex_lock(&container->lock);
	for (i = 0; i < POWERPC_IOMMU_MAX_TABLES; ++i) {
		struct iommu_table *tbl = &container->tables[i];
		unsigned long entry = ioba >> tbl->it_page_shift;
		unsigned long start = tbl->it_offset;
		unsigned long end = start + tbl->it_size;

		if ((start <= entry) && (entry < end)) {
			ret = tbl;
			break;
		}
	}
	mutex_unlock(&container->lock);

	WARN_ON_ONCE(!ret);

	return ret;
}

static unsigned long tce_default_winsize(struct tce_container *container)
{
	struct tce_iommu_group *tcegrp;
	struct powerpc_iommu *iommu;

	if (!tce_groups_attached(container))
		return 0;

	tcegrp = list_first_entry(&container->group_list,
			struct tce_iommu_group, next);
	if (!tcegrp)
		return 0;

	iommu = iommu_group_get_iommudata(tcegrp->grp);
	if (!iommu)
		return 0;

	return iommu->tce32_size;
}

static int tce_iommu_enable(struct tce_container *container)
{
	int ret = 0;

	if (!tce_groups_attached(container))
		return -ENXIO;

	if (container->enabled)
		return -EBUSY;

	/*
	 * When userspace pages are mapped into the IOMMU, they are effectively
	 * locked memory, so, theoretically, we need to update the accounting
	 * of locked pages on each map and unmap.  For powerpc, the map unmap
	 * paths can be very hot, though, and the accounting would kill
	 * performance, especially since it would be difficult to impossible
	 * to handle the accounting in real mode only.
	 *
	 * To address that, rather than precisely accounting every page, we
	 * instead account for a worst case on locked memory when the iommu is
	 * enabled and disabled.  The worst case upper bound on locked memory
	 * is the size of the whole iommu window, which is usually relatively
	 * small (compared to total memory sizes) on POWER hardware.
	 *
	 * Also we don't have a nice way to fail on H_PUT_TCE due to ulimits,
	 * that would effectively kill the guest at random points, much better
	 * enforcing the limit based on the max that the guest can map.
	 *
	 * Unfortunately at the moment it counts whole tables, no matter how
	 * much memory the guest has. I.e. for 4GB guest and 4 IOMMU groups
	 * each with 2GB DMA window, 8GB will be counted here. The reason for
	 * this is that we cannot tell here the amount of RAM used by the guest
	 * as this information is only available from KVM and VFIO is
	 * KVM agnostic.
	 */
	if (!tce_preregistered(container)) {
		ret = try_increment_locked_vm(
				tce_default_winsize(container) >> PAGE_SHIFT);
		if (ret)
			return ret;
	}

	container->enabled = true;

	return ret;
}

static int tce_iommu_clear(struct tce_container *container,
		struct iommu_table *tbl,
		unsigned long entry, unsigned long pages);

static void tce_iommu_disable(struct tce_container *container)
{
	if (!container->enabled)
		return;

	container->enabled = false;

	if (!tce_preregistered(container))
		decrement_locked_vm(
				tce_default_winsize(container) >> PAGE_SHIFT);
}

static void *tce_iommu_open(unsigned long arg)
{
	struct tce_container *container;

	if (arg != VFIO_SPAPR_TCE_IOMMU) {
		pr_err("tce_vfio: Wrong IOMMU type\n");
		return ERR_PTR(-EINVAL);
	}

	container = kzalloc(sizeof(*container), GFP_KERNEL);
	if (!container)
		return ERR_PTR(-ENOMEM);

	mutex_init(&container->lock);
	INIT_LIST_HEAD_RCU(&container->mem_list);
	INIT_LIST_HEAD_RCU(&container->group_list);

	return container;
}

static void tce_iommu_release(void *iommu_data)
{
	int i;
	struct powerpc_iommu *iommu;
	struct tce_iommu_group *tcegrp;
	struct tce_container *container = iommu_data;
	struct tce_memory *mem, *memtmp;
	struct powerpc_iommu_ops *iommuops = NULL;

	tce_iommu_disable(container);

	while (tce_groups_attached(container)) {
		tcegrp = list_first_entry(&container->group_list,
				struct tce_iommu_group, next);
		iommu = iommu_group_get_iommudata(tcegrp->grp);
		iommuops = iommu->ops;
		tce_iommu_detach_group(iommu_data, tcegrp->grp);
	}

	/* Free tables */
	if (iommuops) {
		for (i = 0; i < POWERPC_IOMMU_MAX_TABLES; ++i) {
			struct iommu_table *tbl = &container->tables[i];

			tce_iommu_clear(container, tbl,
					tbl->it_offset, tbl->it_size);

			if (!tce_preregistered(container))
				decrement_locked_vm(IOMMU_TABLE_PAGES(tbl));

			iommuops->free_table(tbl);
		}
	}

	list_for_each_entry_safe(mem, memtmp, &container->mem_list, next)
		tce_do_unregister_pages(mem);

	mutex_destroy(&container->lock);

	kfree(container);
}

static void tce_iommu_unuse_page(unsigned long oldtce, bool do_put)
{
	struct page *page;

	if (!(oldtce & (TCE_PCI_READ | TCE_PCI_WRITE)))
		return;

	page = pfn_to_page(__pa(oldtce) >> PAGE_SHIFT);
	if (oldtce & TCE_PCI_WRITE)
		SetPageDirty(page);
	if (do_put)
		put_page(page);
}

static int tce_iommu_clear(struct tce_container *container,
		struct iommu_table *tbl,
		unsigned long entry, unsigned long pages)
{
	long ret;
	unsigned long oldtce;
	const bool do_put = !tce_preregistered(container);

	for ( ; pages; --pages, ++entry) {
		oldtce = 0;
		ret = iommu_tce_xchg(tbl, entry, 0, &oldtce, DMA_NONE);
		if (ret)
			continue;

		tce_iommu_unuse_page(oldtce, do_put);
	}

	return 0;
}

static enum dma_data_direction tce_iommu_direction(unsigned long tce)
{
	if ((tce & TCE_PCI_READ) && (tce & TCE_PCI_WRITE))
		return DMA_BIDIRECTIONAL;
	else if (tce & TCE_PCI_READ)
		return DMA_TO_DEVICE;
	else if (tce & TCE_PCI_WRITE)
		return DMA_FROM_DEVICE;
	else
		return DMA_NONE;
}

static long tce_iommu_build(struct tce_container *container,
		struct iommu_table *tbl,
		unsigned long entry, unsigned long tce, unsigned long pages)
{
	long i, ret = 0, shift;
	struct page *page = NULL;
	unsigned long hva, oldtce;
	enum dma_data_direction direction = tce_iommu_direction(tce);
	const bool do_get = !tce_preregistered(container);

	for (i = 0; i < pages; ++i) {
		ret = get_user_pages_fast(tce & PAGE_MASK, 1,
				direction != DMA_TO_DEVICE, &page);
		if (unlikely(ret != 1)) {
			/* pr_err("iommu_tce: get_user_pages_fast failed tce=%lx ioba=%lx ret=%d\n",
			   tce, entry << tbl->it_page_shift, ret); */
			ret = -EFAULT;
			break;
		}
		/*
		 * Check that the TCE table granularity is not bigger than the size of
		 * a page we just found. Otherwise the hardware can get access to
		 * a bigger memory chunk that it should.
		 */
		shift = PAGE_SHIFT + compound_order(compound_head(page));
		if (shift < tbl->it_page_shift) {
			ret = -EFAULT;
			break;
		}

		hva = (unsigned long) page_address(page) +
			(tce & IOMMU_PAGE_MASK(tbl) & ~PAGE_MASK);
		oldtce = 0;

		ret = iommu_tce_xchg(tbl, entry + i, hva, &oldtce, direction);
		if (ret) {
			put_page(page);
			pr_err("iommu_tce: %s failed ioba=%lx, tce=%lx, ret=%ld\n",
					__func__, entry << tbl->it_page_shift,
					tce, ret);
			break;
		}

		tce_iommu_unuse_page(oldtce, do_get);

		tce += IOMMU_PAGE_SIZE(tbl);
	}

	if (ret)
		tce_iommu_clear(container, tbl, entry, i);

	return ret;
}

static long tce_iommu_ioctl(void *iommu_data,
				 unsigned int cmd, unsigned long arg)
{
	struct tce_container *container = iommu_data;
	unsigned long minsz;
	long ret;

	switch (cmd) {
	case VFIO_CHECK_EXTENSION:
		switch (arg) {
		case VFIO_SPAPR_TCE_IOMMU:
			ret = 1;
			break;
		default:
			ret = vfio_spapr_iommu_eeh_ioctl(NULL, cmd, arg);
			break;
		}

		return (ret < 0) ? 0 : ret;

	case VFIO_IOMMU_SPAPR_TCE_GET_INFO: {
		struct vfio_iommu_spapr_tce_info info;
		struct tce_iommu_group *tcegrp;
		struct powerpc_iommu *iommu;

		if (!tce_groups_attached(container))
			return -ENXIO;

		tcegrp = list_first_entry(&container->group_list,
				struct tce_iommu_group, next);
		iommu = iommu_group_get_iommudata(tcegrp->grp);

		if (!iommu)
			return -ENXIO;

		minsz = offsetofend(struct vfio_iommu_spapr_tce_info,
				dma32_window_size);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		info.dma32_window_start = iommu->tce32_start;
		info.dma32_window_size = iommu->tce32_size;

		if (copy_to_user((void __user *)arg, &info, minsz))
			return -EFAULT;

		return 0;
	}
	case VFIO_IOMMU_MAP_DMA: {
		struct vfio_iommu_type1_dma_map param;
		struct iommu_table *tbl;
		unsigned long tce;

		if (!container->enabled)
			return -EPERM;

		minsz = offsetofend(struct vfio_iommu_type1_dma_map, size);

		if (copy_from_user(&param, (void __user *)arg, minsz))
			return -EFAULT;

		if (param.argsz < minsz)
			return -EINVAL;

		if (param.flags & ~(VFIO_DMA_MAP_FLAG_READ |
				VFIO_DMA_MAP_FLAG_WRITE))
			return -EINVAL;

		tbl = spapr_tce_find_table(container, param.iova);
		if (!tbl)
			return -ENXIO;

		if ((param.size & ~IOMMU_PAGE_MASK(tbl)) ||
				(param.vaddr & ~IOMMU_PAGE_MASK(tbl)))
			return -EINVAL;

		/* iova is checked by the IOMMU API */
		tce = param.vaddr;
		if (param.flags & VFIO_DMA_MAP_FLAG_READ)
			tce |= TCE_PCI_READ;
		if (param.flags & VFIO_DMA_MAP_FLAG_WRITE)
			tce |= TCE_PCI_WRITE;

		ret = iommu_tce_put_param_check(tbl, param.iova, tce);
		if (ret)
			return ret;

		/* If any memory is pinned, only allow pages from that region */
		if (tce_preregistered(container) &&
				!tce_pinned(container, param.vaddr, param.size))
			return -EPERM;

		ret = tce_iommu_build(container, tbl,
				param.iova >> tbl->it_page_shift,
				tce, param.size >> tbl->it_page_shift);

		iommu_flush_tce(tbl);

		return ret;
	}
	case VFIO_IOMMU_UNMAP_DMA: {
		struct vfio_iommu_type1_dma_unmap param;
		struct iommu_table *tbl;

		minsz = offsetofend(struct vfio_iommu_type1_dma_unmap,
				size);

		if (copy_from_user(&param, (void __user *)arg, minsz))
			return -EFAULT;

		if (param.argsz < minsz)
			return -EINVAL;

		/* No flag is supported now */
		if (param.flags)
			return -EINVAL;

		tbl = spapr_tce_find_table(container, param.iova);
		if (!tbl)
			return -ENXIO;

		if (param.size & ~IOMMU_PAGE_MASK(tbl))
			return -EINVAL;

		ret = iommu_tce_clear_param_check(tbl, param.iova, 0,
				param.size >> tbl->it_page_shift);
		if (ret)
			return ret;

		ret = tce_iommu_clear(container, tbl,
				param.iova >> tbl->it_page_shift,
				param.size >> tbl->it_page_shift);
		iommu_flush_tce(tbl);

		return ret;
	}
	case VFIO_IOMMU_REGISTER_MEMORY: {
		struct vfio_iommu_type1_register_memory param;

		minsz = offsetofend(struct vfio_iommu_type1_register_memory,
				size);

		if (copy_from_user(&param, (void __user *)arg, minsz))
			return -EFAULT;

		if (param.argsz < minsz)
			return -EINVAL;

		/* No flag is supported now */
		if (param.flags)
			return -EINVAL;

		mutex_lock(&container->lock);
		ret = tce_register_pages(container, param.vaddr, param.size);
		mutex_unlock(&container->lock);

		return ret;
	}
	case VFIO_IOMMU_UNREGISTER_MEMORY: {
		struct vfio_iommu_type1_unregister_memory param;

		minsz = offsetofend(struct vfio_iommu_type1_unregister_memory,
				size);

		if (copy_from_user(&param, (void __user *)arg, minsz))
			return -EFAULT;

		if (param.argsz < minsz)
			return -EINVAL;

		/* No flag is supported now */
		if (param.flags)
			return -EINVAL;

		mutex_lock(&container->lock);
		tce_unregister_pages(container, param.vaddr, param.size);
		mutex_unlock(&container->lock);

		return 0;
	}
	case VFIO_IOMMU_ENABLE:
		mutex_lock(&container->lock);
		ret = tce_iommu_enable(container);
		mutex_unlock(&container->lock);
		return ret;


	case VFIO_IOMMU_DISABLE:
		mutex_lock(&container->lock);
		tce_iommu_disable(container);
		mutex_unlock(&container->lock);
		return 0;

	case VFIO_EEH_PE_OP: {
		struct tce_iommu_group *tcegrp;

		ret = 0;
		list_for_each_entry(tcegrp, &container->group_list, next) {
			ret = vfio_spapr_iommu_eeh_ioctl(tcegrp->grp,
					cmd, arg);
			if (ret)
				return ret;
		}
		return ret;
	}

	}

	return -ENOTTY;
}

static int tce_iommu_attach_group(void *iommu_data,
		struct iommu_group *iommu_group)
{
	int ret, i;
	struct tce_container *container = iommu_data;
	struct powerpc_iommu *iommu = iommu_group_get_iommudata(iommu_group);
	struct tce_iommu_group *tcegrp;

	mutex_lock(&container->lock);

	/* pr_debug("tce_vfio: Attaching group #%u to iommu %p\n",
			iommu_group_id(iommu_group), iommu_group); */

	list_for_each_entry(tcegrp, &container->group_list, next) {
		struct powerpc_iommu *iommutmp;

		if (tcegrp->grp == iommu_group) {
			pr_warn("tce_vfio: Group %d is already attached\n",
					iommu_group_id(iommu_group));
			ret = -EBUSY;
			goto unlock_exit;
		}
		iommutmp = iommu_group_get_iommudata(tcegrp->grp);
		if (iommutmp->ops != iommu->ops) {
			pr_warn("tce_vfio: Group %d is incompatible with group %d\n",
					iommu_group_id(iommu_group),
					iommu_group_id(tcegrp->grp));
			ret = -EBUSY;
			goto unlock_exit;
		}
	}

	ret = iommu_take_ownership(iommu);
	if (ret)
		goto unlock_exit;

	tcegrp = kzalloc(sizeof(*tcegrp), GFP_KERNEL);
	tcegrp->grp = iommu_group;
	list_add(&tcegrp->next, &container->group_list);
	for (i = 0; i < POWERPC_IOMMU_MAX_TABLES; ++i) {
		struct iommu_table *tbl = &container->tables[i];

		if (!tbl->it_size)
			continue;

		/* Set the default window to a new group */
		ret = iommu->ops->set_window(iommu, i, tbl);
		if (ret)
			goto unlock_exit;
	}

unlock_exit:
	mutex_unlock(&container->lock);

	return ret;
}

static void tce_iommu_detach_group(void *iommu_data,
		struct iommu_group *iommu_group)
{
	struct tce_container *container = iommu_data;
	struct powerpc_iommu *iommu;
	struct tce_iommu_group *tcegrp, *tcegrptmp;
	long i;

	mutex_lock(&container->lock);

	/* Detach windows from IOMMUs */
	list_for_each_entry_safe(tcegrp, tcegrptmp, &container->group_list,
			next) {
		if (tcegrp->grp != iommu_group)
			continue;

		list_del(&tcegrp->next);
		iommu = iommu_group_get_iommudata(iommu_group);
		BUG_ON(!iommu);

		for (i = 0; i < POWERPC_IOMMU_MAX_TABLES; ++i)
			iommu->ops->unset_window(iommu, i);

		iommu_release_ownership(iommu);

		kfree(tcegrp);
		break;
	}
	mutex_unlock(&container->lock);
}

const struct vfio_iommu_driver_ops tce_iommu_driver_ops = {
	.name		= "iommu-vfio-powerpc",
	.owner		= THIS_MODULE,
	.open		= tce_iommu_open,
	.release	= tce_iommu_release,
	.ioctl		= tce_iommu_ioctl,
	.attach_group	= tce_iommu_attach_group,
	.detach_group	= tce_iommu_detach_group,
};

static int __init tce_iommu_init(void)
{
	return vfio_register_iommu_driver(&tce_iommu_driver_ops);
}

static void __exit tce_iommu_cleanup(void)
{
	vfio_unregister_iommu_driver(&tce_iommu_driver_ops);
}

module_init(tce_iommu_init);
module_exit(tce_iommu_cleanup);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);

