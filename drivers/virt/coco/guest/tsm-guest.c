// SPDX-License-Identifier: GPL-2.0-only

#include <linux/module.h>
#include <linux/tsm.h>
#include <linux/pci.h>

#define DRIVER_VERSION	"0.1"
#define DRIVER_AUTHOR	"aik@amd.com"
#define DRIVER_DESC	"TSM guest library"

struct tsm_guest_subsys {
	struct tsm_subsys base;
	struct tsm_vm_ops *ops;
	void *private_data;
	struct notifier_block notifier;
};

static int tsm_tdi_measurements_locked(struct tsm_dev *tdev)
{
	struct tsm_guest_subsys *gsubsys = (struct tsm_guest_subsys *) tdev->tsm;
	struct tsm_tdi_status tstmp = { 0 };
	struct tsm_tdi *tdi = tsm_tdi_get(tdev->physdev);

	if (!tdi)
		return -EFAULT;

	return gsubsys->ops->tdi_status(tdi, gsubsys->private_data, &tstmp);
}

static int tsm_tdi_validate(struct tsm_tdi *tdi, unsigned featuremask, bool invalidate)
{
	struct tsm_dev *tdev = tdi->tdev;
	struct tsm_guest_subsys *gsubsys = (struct tsm_guest_subsys *) tdev->tsm;
	int ret;

	if (!tdi || !gsubsys->ops->tdi_validate)
		return -EPERM;

	ret = gsubsys->ops->tdi_validate(tdi, featuremask, invalidate, gsubsys->private_data);
	if (ret) {
		tdi->dev.parent->tdi_validated = false;
		dev_err(tdi->dev.parent, "TDI is not validated, ret=%d\n", ret);
	} else {
		tdi->dev.parent->tdi_validated = true;
		dev_info(tdi->dev.parent, "TDI validated\n");
	}

	return ret;
}

//int tsm_tdi_mmio_config(struct tsm_tdi *tdi, u64 start, u64 end, bool tee)
//{
//	struct tsm_dev *tdev = tdi->tdev;
//	struct tsm_guest_subsys *gsubsys = (struct tsm_guest_subsys *) tdev->tsm;
//	int ret;
//
//	if (!tdi || !gsubsys->ops->tdi_mmio_config)
//		return -EPERM;
//
//	ret = gsubsys->ops->tdi_mmio_config(tdi, start, end, tee, gsubsys->private_data);
//
//	return ret;
//}
//EXPORT_SYMBOL_GPL(tsm_tdi_mmio_config);

static int tsm_tdi_status(struct tsm_tdi *tdi, void *private_data, struct tsm_tdi_status *ts)
{
	struct tsm_tdi_status tstmp = { 0 };
	struct tsm_dev *tdev = tdi->tdev;
	struct tsm_guest_subsys *gsubsys = (struct tsm_guest_subsys *) tdev->tsm;
	int ret;

	ret = gsubsys->ops->tdi_status(tdi, private_data, &tstmp);
	if (!ret)
		*ts = tstmp;

	return ret;
}

static ssize_t tsm_tdi_validate_store(struct device *dev, struct device_attribute *attr,
				      const char *buf, size_t count)
{
	struct tsm_tdi *tdi = container_of(dev, struct tsm_tdi, dev);
	unsigned long val;
	ssize_t ret;

	if (kstrtoul(buf, 0, &val) < 0)
		return -EINVAL;

	if (val) {
		ret = tsm_tdi_validate(tdi, TDI_VALIDATE_DMA | TDI_VALIDATE_MMIO, false);
		if (ret)
			return ret;
	} else {
		tsm_tdi_validate(tdi, TDI_VALIDATE_DMA | TDI_VALIDATE_MMIO, true);
	}

	tdi->validated = val;

	return count;
}

static ssize_t tsm_tdi_validate_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_tdi *tdi = container_of(dev, struct tsm_tdi, dev);

	return sysfs_emit(buf, "%u\n", tdi->validated);
}

static DEVICE_ATTR_RW(tsm_tdi_validate);

static char *spdm_algos_to_str(u64 algos, char *buf, size_t len)
{
	size_t n = 0;

	buf[0] = 0;
#define __ALGO(x) do {								\
		if ((n < len) && (algos & (1ULL << (TSM_SPDM_ALGOS_##x))))	\
			n += snprintf(buf + n, len - n, #x" ");			\
	} while (0)

	__ALGO(DHE_SECP256R1);
	__ALGO(DHE_SECP384R1);
	__ALGO(AEAD_AES_128_GCM);
	__ALGO(AEAD_AES_256_GCM);
	__ALGO(ASYM_TPM_ALG_RSASSA_3072);
	__ALGO(ASYM_TPM_ALG_ECDSA_ECC_NIST_P256);
	__ALGO(ASYM_TPM_ALG_ECDSA_ECC_NIST_P384);
	__ALGO(HASH_TPM_ALG_SHA_256);
	__ALGO(HASH_TPM_ALG_SHA_384);
	__ALGO(KEY_SCHED_SPDM_KEY_SCHEDULE);
#undef __ALGO
	return buf;
}

static const char *tdisp_state_to_str(enum tsm_tdisp_state state)
{
	switch (state) {
#define __ST(x) case TDISP_STATE_##x: return #x
	__ST(CONFIG_UNLOCKED);
	__ST(CONFIG_LOCKED);
	__ST(RUN);
	__ST(ERROR);
#undef __ST
	default: return "unknown";
	}
}

static ssize_t tsm_tdi_status_user_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_tdi *tdi = container_of(dev, struct tsm_tdi, dev);
	struct tsm_dev *tdev = tdi->tdev;
	struct tsm_guest_subsys *gsubsys = (struct tsm_guest_subsys *) tdev->tsm;
	struct tsm_tdi_status ts = { 0 };
	char algos[256] = "";
	unsigned int n, m;
	int ret;

	ret = tsm_tdi_status(tdi, gsubsys->private_data, &ts);
	if (ret < 0)
		return sysfs_emit(buf, "ret=%d\n\n", ret);

	if (!ts.valid)
		return sysfs_emit(buf, "ret=%d\nstate=%d:%s\n",
				  ret, ts.state, tdisp_state_to_str(ts.state));

	n = snprintf(buf, PAGE_SIZE,
		     "ret=%d\n"
		     "state=%d:%s\n"
		     "meas_digest_fresh=%x\n"
		     "meas_digest_valid=%x\n"
		     "all_request_redirect=%x\n"
		     "bind_p2p=%x\n"
		     "lock_msix=%x\n"
		     "no_fw_update=%x\n"
		     "cache_line_size=%d\n"
		     "algos=%#llx:%s\n"
		     "report_counter=%lld\n"
		     ,
		     ret,
		     ts.state, tdisp_state_to_str(ts.state),
		     ts.meas_digest_fresh,
		     ts.meas_digest_valid,
		     ts.all_request_redirect,
		     ts.bind_p2p,
		     ts.lock_msix,
		     ts.no_fw_update,
		     ts.cache_line_size,
		     ts.spdm_algos, spdm_algos_to_str(ts.spdm_algos, algos, sizeof(algos) - 1),
		     ts.intf_report_counter);

	n += snprintf(buf + n, PAGE_SIZE - n, "Certs digest: ");
	m = hex_dump_to_buffer(ts.certs_digest, sizeof(ts.certs_digest), 32, 1,
			       buf + n, PAGE_SIZE - n, false);
	n += min(PAGE_SIZE - n, m);
	n += snprintf(buf + n, PAGE_SIZE - n, "...\nMeasurements digest: ");
	m = hex_dump_to_buffer(ts.meas_digest, sizeof(ts.meas_digest), 32, 1,
			       buf + n, PAGE_SIZE - n, false);
	n += min(PAGE_SIZE - n, m);
	n += snprintf(buf + n, PAGE_SIZE - n, "...\nInterface report digest: ");
	m = hex_dump_to_buffer(ts.interface_report_digest, sizeof(ts.interface_report_digest),
			       32, 1, buf + n, PAGE_SIZE - n, false);
	n += min(PAGE_SIZE - n, m);
	n += snprintf(buf + n, PAGE_SIZE - n, "...\n");

	return n;
}

static DEVICE_ATTR_RO(tsm_tdi_status_user);

static ssize_t tsm_tdi_status_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_tdi *tdi = container_of(dev, struct tsm_tdi, dev);
	struct tsm_dev *tdev = tdi->tdev;
	struct tsm_guest_subsys *gsubsys = (struct tsm_guest_subsys *) tdev->tsm;
	struct tsm_tdi_status ts = { 0 };
	u8 state;
	int ret;

	ret = tsm_tdi_status(tdi, gsubsys->private_data, &ts);
	if (ret)
		return ret;

	state = ts.state;
	memcpy(buf, &state, sizeof(state));

	return sizeof(state);
}

static DEVICE_ATTR_RO(tsm_tdi_status);

static struct attribute *tdi_attrs[] = {
	&dev_attr_tsm_tdi_validate.attr,
	&dev_attr_tsm_tdi_status_user.attr,
	&dev_attr_tsm_tdi_status.attr,
	NULL,
};

static const struct attribute_group tdi_group = {
	.attrs = tdi_attrs,
};

/* In case BUS_NOTIFY_PCI_BUS_MASTER is no good, a driver can call pci_dev_tdi_validate() */
int pci_dev_tdi_validate(struct pci_dev *pdev, bool invalidate)
{
	struct tsm_tdi *tdi = tsm_tdi_get(&pdev->dev);
	int ret;

	if (!tdi)
		return -EFAULT;

	ret = tsm_tdi_validate(tdi, TDI_VALIDATE_DMA | TDI_VALIDATE_MMIO, invalidate);

	tsm_tdi_put(tdi);
	return ret;
}
EXPORT_SYMBOL_GPL(pci_dev_tdi_validate);

static int tsm_guest_pci_bus_notifier(struct notifier_block *nb, unsigned long action, void *data)
{
	switch (action) {
	case BUS_NOTIFY_UNBOUND_DRIVER:
		pci_dev_tdi_validate(to_pci_dev(data), true);
		break;
        case BUS_NOTIFY_PCI_BUS_MASTER:
                pci_dev_tdi_validate(to_pci_dev(data), false);
                break;
	}

	return NOTIFY_OK;
}

struct tsm_guest_subsys *tsm_guest_register(struct device *parent,
					    struct tsm_vm_ops *vmops,
					    void *private_data)
{
	struct tsm_subsys *subsys = tsm_register(parent, sizeof(struct tsm_guest_subsys),
						 NULL, &tdi_group,
						 tsm_tdi_measurements_locked);
	struct tsm_guest_subsys *gsubsys;

	gsubsys = (struct tsm_guest_subsys *) subsys;

	if (IS_ERR(gsubsys))
		return gsubsys;

	gsubsys->ops = vmops;
	gsubsys->private_data = private_data;

	gsubsys->notifier.notifier_call = tsm_guest_pci_bus_notifier;
	bus_register_notifier(&pci_bus_type, &gsubsys->notifier);

	return gsubsys;
}
EXPORT_SYMBOL_GPL(tsm_guest_register);

void tsm_guest_unregister(struct tsm_guest_subsys *gsubsys)
{
	bus_unregister_notifier(&pci_bus_type, &gsubsys->notifier);
	tsm_unregister(&gsubsys->base);
}
EXPORT_SYMBOL_GPL(tsm_guest_unregister);

static int __init tsm_init(void)
{
	int ret = 0;

	pr_info(DRIVER_DESC " version: " DRIVER_VERSION "\n");

	return ret;
}

static void __exit tsm_exit(void)
{
	pr_info(DRIVER_DESC " version: " DRIVER_VERSION " shutdown\n");
}

module_init(tsm_init);
module_exit(tsm_exit);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
