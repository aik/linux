// SPDX-License-Identifier: GPL-2.0-only

#include <linux/module.h>
#include <linux/tsm.h>
#include <linux/file.h>
#include <linux/kvm_host.h>

#define DRIVER_VERSION	"0.1"
#define DRIVER_AUTHOR	"aik@amd.com"
#define DRIVER_DESC	"TSM host library"

struct tsm_host_subsys {
	struct tsm_subsys base;
	struct tsm_hv_ops *ops;
	void *private_data;
};

static int tsm_dev_connect(struct tsm_dev *tdev)
{
	struct tsm_host_subsys *hsubsys = (struct tsm_host_subsys *) tdev->tsm;
	int ret;

	if (WARN_ON(!hsubsys->ops->dev_connect))
		return -EPERM;

	if (WARN_ON(!tdev->tsm_bus))
		return -EPERM;

	mutex_lock(&tdev->spdm_mutex);
	while (1) {
		ret = hsubsys->ops->dev_connect(tdev, hsubsys->private_data);
		if (ret <= 0)
			break;

		ret = tdev->tsm_bus->ops->spdm_forward(&tdev->spdm, ret);
		if (ret < 0)
			break;
	}
	mutex_unlock(&tdev->spdm_mutex);

	tdev->connected = (ret == 0);

	return ret;
}

static int tsm_dev_reclaim(struct tsm_dev *tdev)
{
	struct tsm_host_subsys *hsubsys = (struct tsm_host_subsys *) tdev->tsm;
	int ret;

	if (WARN_ON(!hsubsys->ops->dev_disconnect))
		return -EPERM;

	/* Do not disconnect with active TDIs */
	if (tdev->bound)
		return -EBUSY;

	mutex_lock(&tdev->spdm_mutex);
	while (1) {
		ret = hsubsys->ops->dev_disconnect(tdev);
		if (ret <= 0)
			break;

		ret = tdev->tsm_bus->ops->spdm_forward(&tdev->spdm, ret);
		if (ret < 0)
			break;
	}
	mutex_unlock(&tdev->spdm_mutex);

	if (!ret)
		tdev->connected = false;

	return ret;
}

static int tsm_dev_status(struct tsm_dev *tdev, struct tsm_dev_status *s)
{
	struct tsm_host_subsys *hsubsys = (struct tsm_host_subsys *) tdev->tsm;

	if (WARN_ON(!hsubsys->ops->dev_status))
		return -EPERM;

	return hsubsys->ops->dev_status(tdev, s);
}

static int tsm_tdi_measurements_locked(struct tsm_dev *tdev)
{
	struct tsm_host_subsys *hsubsys = (struct tsm_host_subsys *) tdev->tsm;
	int ret;

	while (1) {
		ret = hsubsys->ops->dev_measurements(tdev);
		if (ret <= 0)
			break;

		ret = tdev->tsm_bus->ops->spdm_forward(&tdev->spdm, ret);
		if (ret < 0)
			break;
	}

	return ret;
}

static void tsm_tdi_reclaim(struct tsm_tdi *tdi)
{
	struct tsm_dev *tdev = tdi->tdev;
	struct tsm_host_subsys *hsubsys = (struct tsm_host_subsys *) tdev->tsm;
	int ret;

	if (WARN_ON(!hsubsys->ops->tdi_unbind))
		return;

	mutex_lock(&tdi->tdev->spdm_mutex);
	while (1) {
		ret = hsubsys->ops->tdi_unbind(tdi);
		if (ret <= 0)
			break;

		ret = tdi->tdev->tsm_bus->ops->spdm_forward(&tdi->tdev->spdm, ret);
		if (ret < 0)
			break;
	}
	mutex_unlock(&tdi->tdev->spdm_mutex);
}

static int tsm_tdi_status(struct tsm_tdi *tdi, void *private_data, struct tsm_tdi_status *ts)
{
	struct tsm_tdi_status tstmp = { 0 };
	struct tsm_dev *tdev = tdi->tdev;
	struct tsm_host_subsys *hsubsys = (struct tsm_host_subsys *) tdev->tsm;
	int ret;

	mutex_lock(&tdi->tdev->spdm_mutex);
	while (1) {
		ret = hsubsys->ops->tdi_status(tdi, &tstmp);
		if (ret <= 0)
			break;

		ret = tdi->tdev->tsm_bus->ops->spdm_forward(&tdi->tdev->spdm, ret);
		if (ret < 0)
			break;
	}
	mutex_unlock(&tdi->tdev->spdm_mutex);

	if (!ret)
		*ts = tstmp;

	return ret;
}

static ssize_t tsm_cert_slot_store(struct device *dev, struct device_attribute *attr,
				   const char *buf, size_t count)
{
	struct tsm_dev *tdev = container_of(dev, struct tsm_dev, dev);
	ssize_t ret = count;
	unsigned long val;

	if (kstrtoul(buf, 0, &val) < 0)
		ret = -EINVAL;
	else
		tdev->cert_slot = val;

	return ret;
}

static ssize_t tsm_cert_slot_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_dev *tdev = container_of(dev, struct tsm_dev, dev);
	ssize_t ret = sysfs_emit(buf, "%u\n", tdev->cert_slot);

	return ret;
}

static DEVICE_ATTR_RW(tsm_cert_slot);

static ssize_t tsm_dev_connect_store(struct device *dev, struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct tsm_dev *tdev = container_of(dev, struct tsm_dev, dev);
	unsigned long val;
	ssize_t ret = -EIO;

	if (kstrtoul(buf, 0, &val) < 0)
		ret = -EINVAL;
	else if (val && !tdev->connected)
		ret = tsm_dev_connect(tdev);
	else if (!val && tdev->connected)
		ret = tsm_dev_reclaim(tdev);

	if (!ret)
		ret = count;

	return ret;
}

static ssize_t tsm_dev_connect_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_dev *tdev = container_of(dev, struct tsm_dev, dev);
	ssize_t ret = sysfs_emit(buf, "%u\n", tdev->connected);

	return ret;
}

static DEVICE_ATTR_RW(tsm_dev_connect);

static ssize_t tsm_dev_status_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_dev *tdev = container_of(dev, struct tsm_dev, dev);
	struct tsm_dev_status s = { 0 };
	int ret = tsm_dev_status(tdev, &s);
	ssize_t ret1;

	ret1 = sysfs_emit(buf, "ret=%d\n"
			  "ctx_state=%x\n"
			  "tc_mask=%x\n"
			  "certs_slot=%x\n"
			  "device_id=%x:%x.%d\n"
			  "segment_id=%x\n"
			  "no_fw_update=%x\n",
			  ret,
			  s.ctx_state,
			  s.tc_mask,
			  s.certs_slot,
			  (s.device_id >> 8) & 0xff,
			  (s.device_id >> 3) & 0x1f,
			  s.device_id & 0x07,
			  s.segment_id,
			  s.no_fw_update);

	tsm_dev_put(tdev);
	return ret1;
}

static DEVICE_ATTR_RO(tsm_dev_status);

static struct attribute *host_dev_attrs[] = {
	&dev_attr_tsm_cert_slot.attr,
	&dev_attr_tsm_dev_connect.attr,
	&dev_attr_tsm_dev_status.attr,
	NULL,
};
static const struct attribute_group host_dev_group = {
	.attrs = host_dev_attrs,
};

static ssize_t tsm_tdi_bind_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_tdi *tdi = container_of(dev, struct tsm_tdi, dev);

	if (!tdi->kvm)
		return sysfs_emit(buf, "not bound\n");

	return sysfs_emit(buf, "VM=%p BDFn=%x:%x.%d\n",
			  tdi->kvm,
			  (tdi->guest_rid >> 8) & 0xff,
			  (tdi->guest_rid >> 3) & 0x1f,
			  tdi->guest_rid & 0x07);
}

static DEVICE_ATTR_RO(tsm_tdi_bind);

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
	struct tsm_host_subsys *hsubsys = (struct tsm_host_subsys *) tdev->tsm;
	struct tsm_tdi_status ts = { 0 };
	char algos[256] = "";
	unsigned int n, m;
	int ret;

	ret = tsm_tdi_status(tdi, hsubsys->private_data, &ts);
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
	struct tsm_host_subsys *hsubsys = (struct tsm_host_subsys *) tdev->tsm;
	struct tsm_tdi_status ts = { 0 };
	u8 state;
	int ret;

	ret = tsm_tdi_status(tdi, hsubsys->private_data, &ts);
	if (ret)
		return ret;

	state = ts.state;
	memcpy(buf, &state, sizeof(state));

	return sizeof(state);
}

static DEVICE_ATTR_RO(tsm_tdi_status);

static struct attribute *host_tdi_attrs[] = {
	&dev_attr_tsm_tdi_bind.attr,
	&dev_attr_tsm_tdi_status_user.attr,
	&dev_attr_tsm_tdi_status.attr,
	NULL,
};

static const struct attribute_group host_tdi_group = {
	.attrs = host_tdi_attrs,
};

int tsm_tdi_bind(struct tsm_tdi *tdi, u32 guest_rid, int kvmfd)
{
	struct tsm_dev *tdev = tdi->tdev;
	struct tsm_host_subsys *hsubsys = (struct tsm_host_subsys *) tdev->tsm;
	struct fd f = fdget(kvmfd);
	struct kvm *kvm;
	u64 vmid;
	int ret;

	if (!fd_file(f))
		return -EBADF;

	if (!file_is_kvm(fd_file(f))) {
		ret = -EBADF;
		goto out_fput;
	}

	kvm = fd_file(f)->private_data;
	if (!kvm || !kvm_get_kvm_safe(kvm)) {
		ret = -EFAULT;
		goto out_fput;
	}

	vmid = kvm_arch_tsm_get_vmid(kvm);
	if (!vmid) {
		ret = -EFAULT;
		goto out_kvm_put;
	}

	if (WARN_ON(!hsubsys->ops->tdi_bind)) {
		ret = -EPERM;
		goto out_kvm_put;
	}

	if (!tdev->connected) {
		ret = -EIO;
		goto out_kvm_put;
	}

	mutex_lock(&tdi->tdev->spdm_mutex);
	while (1) {
		ret = hsubsys->ops->tdi_bind(tdi, guest_rid, vmid);
		if (ret < 0)
			break;

		if (!ret)
			break;

		ret = tdi->tdev->tsm_bus->ops->spdm_forward(&tdi->tdev->spdm, ret);
		if (ret < 0)
			break;
	}
	mutex_unlock(&tdi->tdev->spdm_mutex);

	if (ret) {
		tsm_tdi_unbind(tdi);
		goto out_kvm_put;
	}

	tdi->guest_rid = guest_rid;
	tdi->kvm = kvm;
	++tdi->tdev->bound;
	goto out_fput;

out_kvm_put:
	kvm_put_kvm(kvm);
out_fput:
	fdput(f);
	return ret;
}
EXPORT_SYMBOL_GPL(tsm_tdi_bind);

void tsm_tdi_unbind(struct tsm_tdi *tdi)
{
	if (tdi->kvm) {
		tsm_tdi_reclaim(tdi);
		--tdi->tdev->bound;
		kvm_put_kvm(tdi->kvm);
		tdi->kvm = NULL;
	}

	tdi->guest_rid = 0;
	tdi->dev.parent->tdi_enabled = false;
}
EXPORT_SYMBOL_GPL(tsm_tdi_unbind);

int tsm_guest_request(struct tsm_tdi *tdi, u8 __user *req, size_t reqlen, u8 __user *res, size_t reslen,
		      int *fw_err)
{
	struct tsm_dev *tdev = tdi->tdev;
	struct tsm_host_subsys *hsubsys = (struct tsm_host_subsys *) tdev->tsm;
	int ret;

	if (!hsubsys->ops->guest_request)
		return -EPERM;

	mutex_lock(&tdi->tdev->spdm_mutex);
	while (1) {
		ret = hsubsys->ops->guest_request(tdi, req, reqlen, res, reslen, fw_err);
		if (ret <= 0)
			break;

		ret = tdi->tdev->tsm_bus->ops->spdm_forward(&tdi->tdev->spdm, ret);
		if (ret < 0)
			break;
	}

	mutex_unlock(&tdi->tdev->spdm_mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(tsm_guest_request);

struct tsm_host_subsys *tsm_host_register(struct device *parent,
					  struct tsm_hv_ops *hvops,
					  void *private_data)
{
	struct tsm_subsys *subsys = tsm_register(parent, sizeof(struct tsm_host_subsys),
						 &host_dev_group, &host_tdi_group,
						 tsm_tdi_measurements_locked);
	struct tsm_host_subsys *hsubsys;

	hsubsys = (struct tsm_host_subsys *) subsys;

	if (IS_ERR(hsubsys))
		return hsubsys;

	hsubsys->ops = hvops;
	hsubsys->private_data = private_data;

	return hsubsys;
}
EXPORT_SYMBOL_GPL(tsm_host_register);

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
