// SPDX-License-Identifier: GPL-2.0-only

#include <linux/module.h>
#include <linux/tsm.h>

#define DRIVER_VERSION	"0.1"
#define DRIVER_AUTHOR	"aik@amd.com"
#define DRIVER_DESC	"TSM library"

static struct class *tsm_class, *tdev_class, *tdi_class;

/* snprintf does not check for the size, hence this wrapper */
static int tsmprint(char *buf, size_t size, const char *fmt, ...)
{
	va_list args;
	size_t i;

	if (!size)
		return 0;

	va_start(args, fmt);
	i = vsnprintf(buf, size, fmt, args);
	va_end(args);

	return min(i, size);
}

struct tsm_blob *tsm_blob_new(void *data, size_t len)
{
	struct tsm_blob *b;

	if (!len || !data)
		return NULL;

	b = kzalloc(sizeof(*b) + len, GFP_KERNEL);
	if (!b)
		return NULL;

	b->data = (void *)b + sizeof(*b);
	b->len = len;
	memcpy(b->data, data, len);

	return b;
}
EXPORT_SYMBOL_GPL(tsm_blob_new);

static int match_class(struct device *dev, const void *data)
{
	return dev->class == data;
}

struct tsm_dev *tsm_dev_get(struct device *parent)
{
	struct device *dev = device_find_child(parent, tdev_class, match_class);

	if (!dev) {
		dev = device_find_child(parent, tdi_class, match_class);
		if (dev) {
			struct tsm_tdi *tdi = container_of(dev, struct tsm_tdi, dev);

			dev = &tdi->tdev->dev;
		}
	}

	if (!dev)
		return NULL;

	/* device_find_child() does get_device() */
	return container_of(dev, struct tsm_dev, dev);
}
EXPORT_SYMBOL_GPL(tsm_dev_get);

void tsm_dev_put(struct tsm_dev *tdev)
{
	put_device(&tdev->dev);
}
EXPORT_SYMBOL_GPL(tsm_dev_put);

struct tsm_tdi *tsm_tdi_get(struct device *parent)
{
	struct device *dev = device_find_child(parent, tdi_class, match_class);

	if (!dev)
		return NULL;

	/* device_find_child() does get_device() */
	return container_of(dev, struct tsm_tdi, dev);
}
EXPORT_SYMBOL_GPL(tsm_tdi_get);

void tsm_tdi_put(struct tsm_tdi *tdi)
{
	put_device(&tdi->dev);
}
EXPORT_SYMBOL_GPL(tsm_tdi_put);

static ssize_t blob_show(struct tsm_blob *blob, char *buf)
{
	unsigned int n, m;
	size_t sz = PAGE_SIZE - 1;

	if (!blob)
		return sysfs_emit(buf, "none\n");

	n = tsmprint(buf, sz, "%lu %u\n", blob->len);
	m = hex_dump_to_buffer(blob->data, blob->len, 32, 1,
			       buf + n, sz - n, false);
	n += min(sz - n, m);
	n += tsmprint(buf + n, sz - n, "...\n");
	return n;
}

static ssize_t tsm_certs_gen(struct tsm_blob *certs, char *buf, size_t len)
{
	struct spdm_certchain_block_header *h;
	unsigned int n = 0, m, i, off, o2;
	u8 *p;

	for (i = 0, off = 0; off < certs->len; ++i) {
		h = (struct spdm_certchain_block_header *) ((u8 *)certs->data + off);
		if (WARN_ON_ONCE(h->length > certs->len - off))
			return 0;

		n += tsmprint(buf + n, len - n, "[%d] len=%d:\n", i, h->length);

		for (o2 = 0, p = (u8 *)&h[1]; o2 < h->length; o2 += 32) {
			m = hex_dump_to_buffer(p + o2, h->length - o2, 32, 1,
					       buf + n, len - n, true);
			n += min(len - n, m);
			n += tsmprint(buf + n, len - n, "\n");
		}

		off += h->length; /* Includes the header */
	}

	return n;
}

static ssize_t tsm_certs_user_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_dev *tdev = container_of(dev, struct tsm_dev, dev);
	ssize_t n;

	mutex_lock(&tdev->spdm_mutex);
	if (!tdev->certs) {
		n = sysfs_emit(buf, "none\n");
	} else {
		n = tsm_certs_gen(tdev->certs, buf, PAGE_SIZE - 1);
		if (!n)
			n = blob_show(tdev->certs, buf);
	}
	mutex_unlock(&tdev->spdm_mutex);

	return n;
}

static DEVICE_ATTR_RO(tsm_certs_user);

static ssize_t tsm_certs_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_dev *tdev = container_of(dev, struct tsm_dev, dev);
	ssize_t n = 0;

	mutex_lock(&tdev->spdm_mutex);
	if (tdev->certs) {
		n = min(PAGE_SIZE, tdev->certs->len);
		memcpy(buf, tdev->certs->data, n);
	}
	mutex_unlock(&tdev->spdm_mutex);

	return n;
}

static DEVICE_ATTR_RO(tsm_certs);

static ssize_t tsm_meas_gen(struct tsm_blob *meas, char *buf, size_t len)
{
	static const char * const whats[] = {
		"ImmuROM", "MutFW", "HWCfg", "FWCfg",
		"MeasMft", "DevDbg", "MutFWVer", "MutFWVerSec"
	};
	struct dmtf_measurement_block_device_mode *dm;
	struct spdm_measurement_block_header *mb;
	struct dmtf_measurement_block_header *h;
	unsigned int n, m, off, what;
	bool dmtf;

	n = tsmprint(buf, len, "Len=%d\n", meas->len);
	for (off = 0; off < meas->len; ) {
		mb = (struct spdm_measurement_block_header *)(((u8 *) meas->data) + off);
		dmtf = mb->spec & 1;

		n += tsmprint(buf + n, len - n, "#%d (%d) ", mb->index, mb->size);
		if (dmtf) {
			h = (void *) &mb[1];

			if (WARN_ON_ONCE(mb->size != (sizeof(*h) + h->size)))
				return -EINVAL;

			what = h->type & 0x7F;
			n += tsmprint(buf + n, len - n, "%x=[%s %s]: ",
				h->type,
				h->type & 0x80 ? "digest" : "raw",
				what < ARRAY_SIZE(whats) ? whats[what] : "reserved");

			if (what == 5) {
				dm = (struct dmtf_measurement_block_device_mode *) &h[1];
				n += tsmprint(buf + n, len - n, " %x %x %x %x",
					      dm->opmode_cap, dm->opmode_sta,
					      dm->devmode_cap, dm->devmode_sta);
			} else {
				m = hex_dump_to_buffer(&h[1], h->size, 32, 1,
						       buf + n, len - n, false);
				n += min(len - n, m);
			}
		} else {
			n += tsmprint(buf + n, len - n, "spec=%x: ", mb->spec);
			m = hex_dump_to_buffer(&mb[1], min(len - off, mb->size),
					       32, 1, buf + n, len - n, false);
			n += min(len - n, m);
		}

		off += sizeof(*mb) + mb->size;
		n += tsmprint(buf + n, len - n, "...\n");
	}

	return n;
}

static ssize_t tsm_meas_user_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_dev *tdev = container_of(dev, struct tsm_dev, dev);
	ssize_t n;

	mutex_lock(&tdev->spdm_mutex);
	n = tdev->tsm->update_measurements(tdev);

	if (!tdev->meas || n) {
		n = sysfs_emit(buf, "none\n");
	} else {
		n = tsm_meas_gen(tdev->meas, buf, PAGE_SIZE);
		if (!n)
			n = blob_show(tdev->meas, buf);
	}
	mutex_unlock(&tdev->spdm_mutex);

	return n;
}

static DEVICE_ATTR_RO(tsm_meas_user);

static ssize_t tsm_meas_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_dev *tdev = container_of(dev, struct tsm_dev, dev);
	ssize_t n = 0;

	mutex_lock(&tdev->spdm_mutex);
	n = tdev->tsm->update_measurements(tdev);
	if (!n && tdev->meas) {
		n = MIN(PAGE_SIZE, tdev->meas->len);
		memcpy(buf, tdev->meas->data, n);
	}
	mutex_unlock(&tdev->spdm_mutex);

	return n;
}

static DEVICE_ATTR_RO(tsm_meas);

static ssize_t tsm_nonce_store(struct device *dev, struct device_attribute *attr,
			       const char *buf, size_t count)
{
	struct tsm_dev *tdev = tsm_dev_get(dev);

	if (!tdev)
		return -EFAULT;

	tdev->nonce_len = min(count, sizeof(tdev->nonce));
	mutex_lock(&tdev->spdm_mutex);
	memcpy(tdev->nonce, buf, tdev->nonce_len);
	mutex_unlock(&tdev->spdm_mutex);
	tsm_dev_put(tdev);

	return tdev->nonce_len;
}

static ssize_t tsm_nonce_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_dev *tdev = tsm_dev_get(dev);

	if (!tdev)
		return -EFAULT;

	mutex_lock(&tdev->spdm_mutex);
	memcpy(buf, tdev->nonce, tdev->nonce_len);
	mutex_unlock(&tdev->spdm_mutex);
	tsm_dev_put(tdev);

	return tdev->nonce_len;
}

static DEVICE_ATTR_RW(tsm_nonce);

static struct attribute *dev_attrs[] = {
	&dev_attr_tsm_certs_user.attr,
	&dev_attr_tsm_meas_user.attr,
	&dev_attr_tsm_certs.attr,
	&dev_attr_tsm_meas.attr,
	&dev_attr_tsm_nonce.attr,
	NULL,
};
static const struct attribute_group dev_group = {
	.attrs = dev_attrs,
};


ssize_t tsm_report_gen(struct tsm_blob *report, char *buf, size_t len)
{
	struct tdi_report_header *h = TDI_REPORT_HDR(report);
	struct tdi_report_mmio_range *mr = TDI_REPORT_MR_OFF(report);
	struct tdi_report_footer *f = TDI_REPORT_FTR(report);
	unsigned int n, m, i;

	n = tsmprint(buf, len,
		     "no_fw_update=%u\ndma_no_pasid=%u\ndma_pasid=%u\nats=%u\nprs=%u\n",
		     FIELD_GET(TSM_TDI_REPORT_NO_FW_UPDATE, h->interface_info),
		     FIELD_GET(TSM_TDI_REPORT_DMA_NO_PASID, h->interface_info),
		     FIELD_GET(TSM_TDI_REPORT_DMA_PASID, h->interface_info),
		     FIELD_GET(TSM_TDI_REPORT_ATS,  h->interface_info),
		     FIELD_GET(TSM_TDI_REPORT_PRS, h->interface_info));
	n += tsmprint(buf + n, len - n,
		      "msi_x_message_control=%#04x\nlnr_control=%#04x\n",
		      h->msi_x_message_control, h->lnr_control);
	n += tsmprint(buf + n, len - n, "tph_control=%#08x\n", h->tph_control);

	for (i = 0; i < h->mmio_range_count; ++i) {
#define FIELD_CH(m, r) (FIELD_GET((m), (r)) ? '+':'-')
		n += tsmprint(buf + n, len - n,
			      "[%i] #%lu %#016llx +%#lx MSIX%c PBA%c NonTEE%c Upd%c\n",
			      i,
			      FIELD_GET(TSM_TDI_REPORT_MMIO_RANGE_ID, mr[i].range_attributes),
			      mr[i].first_page << PAGE_SHIFT,
			      (unsigned long) mr[i].num << PAGE_SHIFT,
			      FIELD_CH(TSM_TDI_REPORT_MMIO_MSIX_TABLE, mr[i].range_attributes),
			      FIELD_CH(TSM_TDI_REPORT_MMIO_PBA, mr[i].range_attributes),
			      FIELD_CH(TSM_TDI_REPORT_MMIO_IS_NON_TEE, mr[i].range_attributes),
			      FIELD_CH(TSM_TDI_REPORT_MMIO_IS_UPDATABLE, mr[i].range_attributes));

		if (FIELD_GET(TSM_TDI_REPORT_MMIO_RESERVED, mr[i].range_attributes))
			n += tsmprint(buf + n, len - n,
				      "[%i] WARN: reserved=%#x\n", i, mr[i].range_attributes);
	}

	if (f->device_specific_info_len) {
		unsigned int num = report->len - ((u8 *)f->device_specific_info - (u8 *)h);

		num = min(num, f->device_specific_info_len);
		n += tsmprint(buf + n, len - n, "DevSp len=%d%s",
			f->device_specific_info_len, num ? ": " : "");
		m = hex_dump_to_buffer(f->device_specific_info, num, 32, 1,
				       buf + n, len - n, false);
		n += min(len - n, m);
		n += tsmprint(buf + n, len - n, m ? "\n" : "...\n");
	}

	return n;
}
EXPORT_SYMBOL_GPL(tsm_report_gen);

static ssize_t tsm_report_user_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_tdi *tdi = container_of(dev, struct tsm_tdi, dev);
	ssize_t n;

	mutex_lock(&tdi->tdev->spdm_mutex);
	if (!tdi->report) {
		n = sysfs_emit(buf, "none\n");
	} else {
		n = tsm_report_gen(tdi->report, buf, PAGE_SIZE - 1);
		if (!n)
			n = blob_show(tdi->report, buf);
	}
	mutex_unlock(&tdi->tdev->spdm_mutex);

	return n;
}

static DEVICE_ATTR_RO(tsm_report_user);

static ssize_t tsm_report_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_tdi *tdi = container_of(dev, struct tsm_tdi, dev);
	ssize_t n = 0;

	mutex_lock(&tdi->tdev->spdm_mutex);
	if (tdi->report) {
		n = min(PAGE_SIZE, tdi->report->len);
		memcpy(buf, tdi->report->data, n);
	}
	mutex_unlock(&tdi->tdev->spdm_mutex);

	return n;
}
static DEVICE_ATTR_RO(tsm_report);

static struct attribute *tdi_attrs[] = {
	&dev_attr_tsm_report_user.attr,
	&dev_attr_tsm_report.attr,
	NULL,
};

static const struct attribute_group tdi_group = {
	.attrs = tdi_attrs,
};

int tsm_tdi_init(struct tsm_dev *tdev, struct device *parent)
{
	struct tsm_tdi *tdi;
	struct device *dev;
	int ret = 0;

	dev_info(parent, "Initializing tdi\n");
	if (!tdev)
		return -ENODEV;

	tdi = kzalloc(sizeof(*tdi), GFP_KERNEL);
	if (!tdi)
		return -ENOMEM;

        dev = &tdi->dev;
	dev->groups = tdev->tsm->tdi_groups;
        dev->parent = parent;
        dev->class = tdi_class;
	dev_set_name(dev, "tdi:%s", dev_name(parent));
        device_initialize(dev);
	ret = device_add(dev);
	if (ret)
		return ret;

	ret = sysfs_create_link(&parent->kobj, &tdev->dev.kobj, "tsm_dev");
	if (ret)
		goto free_exit;

	tdi->tdev = tdev;

	return 0;

free_exit:
	kfree(tdi);

	return ret;
}
EXPORT_SYMBOL_GPL(tsm_tdi_init);

void tsm_tdi_free(struct tsm_tdi *tdi)
{
	struct device *parent = tdi->dev.parent;

	dev_notice(&tdi->dev, "Freeing tdi\n");
	sysfs_remove_link(&parent->kobj, "tsm_dev");
	device_unregister(&tdi->dev);
}
EXPORT_SYMBOL_GPL(tsm_tdi_free);

int tsm_dev_init(struct tsm_bus_subsys *tsm_bus, struct device *parent,
		 size_t busdatalen, struct tsm_dev **ptdev)
{
	struct tsm_dev *tdev;
	struct device *dev;
	int ret = 0;

	dev_info(parent, "Initializing tdev\n");
	tdev = kzalloc(sizeof(*tdev) + busdatalen, GFP_KERNEL);
	if (!tdev)
		return -ENOMEM;

	tdev->physdev = get_device(parent);
	mutex_init(&tdev->spdm_mutex);

	tdev->tsm = tsm_bus->tsm;
	tdev->tsm_bus = tsm_bus;

	dev = &tdev->dev;
	dev->groups = tdev->tsm->tdev_groups;
	dev->parent = parent;
	dev->class = tdev_class;
	dev_set_name(dev, "tdev:%s", dev_name(parent));
	device_initialize(dev);
	ret = device_add(dev);

	get_device(dev);
	*ptdev = tdev;
	return 0;
}
EXPORT_SYMBOL_GPL(tsm_dev_init);

void tsm_dev_free(struct tsm_dev *tdev)
{
	dev_notice(&tdev->dev, "Freeing tdevice\n");
	device_unregister(&tdev->dev);
}
EXPORT_SYMBOL_GPL(tsm_dev_free);

int tsm_create_link(struct tsm_subsys *tsm, struct device *dev, const char *name)
{
	return sysfs_create_link(&tsm->dev.kobj, &dev->kobj, name);
}
EXPORT_SYMBOL_GPL(tsm_create_link);

void tsm_remove_link(struct tsm_subsys *tsm, const char *name)
{
	sysfs_remove_link(&tsm->dev.kobj, name);
}
EXPORT_SYMBOL_GPL(tsm_remove_link);

static struct tsm_subsys *alloc_tsm_subsys(struct device *parent, size_t size)
{
	struct tsm_subsys *subsys;
        struct device *dev;

	if (WARN_ON_ONCE(size < sizeof(*subsys)))
		return ERR_PTR(-EINVAL);

	subsys = kzalloc(size, GFP_KERNEL);
        if (!subsys)
                return ERR_PTR(-ENOMEM);

        dev = &subsys->dev;
        dev->parent = parent;
        dev->class = tsm_class;
        device_initialize(dev);
        return subsys;
}

struct tsm_subsys *tsm_register(struct device *parent, size_t size,
				const struct attribute_group *tdev_ag,
				const struct attribute_group *tdi_ag,
				int (*update_measurements)(struct tsm_dev *tdev))
{
	struct tsm_subsys *subsys = alloc_tsm_subsys(parent, size);
	struct device *dev;
	int rc;

	if (IS_ERR(subsys))
		return subsys;

	dev = &subsys->dev;
	rc = dev_set_name(dev, "tsm0");
	if (rc)
		return ERR_PTR(rc);

	rc = device_add(dev);
	if (rc)
		return ERR_PTR(rc);

	subsys->tdev_groups[0] = &dev_group;
	subsys->tdev_groups[1] = tdev_ag;
	subsys->tdi_groups[0] = &tdi_group;
	subsys->tdi_groups[1] = tdi_ag;
	subsys->update_measurements = update_measurements;

	return subsys;
}
EXPORT_SYMBOL_GPL(tsm_register);

void tsm_unregister(struct tsm_subsys *subsys)
{
        device_unregister(&subsys->dev);
}
EXPORT_SYMBOL_GPL(tsm_unregister);

static void tsm_release(struct device *dev)
{
        struct tsm_subsys *tsm = container_of(dev, typeof(*tsm), dev);

	dev_info(&tsm->dev, "Releasing TSM\n");
        kfree(tsm);
}

static void tdev_release(struct device *dev)
{
        struct tsm_dev *tdev = container_of(dev, typeof(*tdev), dev);

	dev_info(&tdev->dev, "Releasing %s TDEV\n",
		 tdev->connected ? "connected":"disconnected");
	pr_err("___K___ %s %u: FIXME: call tsm_dev_reclaim\n", __func__, __LINE__);
	kfree(tdev);
}

static void tdi_release(struct device *dev)
{
        struct tsm_tdi *tdi = container_of(dev, typeof(*tdi), dev);

	dev_info(&tdi->dev, "Releasing %s TDI\n", tdi->kvm ? "bound" : "unbound");
	sysfs_remove_link(&tdi->dev.parent->kobj, "tsm_dev");
	kfree(tdi);
}

static int __init tsm_init(void)
{
	int ret = 0;

	pr_info(DRIVER_DESC " version: " DRIVER_VERSION "\n");

	tsm_class = class_create("tsm");
	if (IS_ERR(tsm_class))
		return PTR_ERR(tsm_class);
	tsm_class->dev_release = tsm_release;

	tdev_class = class_create("tsm-dev");
	if (IS_ERR(tdev_class))
		return PTR_ERR(tdev_class);
	tdev_class->dev_release = tdev_release;

	tdi_class = class_create("tsm-tdi");
	if (IS_ERR(tdi_class))
		return PTR_ERR(tdi_class);
	tdi_class->dev_release = tdi_release;

	return ret;
}

static void __exit tsm_exit(void)
{
	pr_info(DRIVER_DESC " version: " DRIVER_VERSION " shutdown\n");
	class_destroy(tdi_class);
	class_destroy(tdev_class);
	class_destroy(tsm_class);
}

module_init(tsm_init);
module_exit(tsm_exit);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
