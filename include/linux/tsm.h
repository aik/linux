/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __TSM_H
#define __TSM_H

#include <linux/sizes.h>
#include <linux/types.h>
#include <linux/uuid.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/device.h>
#include <linux/bitfield.h>

#define TSM_REPORT_INBLOB_MAX 64
#define TSM_REPORT_OUTBLOB_MAX SZ_32K

/*
 * Privilege level is a nested permission concept to allow confidential
 * guests to partition address space, 4-levels are supported.
 */
#define TSM_REPORT_PRIVLEVEL_MAX 3

/**
 * struct tsm_report_desc - option descriptor for generating tsm report blobs
 * @privlevel: optional privilege level to associate with @outblob
 * @inblob_len: sizeof @inblob
 * @inblob: arbitrary input data
 * @service_provider: optional name of where to obtain the tsm report blob
 * @service_guid: optional service-provider service guid to attest
 * @service_manifest_version: optional service-provider service manifest version requested
 */
struct tsm_report_desc {
	unsigned int privlevel;
	size_t inblob_len;
	u8 inblob[TSM_REPORT_INBLOB_MAX];
	char *service_provider;
	guid_t service_guid;
	unsigned int service_manifest_version;
};

/**
 * struct tsm_report - track state of report generation relative to options
 * @desc: input parameters to @report_new()
 * @outblob_len: sizeof(@outblob)
 * @outblob: generated evidence to provider to the attestation agent
 * @auxblob_len: sizeof(@auxblob)
 * @auxblob: (optional) auxiliary data to the report (e.g. certificate data)
 * @manifestblob_len: sizeof(@manifestblob)
 * @manifestblob: (optional) manifest data associated with the report
 */
struct tsm_report {
	struct tsm_report_desc desc;
	size_t outblob_len;
	u8 *outblob;
	size_t auxblob_len;
	u8 *auxblob;
	size_t manifestblob_len;
	u8 *manifestblob;
};

/**
 * enum tsm_attr_index - index used to reference report attributes
 * @TSM_REPORT_GENERATION: index of the report generation number attribute
 * @TSM_REPORT_PROVIDER: index of the provider name attribute
 * @TSM_REPORT_PRIVLEVEL: index of the desired privilege level attribute
 * @TSM_REPORT_PRIVLEVEL_FLOOR: index of the minimum allowed privileg level attribute
 * @TSM_REPORT_SERVICE_PROVIDER: index of the service provider identifier attribute
 * @TSM_REPORT_SERVICE_GUID: index of the service GUID attribute
 * @TSM_REPORT_SERVICE_MANIFEST_VER: index of the service manifest version attribute
 */
enum tsm_attr_index {
	TSM_REPORT_GENERATION,
	TSM_REPORT_PROVIDER,
	TSM_REPORT_PRIVLEVEL,
	TSM_REPORT_PRIVLEVEL_FLOOR,
	TSM_REPORT_SERVICE_PROVIDER,
	TSM_REPORT_SERVICE_GUID,
	TSM_REPORT_SERVICE_MANIFEST_VER,
};

/**
 * enum tsm_bin_attr_index - index used to reference binary report attributes
 * @TSM_REPORT_INBLOB: index of the binary report input attribute
 * @TSM_REPORT_OUTBLOB: index of the binary report output attribute
 * @TSM_REPORT_AUXBLOB: index of the binary auxiliary data attribute
 * @TSM_REPORT_MANIFESTBLOB: index of the binary manifest data attribute
 */
enum tsm_bin_attr_index {
	TSM_REPORT_INBLOB,
	TSM_REPORT_OUTBLOB,
	TSM_REPORT_AUXBLOB,
	TSM_REPORT_MANIFESTBLOB,
};

/**
 * struct tsm_report_ops - attributes and operations for tsm_report instances
 * @name: tsm id reflected in /sys/kernel/config/tsm/report/$report/provider
 * @privlevel_floor: convey base privlevel for nested scenarios
 * @report_new: Populate @report with the report blob and auxblob
 * (optional), return 0 on successful population, or -errno otherwise
 * @report_attr_visible: show or hide a report attribute entry
 * @report_bin_attr_visible: show or hide a report binary attribute entry
 *
 * Implementation specific ops, only one is expected to be registered at
 * a time i.e. only one of "sev-guest", "tdx-guest", etc.
 */
struct tsm_report_ops {
	const char *name;
	unsigned int privlevel_floor;
	int (*report_new)(struct tsm_report *report, void *data);
	bool (*report_attr_visible)(int n);
	bool (*report_bin_attr_visible)(int n);
};

int tsm_report_register(const struct tsm_report_ops *ops, void *priv);
int tsm_report_unregister(const struct tsm_report_ops *ops);

/* SPDM control structure for DOE */
struct tsm_spdm {
	unsigned long req_len;
	void *req;
	unsigned long rsp_len;
	void *rsp;
};

/* Data object for measurements/certificates/attestationreport */
struct tsm_blob {
	void *data;
	size_t len;
};

struct tsm_blob *tsm_blob_new(void *data, size_t len);
static inline void tsm_blob_free(struct tsm_blob *b)
{
	kfree(b);
}

/**
 * struct tdisp_interface_id - TDISP INTERFACE_ID Definition
 *
 * @function_id: Identifies the function of the device hosting the TDI
 *   15:0: @rid: Requester ID
 *   23:16: @rseg: Requester Segment (Reserved if Requester Segment Valid is Clear)
 *   24: @rseg_valid: Requester Segment Valid
 *   31:25 – Reserved
 * 8B - Reserved
 */
struct tdisp_interface_id {
	u32 function_id; /* TSM_TDISP_IID_xxxx */
	u8 reserved[8];
} __packed;

#define TSM_TDISP_IID_REQUESTER_ID	GENMASK(15, 0)
#define TSM_TDISP_IID_RSEG		GENMASK(23, 16)
#define TSM_TDISP_IID_RSEG_VALID	BIT(24)

/*
 * Measurement block as defined in SPDM DSP0274.
 */
struct spdm_measurement_block_header {
	u8 index;
	u8 spec; /* MeasurementSpecification */
	u16 size;
} __packed;

struct dmtf_measurement_block_header {
	u8 type;  /* DMTFSpecMeasurementValueType */
	u16 size; /* DMTFSpecMeasurementValueSize */
} __packed;

struct dmtf_measurement_block_device_mode {
	u32 opmode_cap;	 /* OperationalModeCapabilties */
	u32 opmode_sta;  /* OperationalModeState */
	u32 devmode_cap; /* DeviceModeCapabilties */
	u32 devmode_sta; /* DeviceModeState */
} __packed;

struct spdm_certchain_block_header {
	u16 length;
	u16 reserved;
} __packed;

/*
 * TDI Report Structure as defined in TDISP.
 */
struct tdi_report_header {
	u16 interface_info; /* TSM_TDI_REPORT_xxx */
	u16 reserved2;
	u16 msi_x_message_control;
	u16 lnr_control;
	u32 tph_control;
	u32 mmio_range_count;
} __packed;

#define _BITSH(x)	(1 << (x))
#define TSM_TDI_REPORT_NO_FW_UPDATE	_BITSH(0)  /* fw updates not permitted in CONFIG_LOCKED or RUN */
#define TSM_TDI_REPORT_DMA_NO_PASID	_BITSH(1)  /* TDI generates DMA requests without PASID */
#define TSM_TDI_REPORT_DMA_PASID	_BITSH(2)  /* TDI generates DMA requests with PASID */
#define TSM_TDI_REPORT_ATS		_BITSH(3)  /* ATS supported and enabled for the TDI */
#define TSM_TDI_REPORT_PRS		_BITSH(4)  /* PRS supported and enabled for the TDI */

/*
 * Each MMIO Range of the TDI is reported with the MMIO reporting offset added.
 * Base and size in units of 4K pages
 */
struct tdi_report_mmio_range {
	u64 first_page; /* First 4K page with offset added */
	u32 num; 	/* Number of 4K pages in this range */
	u32 range_attributes; /* TSM_TDI_REPORT_MMIO_xxx */
} __packed;

#define TSM_TDI_REPORT_MMIO_MSIX_TABLE		BIT(0)
#define TSM_TDI_REPORT_MMIO_PBA			BIT(1)
#define TSM_TDI_REPORT_MMIO_IS_NON_TEE		BIT(2)
#define TSM_TDI_REPORT_MMIO_IS_UPDATABLE	BIT(3)
#define TSM_TDI_REPORT_MMIO_RESERVED		GENMASK(15, 4)
#define TSM_TDI_REPORT_MMIO_RANGE_ID		GENMASK(31, 16)

struct tdi_report_footer {
	u32 device_specific_info_len;
	u8 device_specific_info[];
} __packed;

#define TDI_REPORT_HDR(rep)		((struct tdi_report_header *) ((rep)->data))
#define TDI_REPORT_MR_NUM(rep)		(TDI_REPORT_HDR(rep)->mmio_range_count)
#define TDI_REPORT_MR_OFF(rep)		((struct tdi_report_mmio_range *) (TDI_REPORT_HDR(rep) + 1))
#define TDI_REPORT_MR(rep, rangeid)	TDI_REPORT_MR_OFF(rep)[rangeid]
#define TDI_REPORT_FTR(rep)		((struct tdi_report_footer *) &TDI_REPORT_MR((rep), \
					TDI_REPORT_MR_NUM(rep)))

struct tsm_bus_ops;

/* Physical device descriptor responsible for IDE/TDISP setup */
struct tsm_dev {
	const struct attribute_group *ag;
	struct device *physdev; /* Physical PCI function #0 */
	struct device dev; /* A child device of PCI function #0 */
	struct tsm_spdm spdm;
	struct mutex spdm_mutex;

	u8 cert_slot;
	u8 connected;
	unsigned bound;

	struct tsm_blob *meas;
	struct tsm_blob *certs;
#define TSM_MAX_NONCE_LEN	64
	u8 nonce[TSM_MAX_NONCE_LEN];
	size_t nonce_len;

	void *data; /* Platform specific data */

	struct tsm_subsys *tsm;
	struct tsm_bus_subsys *tsm_bus;
	/* Bus specific data follow this struct, see tsm_dev_to_bdata */
};

#define tsm_dev_to_bdata(tdev)	((tdev)?((void *)&(tdev)[1]):NULL)

/* PCI function for passing through, can be the same as tsm_dev::pdev */
struct tsm_tdi {
	const struct attribute_group *ag;
	struct device dev; /* A child device of PCI VF */
	struct list_head node;
	struct tsm_dev *tdev;

	u8 rseg;
	u8 rseg_valid;
	bool validated;

	struct tsm_blob *report;

	void *data; /* Platform specific data */

	struct kvm *kvm;
	u16 guest_rid; /* BDFn of PCI Fn in the VM (when PCI TDISP) */
};

struct tsm_dev_status {
	u8 ctx_state;
	u8 tc_mask;
	u8 certs_slot;
	u16 device_id;
	u16 segment_id;
	u8 no_fw_update;
	u16 ide_stream_id[8];
};

enum tsm_spdm_algos {
	TSM_SPDM_ALGOS_DHE_SECP256R1,
	TSM_SPDM_ALGOS_DHE_SECP384R1,
	TSM_SPDM_ALGOS_AEAD_AES_128_GCM,
	TSM_SPDM_ALGOS_AEAD_AES_256_GCM,
	TSM_SPDM_ALGOS_ASYM_TPM_ALG_RSASSA_3072,
	TSM_SPDM_ALGOS_ASYM_TPM_ALG_ECDSA_ECC_NIST_P256,
	TSM_SPDM_ALGOS_ASYM_TPM_ALG_ECDSA_ECC_NIST_P384,
	TSM_SPDM_ALGOS_HASH_TPM_ALG_SHA_256,
	TSM_SPDM_ALGOS_HASH_TPM_ALG_SHA_384,
	TSM_SPDM_ALGOS_KEY_SCHED_SPDM_KEY_SCHEDULE,
};

enum tsm_tdisp_state {
	TDISP_STATE_CONFIG_UNLOCKED,
	TDISP_STATE_CONFIG_LOCKED,
	TDISP_STATE_RUN,
	TDISP_STATE_ERROR,
};

struct tsm_tdi_status {
	bool valid;
	u8 meas_digest_fresh:1;
	u8 meas_digest_valid:1;
	u8 all_request_redirect:1;
	u8 bind_p2p:1;
	u8 lock_msix:1;
	u8 no_fw_update:1;
	u16 cache_line_size;
	u64 spdm_algos; /* Bitmask of TSM_SPDM_ALGOS */
	u8 certs_digest[48];
	u8 meas_digest[48];
	u8 interface_report_digest[48];
	u64 intf_report_counter;
	struct tdisp_interface_id id;
	enum tsm_tdisp_state state;
};

struct tsm_bus_ops {
	int (*spdm_forward)(struct tsm_spdm *spdm, u8 type);
};

struct tsm_bus_subsys {
	struct tsm_bus_ops *ops;
	struct notifier_block notifier;
	struct tsm_subsys *tsm;
};

struct tsm_bus_subsys *pci_tsm_register(struct tsm_subsys *tsm_subsys);
void pci_tsm_unregister(struct tsm_bus_subsys *subsys);

/* tsm_hv_ops return codes for SPDM bouncing, when requested by the TSM */
#define TSM_PROTO_CMA_SPDM		1
#define TSM_PROTO_SECURED_CMA_SPDM	2

struct tsm_hv_ops {
	int (*dev_connect)(struct tsm_dev *tdev, void *private_data);
	int (*dev_disconnect)(struct tsm_dev *tdev);
	int (*dev_status)(struct tsm_dev *tdev, struct tsm_dev_status *s);
	int (*dev_measurements)(struct tsm_dev *tdev);
	int (*tdi_bind)(struct tsm_tdi *tdi, u32 bdfn, u64 vmid);
	int (*tdi_unbind)(struct tsm_tdi *tdi);
	int (*guest_request)(struct tsm_tdi *tdi, u8 __user *req, size_t reqlen,
			     u8 __user *rsp, size_t rsplen, int *fw_err);
	int (*tdi_status)(struct tsm_tdi *tdi, struct tsm_tdi_status *ts);
};

/* featuremask for tdi_validate */
/* TODO: use it */
#define TDI_VALIDATE_DMA	BIT(0)
#define TDI_VALIDATE_MMIO	BIT(1)

struct tsm_vm_ops {
	int (*tdi_validate)(struct tsm_tdi *tdi, unsigned featuremask,
			    bool invalidate, void *private_data);
	int (*tdi_mmio_config)(struct tsm_tdi *tdi, u64 start, u64 size,
			       bool tee, void *private_data);
	int (*tdi_status)(struct tsm_tdi *tdi, void *private_data,
			  struct tsm_tdi_status *ts);
};

struct tsm_subsys {
	struct device dev;
	struct list_head tdi_head;
	struct mutex lock;
	const struct attribute_group *tdev_groups[3]; /* Common, host/guest, NULL */
	const struct attribute_group *tdi_groups[3]; /* Common, host/guest, NULL */
	int (*update_measurements)(struct tsm_dev *tdev);
};

struct tsm_subsys *tsm_register(struct device *parent, size_t extra,
				const struct attribute_group *tdev_ag,
				const struct attribute_group *tdi_ag,
				int (*update_measurements)(struct tsm_dev *tdev));
void tsm_unregister(struct tsm_subsys *subsys);

struct tsm_host_subsys;
struct tsm_host_subsys *tsm_host_register(struct device *parent,
					  struct tsm_hv_ops *hvops,
					  void *private_data);
struct tsm_guest_subsys;
struct tsm_guest_subsys *tsm_guest_register(struct device *parent,
					    struct tsm_vm_ops *vmops,
					    void *private_data);
void tsm_guest_unregister(struct tsm_guest_subsys *gsubsys);

struct tsm_dev *tsm_dev_get(struct device *dev);
void tsm_dev_put(struct tsm_dev *tdev);
struct tsm_tdi *tsm_tdi_get(struct device *dev);
void tsm_tdi_put(struct tsm_tdi *tdi);

struct pci_dev;
int pci_dev_tdi_validate(struct pci_dev *pdev, bool invalidate);
int pci_dev_tdi_mmio_config(struct pci_dev *pdev, u32 range_id, bool tee);

int tsm_dev_init(struct tsm_bus_subsys *tsm_bus, struct device *parent,
		 size_t busdatalen, struct tsm_dev **ptdev);
void tsm_dev_free(struct tsm_dev *tdev);
int tsm_tdi_init(struct tsm_dev *tdev, struct device *dev);
void tsm_tdi_free(struct tsm_tdi *tdi);

/* IOMMUFD vIOMMU helpers */
int tsm_tdi_bind(struct tsm_tdi *tdi, u32 guest_rid, int kvmfd);
void tsm_tdi_unbind(struct tsm_tdi *tdi);
int tsm_guest_request(struct tsm_tdi *tdi, u8 __user *req, size_t reqlen,
		      u8 __user *res, size_t reslen, int *fw_err);

/* Debug */
ssize_t tsm_report_gen(struct tsm_blob *report, char *b, size_t len);

/* IDE */
int tsm_create_link(struct tsm_subsys *tsm, struct device *dev, const char *name);
void tsm_remove_link(struct tsm_subsys *tsm, const char *name);
#define tsm_register_ide_stream(tdev, ide) \
	tsm_create_link((tdev)->tsm, &(tdev)->dev, (ide)->name)
#define tsm_unregister_ide_stream(tdev, ide) \
	tsm_remove_link((tdev)->tsm, (ide)->name)

#endif /* __TSM_H */
