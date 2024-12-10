/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Intel Corporation. All rights reserved. */

/* PCIe 6.2 section 6.33 Integrity & Data Encryption (IDE) */

#ifndef __PCI_IDE_H__
#define __PCI_IDE_H__

#include <linux/range.h>

enum pci_ide_flags {
	PCI_IDE_SETUP_ROOT_PORT = BIT(0),
	PCI_IDE_SETUP_ROOT_PORT_MEM = BIT(1),
};

struct pci_ide {
	int domain;
	u16 devid_start;
	u16 devid_end;
	u16 rpid_start;
	u16 rpid_end;
	int stream_id;
	const char *name;
	int nr_mem;
	struct range mem[16];
	unsigned dev_sel_ctl;
	unsigned rootport_sel_ctl;
	enum pci_ide_flags flags;
};

void pci_ide_stream_probe(struct pci_dev *pdev, struct pci_ide *ide);

int pci_ide_stream_setup(struct pci_dev *pdev, struct pci_ide *ide,
			 enum pci_ide_flags flags);
void pci_ide_stream_teardown(struct pci_dev *pdev, struct pci_ide *ide);
void pci_ide_enable_stream(struct pci_dev *pdev, struct pci_ide *ide);
void pci_ide_disable_stream(struct pci_dev *pdev, struct pci_ide *ide);
int pci_ide_stream_state(struct pci_dev *pdev, struct pci_ide *ide, u32 *status, u32 *rpstatus);

#endif /* __PCI_IDE_H__ */
