// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/device.h>
#include <linux/sysfs.h>
#include <linux/kernel.h>

#include "surface_sam_ssh.h"


static char sam_ssh_debug_rqst_buf_sysfs[SURFACE_SAM_SSH_MAX_RQST_RESPONSE + 1] = { 0 };
static char sam_ssh_debug_rqst_buf_pld[SURFACE_SAM_SSH_MAX_RQST_PAYLOAD] = { 0 };
static char sam_ssh_debug_rqst_buf_res[SURFACE_SAM_SSH_MAX_RQST_RESPONSE] = { 0 };


struct sysfs_rqst {
	u8 tc;
	u8 cid;
	u8 iid;
	u8 pri;
	u8 snc;
	u8 cdl;
	u8 pld[0];
} __packed;


static ssize_t rqst_read(struct file *f, struct kobject *kobj, struct bin_attribute *attr,
			 char *buf, loff_t offs, size_t count)
{
	if (offs < 0 || count + offs > SURFACE_SAM_SSH_MAX_RQST_RESPONSE)
		return -EINVAL;

	memcpy(buf, sam_ssh_debug_rqst_buf_sysfs + offs, count);
	return count;
}

static ssize_t rqst_write(struct file *f, struct kobject *kobj, struct bin_attribute *attr,
			  char *buf, loff_t offs, size_t count)
{
	struct sysfs_rqst *input;
	struct surface_sam_ssh_rqst rqst = {};
	struct surface_sam_ssh_buf result = {};
	int status;

	// check basic write constriants
	if (offs != 0 || count > SURFACE_SAM_SSH_MAX_RQST_PAYLOAD + sizeof(struct sysfs_rqst))
		return -EINVAL;

	if (count < sizeof(struct sysfs_rqst))
		return -EINVAL;

	input = (struct sysfs_rqst *)buf;

	// payload length should be consistent with data provided
	if (input->cdl + sizeof(struct sysfs_rqst) != count)
		return -EINVAL;

	rqst.tc  = input->tc;
	rqst.cid = input->cid;
	rqst.iid = input->iid;
	rqst.pri = input->pri;
	rqst.snc = input->snc;
	rqst.cdl = input->cdl;
	rqst.pld = sam_ssh_debug_rqst_buf_pld;
	memcpy(sam_ssh_debug_rqst_buf_pld, &input->pld[0], input->cdl);

	result.cap = SURFACE_SAM_SSH_MAX_RQST_RESPONSE;
	result.len = 0;
	result.data = sam_ssh_debug_rqst_buf_res;

	status = surface_sam_ssh_rqst(&rqst, &result);
	if (status)
		return status;

	sam_ssh_debug_rqst_buf_sysfs[0] = result.len;
	memcpy(sam_ssh_debug_rqst_buf_sysfs + 1, result.data, result.len);
	memset(sam_ssh_debug_rqst_buf_sysfs + result.len + 1, 0,
	       SURFACE_SAM_SSH_MAX_RQST_RESPONSE + 1 - result.len);

	return count;
}

static const BIN_ATTR_RW(rqst, SURFACE_SAM_SSH_MAX_RQST_RESPONSE + 1);


int surface_sam_ssh_sysfs_register(struct device *dev)
{
	return sysfs_create_bin_file(&dev->kobj, &bin_attr_rqst);
}

void surface_sam_ssh_sysfs_unregister(struct device *dev)
{
	sysfs_remove_bin_file(&dev->kobj, &bin_attr_rqst);
}
