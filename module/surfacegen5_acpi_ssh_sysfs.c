#include <linux/device.h>
#include <linux/sysfs.h>
#include <linux/kernel.h>

#include "surfacegen5_acpi_ssh.h"


#define RQST_IO_SIZE		256
#define RQST_MAX_WRITE_LEN	SURFACEGEN5_MAX_RQST_PAYLOAD + 5

static char rqst_buf_sysfs[RQST_IO_SIZE] = { 0 };
static char rqst_buf_pld[SURFACEGEN5_MAX_RQST_PAYLOAD] = { 0 };
static char rqst_buf_res[SURFACEGEN5_MAX_RQST_RESPONSE] = { 0 };


static ssize_t rqst_read(struct file *f, struct kobject *kobj, struct bin_attribute *attr,
                         char *buf, loff_t offs, size_t count)
{
	if (offs < 0 || count + offs > RQST_IO_SIZE) {
		return -EINVAL;
	}

	memcpy(buf, rqst_buf_sysfs + offs, count);
	return count;
}

static ssize_t rqst_write(struct file *f, struct kobject *kobj, struct bin_attribute *attr,
			  char *buf, loff_t offs, size_t count)
{
	struct surfacegen5_rqst rqst = {};
	struct surfacegen5_buf result = {};
	int status;

	// check basic write constriants
	if (offs != 0 || count > RQST_MAX_WRITE_LEN) {
		return -EINVAL;
	}

	// payload length should be consistent with data provided
	if (buf[4] + 5 != count) {
		return -EINVAL;
	}

	rqst.tc  = buf[0];
	rqst.iid = buf[1];
	rqst.cid = buf[2];
	rqst.snc = buf[3];
	rqst.cdl = buf[4];
	rqst.pld = rqst_buf_pld;
	memcpy(rqst_buf_pld, buf + 5, count - 5);

	result.cap = SURFACEGEN5_MAX_RQST_RESPONSE;
	result.len = 0;
	result.data = rqst_buf_res;

	status = surfacegen5_ec_rqst(&rqst, &result);
	if (status) {
		return status;
	}

	memset(memcpy(rqst_buf_sysfs, result.data, result.len), 0, RQST_IO_SIZE - result.len);
	return count;
}

static const BIN_ATTR_RW(rqst, RQST_IO_SIZE);


int surfacegen5_ssh_sysfs_register(struct device *dev)
{
	return sysfs_create_bin_file(&dev->kobj, &bin_attr_rqst);
}

void surfacegen5_ssh_sysfs_unregister(struct device *dev)
{
	sysfs_remove_bin_file(&dev->kobj, &bin_attr_rqst);
}
