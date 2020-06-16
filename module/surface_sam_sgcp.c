// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Surface Integration Driver.
 * MFD driver to provide device/model dependent functionality.
 */

#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "surface_sam_sgcp.h"

surface_sam_sgcp_handler_fn event_handler;
void *event_handler_data;
bool in_notification;

void surface_sam_sgcp_register_notification(surface_sam_sgcp_handler_fn handler, void *data) {
    event_handler = handler;
    event_handler_data = data;
}

EXPORT_SYMBOL_GPL(surface_sam_sgcp_register_notification);

static const struct acpi_device_id surface_sam_sgcp_ids[] = {
	{ "MSHW0216", 0 },
	{ },
};

static int surface_sam_sgcp_add(struct acpi_device *pdev) {
    return 0;
}

static int surface_sam_sgcp_remove(struct acpi_device *pdev) {
    return 0;
}

static void surface_sam_sgcp_notify(struct acpi_device *pdev, u32 event)
{
    dev_dbg(&pdev->dev, "sgcp notify %d", event);
    if (event_handler) {
        if (!in_notification) {
            in_notification = TRUE;
            event_handler(event, event_handler_data);
            in_notification = FALSE;
        } else {
            dev_err(&pdev->dev, "sgcp - prevented recursive notification");
        }
    }
}

static struct acpi_driver surface_sam_sgcp = {
    .name = "surface_sam_sgcp",
    .ids = surface_sam_sgcp_ids,
    .ops = {
        .add = surface_sam_sgcp_add,
        .remove = surface_sam_sgcp_remove,
        .notify = surface_sam_sgcp_notify
    }
};

module_acpi_driver(surface_sam_sgcp);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Surface SGCP Driver for 5th Generation Surface Devices");
MODULE_LICENSE("GPL");
