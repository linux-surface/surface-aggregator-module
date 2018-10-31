#ifndef _SURFACEGEN5_ACPI_NOTIFY_SAN_H
#define _SURFACEGEN5_ACPI_NOTIFY_SAN_H

enum surfacegen5_pwr_event {
	_surfacegen5_pwr_event_MIN      = 0x03,
	SURFACEGEN5_PWR_EVENT_BAT1_STAT	= 0x03,
	SURFACEGEN5_PWR_EVENT_BAT1_INFO	= 0x04,
	SURFACEGEN5_PWR_EVENT_ADP1_STAT	= 0x05,
	SURFACEGEN5_PWR_EVENT_ADP1_INFO	= 0x06,
	SURFACEGEN5_PWR_EVENT_BAT2_STAT	= 0x07,
	SURFACEGEN5_PWR_EVENT_BAT2_INFO	= 0x08,
	_surfacegen5_pwr_event_MAX      = 0x08,
};

int surfacegen5_acpi_notify_power_event(enum surfacegen5_pwr_event event);

#endif /* _SURFACEGEN5_ACPI_NOTIFY_SAN_H */
