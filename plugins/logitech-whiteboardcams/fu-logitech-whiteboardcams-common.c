/*
 * Copyright (c) 1999-2021 Logitech, Inc.
 * All Rights Reserved
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <fwupdplugin.h>

#include "fu-logitech-whiteboardcams-common.h"

const gchar *
fu_logitech_whiteboardcams_device_status_to_string(FuLogitechWhiteboardcamsDeviceStatus status)
{
	if (status == kDeviceStateUnknown)
		return "Unknown";
	if (status == kDeviceStateOffline)
		return "Offline";
	if (status == kDeviceStateOnline)
		return "Online";
	if (status == kDeviceStateIdle)
		return "Idle";
	if (status == kDeviceStateInUse)
		return "InUse";
	if (status == kDeviceStateAudioOnly)
		return "AudioOnly";
	if (status == kDeviceStateEnumerating)
		return "Enumerating";
	return NULL;
}

const gchar *
fu_logitech_whiteboardcams_device_update_state_to_string(
    FuLogitechWhiteboardcamsDeviceUpdateState update_state)
{
	if (update_state == kUpdateStateUnknown)
		return "Unknown";
	if (update_state == kUpdateStateCurrent)
		return "Current";
	if (update_state == kUpdateStateAvailable)
		return "Available";
	if (update_state == kUpdateStateStarting)
		return "Starting";
	if (update_state == kUpdateStateDownloading)
		return "Downloading";
	if (update_state == kUpdateStateReady)
		return "Ready";
	if (update_state == kUpdateStateUpdating)
		return "Updating";
	if (update_state == kUpdateStateScheduled)
		return "Scheduled";
	if (update_state == kUpdateStateError)
		return "Error";
	return NULL;
}
