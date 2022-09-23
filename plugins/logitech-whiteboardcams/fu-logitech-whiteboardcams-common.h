/*
 * Copyright (c) 1999-2022 Logitech, Inc.
 * All Rights Reserved
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <glib.h>

#define SET_TIME_DELAY_MS 500 /* send future time to keep PC & device time as close as possible */

typedef enum {
	kDeviceStateUnknown = -1,
	kDeviceStateOffline,
	kDeviceStateOnline,
	kDeviceStateIdle,
	kDeviceStateInUse,
	kDeviceStateAudioOnly,
	kDeviceStateEnumerating
} FuLogitechWhiteboardcamsDeviceStatus;

typedef enum {
	kUpdateStateUnknown = -1,
	kUpdateStateCurrent,
	kUpdateStateAvailable,
	kUpdateStateStarting = 3,
	kUpdateStateDownloading,
	kUpdateStateReady,
	kUpdateStateUpdating,
	kUpdateStateScheduled,
	kUpdateStateError
} FuLogitechWhiteboardcamsDeviceUpdateState;

const gchar *
fu_logitech_whiteboardcams_device_status_to_string(FuLogitechWhiteboardcamsDeviceStatus status);
const gchar *
fu_logitech_whiteboardcams_device_update_state_to_string(
    FuLogitechWhiteboardcamsDeviceUpdateState update_state);
