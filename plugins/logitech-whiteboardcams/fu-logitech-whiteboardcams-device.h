/*
 * Copyright (C) 2022 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <fwupdplugin.h>

#define FU_TYPE_LOGITECH_WHITEBOARDCAMS_DEVICE (fu_logitech_whiteboardcams_device_get_type())
G_DECLARE_FINAL_TYPE(FuLogitechWhiteboardcamsDevice,
		     fu_logitech_whiteboardcams_device,
		     FU,
		     LOGITECH_WHITEBOARDCAMS_DEVICE,
		     FuUdevDevice)
