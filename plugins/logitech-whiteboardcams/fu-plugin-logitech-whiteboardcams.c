/*
 * Copyright (c) 1999-2022 Logitech, Inc.
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <fwupdplugin.h>

#include "fu-logitech-whiteboardcams-device.h"

static void
fu_plugin_logitech_whiteboardcams_init(FuPlugin *plugin)
{
	fu_plugin_add_udev_subsystem(plugin, "video4linux");
	fu_plugin_add_device_gtype(plugin, FU_TYPE_LOGITECH_WHITEBOARDCAMS_DEVICE);
}

void
fu_plugin_init_vfuncs(FuPluginVfuncs *vfuncs)
{
	vfuncs->build_hash = FU_BUILD_HASH;
	vfuncs->init = fu_plugin_logitech_whiteboardcams_init;
}
