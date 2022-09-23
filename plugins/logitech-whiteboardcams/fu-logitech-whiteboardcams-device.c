/*
 * Copyright (c) 1999-2021 Logitech, Inc.
 * Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <fwupdplugin.h>

#include <linux/types.h>
#include <linux/usb/video.h>
#include <linux/uvcvideo.h>
#ifdef HAVE_IOCTL_H
#include <sys/ioctl.h>
#endif

#include <string.h>

#include "fu-logitech-whiteboardcams-common.h"
#include "fu-logitech-whiteboardcams-device.h"

#define HASH_TIMEOUT		      30000
#define MAX_DATA_SIZE		      8192 /* 8k */
#define SESSION_TIMEOUT	              1000
#define HASH_VALUE_SIZE		      16
#define LENGTH_OFFSET		      0x4
#define COMMAND_OFFSET		      0x0
#define MAX_RETRIES		          5
#define MAX_HANDSHAKE_RETRIES	  3
#define MAX_WAIT_COUNT		      150

#define FU_LOGITECH_WHITEBOARDCAMS_DEVICE_IOCTL_TIMEOUT 5000 /* ms */
// 2 byte for get len query.
#define kDefaultUvcGetLenQueryControlSize  2

const guchar kLogiCameraVersionSelector = 1;
const guchar kLogiUvcXuDevInfoCsEepromVersion = 3;
const guint kLogiVideoImageVersionMaxSize = 32;
const guchar kLogiVideoAitInitiateSetMMPData = 1;
const guchar kLogiVideoAitFinalizeSetMMPData = 1;
const guchar kLogiUnitIdAccessMmp = 6;
const guchar kLogiUvcXuAitCustomCsSetMmp = 4;
const guchar kLogiUvcXuAitCustomCsGetMmpResult = 5;
const guchar kLogiUnitIdPeripheralControl = 11;

const guchar kLogiUnitIdCameraVersion = 8;
const guchar kLogiAitSetMmpCmdFwBurning = 1;
const guint kLogiUvcXuTestDbgTdeModeEnable = 8;
const guint kLogiUnitIdGuidTestAndDebug = 0; // SRS: TODO
const guint kLogiUvcXuTdeModeSelector = 0; // SRS: TODO
enum { SHA_256, SHA_512, MD5 };

struct _FuLogitechWhiteboardcamsDevice {
	FuUdevDevice parent_instance;
	FuLogitechWhiteboardcamsDeviceStatus status;
	FuLogitechWhiteboardcamsDeviceUpdateState update_status;
	guint update_progress; /* percentage value */
};

typedef struct {
	FuLogitechWhiteboardcamsDevice *self; /* no-ref */
	GByteArray *device_response;
	GByteArray *buf_pkt;
	GError *error;
} FuLogitechWhiteboardcamsHelper;

G_DEFINE_TYPE(FuLogitechWhiteboardcamsDevice, fu_logitech_whiteboardcams_device, FU_TYPE_UDEV_DEVICE)

static gboolean
fu_logitech_whiteboardcams_device_query_data_size(FuLogitechWhiteboardcamsDevice *self,
						guchar unit_id, 
						guchar control_selector,
						guint16  *data_size,
						GError **error) 
{
	/*if (!is_open_) {
		g_prefix_error(error, "failed to query data size: device not open for unit: 0x%x selector: 0x%x ", (guchar)unit_id, (guchar)control_selector);
		return FALSE;
	}*/

	guint8 size_data[kDefaultUvcGetLenQueryControlSize] = {0x0};
	struct uvc_xu_control_query size_query;
	size_query.unit = unit_id;
	size_query.selector = control_selector;
	size_query.query = UVC_GET_LEN;
	size_query.size = kDefaultUvcGetLenQueryControlSize;
	size_query.data = size_data;

	if (g_getenv("FWUPD_LOGITECH_WHITEBOARDCAMS_VERBOSE") != NULL) {
		g_debug("Data size query request, unit: 0x%x selector: 0x%x", (guchar)unit_id, (guchar)control_selector);
	}

	if (!fu_udev_device_ioctl(FU_UDEV_DEVICE(self),
				  UVCIOC_CTRL_QUERY,
				  (guint8 *)&size_query,
				  NULL,
				  FU_LOGITECH_WHITEBOARDCAMS_DEVICE_IOCTL_TIMEOUT,
				  error))
		return FALSE;
	// convert the data byte to int
	// guint32 response_size = 0;
	// response_size = GUINT32_FROM_BE(size_data);
	// response_size = size_data[1] << 8 | size_data[0];
	*data_size = size_data[1] << 8 | size_data[0];
	if (g_getenv("FWUPD_LOGITECH_WHITEBOARDCAMS_VERBOSE") != NULL) {
		g_debug("Data size query response, size: %u unit: 0x%x selector: 0x%x", *data_size, (guchar)unit_id, (guchar)control_selector);
		fu_dump_raw(G_LOG_DOMAIN, "UVC_GET_LEN", size_data, kDefaultUvcGetLenQueryControlSize);
	}
	
	/* success */
	return TRUE;
}

static gboolean
fu_logitech_whiteboardcams_device_get_xu_control(FuLogitechWhiteboardcamsDevice *self,
						guchar unit_id,
						guchar control_selector,
						guint16 data_size,
						guchar *data,
						GError **error) 
{
	struct uvc_xu_control_query control_query;

	if (g_getenv("FWUPD_LOGITECH_WHITEBOARDCAMS_VERBOSE") != NULL) {
		g_debug("Get xu control request, size: %" G_GUINT16_FORMAT " unit: 0x%x selector: 0x%x", data_size, (guchar)unit_id, (guchar)control_selector);
	}
	control_query.unit = unit_id;
	control_query.selector = control_selector;
	control_query.query = UVC_GET_CUR;
	control_query.size = data_size;
	control_query.data = data;
	if (!fu_udev_device_ioctl(FU_UDEV_DEVICE(self),
					UVCIOC_CTRL_QUERY,
				  	(guint8 *)&control_query,
				  	NULL,
				  	FU_LOGITECH_WHITEBOARDCAMS_DEVICE_IOCTL_TIMEOUT,
				  	error))
		return FALSE;
	for (guint i = 0; i < data_size; i++) {
		data[i] = (guchar)data[i];
	}
	if (g_getenv("FWUPD_LOGITECH_WHITEBOARDCAMS_VERBOSE") != NULL) {
		g_debug("Received get xu control response, size: %u unit: 0x%x selector: 0x%x", data_size, (guchar)unit_id, (guchar)control_selector);
		fu_dump_raw(G_LOG_DOMAIN, "UVC_GET_CUR", data, data_size);
	}
	/* success */
	return TRUE;
}

static gboolean
fu_logitech_whiteboardcams_device_set_xu_control(FuLogitechWhiteboardcamsDevice *self,
						guchar unit_id,
						guchar control_selector,
						guint16 data_size,
						guchar *data,
						GError **error)
{
  	struct uvc_xu_control_query control_query;
  	control_query.unit = unit_id;
  	control_query.selector = control_selector;
  	control_query.query = UVC_SET_CUR;
  	control_query.size = data_size;
  	control_query.data = data;
	if (g_getenv("FWUPD_LOGITECH_WHITEBOARDCAMS_VERBOSE") != NULL) {
		g_debug("Set xu control request, size: %" G_GUINT16_FORMAT " unit: 0x%x selector: 0x%x", data_size, (guchar)unit_id, (guchar)control_selector);
	}

	// A few ioctl requests use return value as an output parameter
	// and return a nonnegative value on success, so we should check
	// for real error before returning.
	if (!fu_udev_device_ioctl(FU_UDEV_DEVICE(self),
					UVCIOC_CTRL_QUERY,
				  	(guint8 *)&control_query,
				  	NULL,
				  	FU_LOGITECH_WHITEBOARDCAMS_DEVICE_IOCTL_TIMEOUT,
				  	error))
		return FALSE;

	/* success */
	return TRUE;
}

static gboolean
fu_logitech_whiteboardcams_device_ait_initiate_update(FuLogitechWhiteboardcamsDevice *self,
						GError **error) 
{

	guint16 data_len = 0;
	g_autofree guint8 *mmp_get_data = NULL;
	guint8 ait_initiate_update[] = {kLogiAitSetMmpCmdFwBurning,
                                     0,
                                     0,
                                     kLogiVideoAitInitiateSetMMPData,
                                     0,
                                     0,
                                     0,
                                     0};
	if (g_getenv("FWUPD_LOGITECH_WHITEBOARDCAMS_VERBOSE") != NULL) {
		g_debug("Ait initiate update request");
	}

	if (!fu_logitech_whiteboardcams_device_set_xu_control(self, 
			kLogiUnitIdAccessMmp, 
			kLogiUvcXuAitCustomCsSetMmp,
			sizeof(ait_initiate_update), 
			(guchar *)&ait_initiate_update, 
			error))
    	return FALSE;

	if (!fu_logitech_whiteboardcams_device_query_data_size(self, 
			kLogiUnitIdAccessMmp, 
			kLogiUvcXuAitCustomCsSetMmp, 
			&data_len, 
			error))
		return FALSE;
	mmp_get_data = g_malloc0(data_len);
	if (!fu_logitech_whiteboardcams_device_get_xu_control(self, 
			kLogiUnitIdAccessMmp, 
			kLogiUvcXuAitCustomCsGetMmpResult,
			data_len, 
			(guchar *)mmp_get_data, 
			error))
    	return FALSE;
	if (mmp_get_data[0] != 0) {
		g_set_error(error,
			G_IO_ERROR,
			G_IO_ERROR_FAILED,
			"failed to initialize AIT update, invalid result data: 0x%x",
			(guchar)mmp_get_data[0]);
    	return FALSE;
	}
	
	/* success */
	return TRUE;
  }


static gboolean
fu_logitech_whiteboardcams_device_ait_finalize_update(FuLogitechWhiteboardcamsDevice *self,
						GError **error) 
{

	guint16 data_len = 0;
	g_autofree guint8 *mmp_get_data = NULL;
	guint8 ait_finalize_update[] = {kLogiAitSetMmpCmdFwBurning,
									kLogiVideoAitInitiateSetMMPData,
                                    0,
                                	0,
                                    0,
                                    0,
                                    0,
                                    0};

	if (g_getenv("FWUPD_LOGITECH_WHITEBOARDCAMS_VERBOSE") != NULL) {
		g_debug("Ait finalize update request");
	}

	if (!fu_logitech_whiteboardcams_device_set_xu_control(self, 
			kLogiUnitIdAccessMmp, 
			kLogiUvcXuAitCustomCsSetMmp,
			sizeof(ait_finalize_update), 
			(guchar *)&ait_finalize_update, 
			error))
    	return FALSE;

	if (!fu_logitech_whiteboardcams_device_query_data_size(self, 
			kLogiUnitIdAccessMmp, 
			kLogiUvcXuAitCustomCsSetMmp, 
			&data_len, 
			error))
		return FALSE;
	mmp_get_data = g_malloc0(data_len);
	if (!fu_logitech_whiteboardcams_device_get_xu_control(self, 
			kLogiUnitIdAccessMmp, 
			kLogiUvcXuAitCustomCsGetMmpResult,
			data_len, 
			(guchar *)mmp_get_data, 
			error))
    	return FALSE;
	if (mmp_get_data[0] != 0) {
		g_set_error(error,
			G_IO_ERROR,
			G_IO_ERROR_FAILED,
			"failed to finalize AIT update, invalid result data: 0x%x",
			(guchar)mmp_get_data[0]);
    	return FALSE;
	}
	
	/* success */
	return TRUE;
  }

static void
fu_logitech_whiteboardcams_helper_free(FuLogitechWhiteboardcamsHelper *helper)
{
	if (helper->error != NULL)
		g_error_free(helper->error);
	g_byte_array_unref(helper->buf_pkt);
	g_slice_free(FuLogitechWhiteboardcamsHelper, helper);
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
G_DEFINE_AUTOPTR_CLEANUP_FUNC(FuLogitechWhiteboardcamsHelper,
			      fu_logitech_whiteboardcams_helper_free)
#pragma clang diagnostic pop

static void
fu_logitech_whiteboardcams_device_to_string(FuDevice *device, guint idt, GString *str)
{
	FuLogitechWhiteboardcamsDevice *self = FU_LOGITECH_WHITEBOARDCAMS_DEVICE(device);
	fu_string_append(str,
			 idt,
			 "Status",
			 fu_logitech_whiteboardcams_device_status_to_string(self->status));
	fu_string_append(
	    str,
	    idt,
	    "UpdateState",
	    fu_logitech_whiteboardcams_device_update_state_to_string(self->update_status));
}

static gboolean
fu_logitech_whiteboardcams_device_probe(FuDevice *device, GError **error)
{
	g_debug("SRS LOGITECH_PLUGIN Inside %s", "fu_logitech_whiteboardcams_device_probe");
	/* check is valid */
	if (g_strcmp0(fu_udev_device_get_subsystem(FU_UDEV_DEVICE(device)), "video4linux") != 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "is not correct subsystem=%s, expected video4linux",
			    fu_udev_device_get_subsystem(FU_UDEV_DEVICE(device)));
		return FALSE;
	}
	/*if (fu_udev_device_get_device_file(FU_UDEV_DEVICE(device)) == NULL) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_NOT_SUPPORTED,
				    "no device file");
		g_debug("SRS LOGITECH_PLUGIN Inside %s", "fu_logitech_whiteboardcams_device_probe ERROR");
		return FALSE;
	}*/
	/* only enumerate number 0. TODO how to ignore siblings like video1/video2/video3 etc?*/
	if (fu_udev_device_get_number(FU_UDEV_DEVICE(device)) != 0) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_NOT_SUPPORTED,
				    "only device 0 supported on multi-device card");
		return FALSE;
	}
	/* set the physical ID */
	return fu_udev_device_set_physical_id(FU_UDEV_DEVICE(device), "video4linux", error);
}

/*
static gboolean
fu_logitech_whiteboardcams_device_get_data(FuDevice *device, gboolean send_req, GError **error)
{
	FuLogitechWhiteboardcamsDevice *self = FU_LOGITECH_WHITEBOARDCAMS_DEVICE(device);

	g_debug("SRS LOGITECH_PLUGIN Inside %s", "fu_logitech_whiteboardcams_device_get_data");
	if (g_getenv("FWUPD_LOGITECH_WHITEBOARDCAMS_VERBOSE") != NULL) {
		g_debug("Received fu_logitech_whiteboardcams_device_get_data.");
	}

	//fu_device_set_name(device, "BrioName");
	//fu_device_set_version(device, "1.1.0");
	// SRS:TBD NEEDED? fu_device_add_instance_id(device, "Brio Type");
	self->status = kDeviceStateUnknown;
	self->update_status = kUpdateStateUnknown;
	self->update_progress = 0;

	if (g_getenv("FWUPD_LOGITECH_WHITEBOARDCAMS_VERBOSE") != NULL) {
		g_debug("Leaving fu_logitech_whiteboardcams_device_get_data.");
	}

	return TRUE;
}
*/

static gboolean
fu_logitech_whiteboardcams_device_finalize_cb(FuDevice *device,
						       gpointer user_data,
						       GError **error)
{
	FuLogitechWhiteboardcamsDevice *self = FU_LOGITECH_WHITEBOARDCAMS_DEVICE(device);
	return fu_logitech_whiteboardcams_device_ait_finalize_update(self, error);
}

static gboolean
fu_logitech_whiteboardcams_device_write_firmware(FuDevice *device,
						 FuFirmware *firmware,
						 FuProgress *progress,
						 FwupdInstallFlags flags,
						 GError **error)
{
	FuLogitechWhiteboardcamsDevice *self = FU_LOGITECH_WHITEBOARDCAMS_DEVICE(device);
	g_autofree gchar *old_firmware_version = NULL;
	g_debug("SRS LOGITECH_PLUGIN Inside %s", "fu_logitech_whiteboardcams_device_write_firmware");
	/* progress */
	fu_progress_set_id(progress, G_STRLOC);
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_BUSY, 1, "init");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_WRITE, 48, "device-write-blocks");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_BUSY, 1, "end-transfer");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_BUSY, 1, "uninit");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_VERIFY, 49, NULL);

    /* init */
	if (!fu_logitech_whiteboardcams_device_ait_initiate_update(self, 
			error))
		return FALSE;
	//g_usleep(G_TIME_SPAN_SECOND);
	fu_progress_step_done(progress);


    /* device-write-blocks */
	//g_usleep(G_TIME_SPAN_SECOND);
	fu_progress_step_done(progress);

        /* end-transfer */
	g_usleep(G_TIME_SPAN_SECOND);
	fu_progress_step_done(progress);

    /* uninit */
	//g_usleep(G_TIME_SPAN_SECOND);
	if (!fu_device_retry(device,
			     fu_logitech_whiteboardcams_device_finalize_cb,
			     MAX_RETRIES,
			     NULL,
			     error)) {
		g_prefix_error(error,
			       "failed to write flash: please reboot the device: ");
		return FALSE;
	}
	fu_progress_step_done(progress);


	g_usleep(G_TIME_SPAN_SECOND);
	/* save the current firmware version for troubleshooting purpose */
	old_firmware_version = g_strdup(fu_device_get_version(device));
	if (g_getenv("FWUPD_LOGITECH_WHITEBOARDCAMS_VERBOSE") != NULL) {
		g_debug("new firmware version: %s, old firmware version: %s, "
			"rebooting...",
			fu_device_get_version(device),
			old_firmware_version);
	}
	fu_progress_step_done(progress);

	/* success! SRS TODO */
	return FALSE;
}

static gboolean
fu_logitech_whiteboardcams_device_get_tde_mode(FuDevice *device, GError **error)
{
	FuLogitechWhiteboardcamsDevice *self = FU_LOGITECH_WHITEBOARDCAMS_DEVICE(device);
	g_autofree gchar *fwversion_str = NULL;
	guint32 fwversion = 0;
	guint16 data_len = 0;
	g_autofree guint8 *query_data = NULL;
	g_debug("SRS LOGITECH_PLUGIN Inside %s", "fu_logitech_whiteboardcams_device_get_tde_mode");

	if (g_getenv("FWUPD_LOGITECH_WHITEBOARDCAMS_VERBOSE") != NULL) {
		g_debug("Received fu_logitech_whiteboardcams_device_get_tde_mode");
	}

	/* load current TDE mode */
	if (!fu_logitech_whiteboardcams_device_query_data_size(self, kLogiUnitIdGuidTestAndDebug, kLogiUvcXuTdeModeSelector, &data_len, error))
		return FALSE;
	query_data = g_malloc0(data_len);
	if (!fu_logitech_whiteboardcams_device_get_xu_control(self, 
			kLogiUnitIdGuidTestAndDebug, 
			kLogiUvcXuTdeModeSelector,
			data_len, 
			(guchar *)query_data, 
			error)) {
		g_prefix_error(error, "failed to query tde mode: ");
    	return FALSE;
		}
	if (g_getenv("FWUPD_LOGITECH_WHITEBOARDCAMS_VERBOSE") != NULL) {
		g_debug("Current TDE mode: %u", query_data[0]);
	}
    if (query_data[0] != kLogiUvcXuTestDbgTdeModeEnable)
		return FALSE;

	/* success SRS TODO */
	return TRUE;
}

static gboolean
fu_logitech_whiteboardcams_device_set_tde_mode(FuLogitechWhiteboardcamsDevice *self,
						GError **error) 
{

	guint16 data_len = 0;
	g_autofree guint8 *mmp_get_data = NULL;
	guint8 set_tde_mode_data[] = {kLogiUvcXuTestDbgTdeModeEnable};
	if (g_getenv("FWUPD_LOGITECH_WHITEBOARDCAMS_VERBOSE") != NULL) {
		g_debug("Set TDE mode request");
	}

	if (!fu_logitech_whiteboardcams_device_set_xu_control(self, 
			kLogiUnitIdGuidTestAndDebug, 
			kLogiUvcXuTdeModeSelector,
			sizeof(set_tde_mode_data), 
			(guchar *)&set_tde_mode_data, 
			error))  {
		g_prefix_error(error, "failed to set tde mode: ");
    	return FALSE;
		}
	if (g_getenv("FWUPD_LOGITECH_WHITEBOARDCAMS_VERBOSE") != NULL) {
		g_debug("Successfully set device into TDE mode");
	}
	/* success */
	return TRUE;
}

static gboolean
fu_logitech_whiteboardcams_device_setup(FuDevice *device, GError **error)
{
	FuLogitechWhiteboardcamsDevice *self = FU_LOGITECH_WHITEBOARDCAMS_DEVICE(device);
	//guint32 success = 0;
	//guint32 error_code = 0;
	//g_autoptr(GError) error_local = NULL;
	g_autofree gchar *fwversion_str = NULL;
	guint32 fwversion = 0;
	guint16 data_len = 0;
	g_autofree guint8 *query_data = NULL;
	g_autoptr(GUsbDevice) usb_device = NULL;
	g_debug("SRS LOGITECH_PLUGIN Inside %s", "fu_logitech_whiteboardcams_device_setup");

	if (g_getenv("FWUPD_LOGITECH_WHITEBOARDCAMS_VERBOSE") != NULL) {
		g_debug("Received fu_logitech_whiteboardcams_device_setup");
	}

	/* load current device version data */
	if (!fu_logitech_whiteboardcams_device_query_data_size(self, kLogiUnitIdCameraVersion, kLogiCameraVersionSelector, &data_len, error))
		return FALSE;
	query_data = g_malloc0(data_len);
	if (!fu_logitech_whiteboardcams_device_get_xu_control(self, 
			kLogiUnitIdCameraVersion, 
			kLogiCameraVersionSelector,
			data_len, 
			(guchar *)query_data, 
			error))
    	return FALSE;
	//  little-endian data. MinorVersion byte 0, MajorVersion byte 1, BuildVersion byte 3 & 2 
	fwversion = (query_data[1] << 24) + (query_data[0] << 16) + (query_data[3] << 8) + query_data[2];
	fwversion_str = fu_version_from_uint32(fwversion, FWUPD_VERSION_FORMAT_TRIPLET);
	fu_device_set_version(device, fwversion_str);
	if (g_getenv("FWUPD_LOGITECH_WHITEBOARDCAMS_VERBOSE") != NULL) {
		g_debug("Device version: %u, string %s ", fwversion, fwversion_str);
	}

	/* convert GUdevDevice to GUsbDevice */
	usb_device = fu_udev_device_find_usb_device(FU_UDEV_DEVICE(device), error);
	if (usb_device == NULL)
		return FALSE;
g_debug("SRS LOGITECH_PLUGIN Successfully Leaving %s", "fu_logitech_whiteboardcams_device_setup");

	/* success SRS TODO */
	return TRUE;
}

static void
fu_logitech_whiteboardcams_device_set_progress(FuDevice *self, FuProgress *progress)
{
	g_debug("SRS LOGITECH_PLUGIN Inside %s", "fu_logitech_whiteboardcams_device_set_progress");
	fu_progress_set_id(progress, G_STRLOC);
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_RESTART, 0, "detach");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_WRITE, 99, "write");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_RESTART, 0, "attach");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_BUSY, 1, "reload");
}

static void
fu_logitech_whiteboardcams_device_init(FuLogitechWhiteboardcamsDevice *self)
{
	g_debug("SRS LOGITECH_PLUGIN Inside %s", "fu_logitech_whiteboardcams_device_init");
	fu_device_add_protocol(FU_DEVICE(self), "com.logitech.vc.whiteboardcams");
	fu_device_set_version_format(FU_DEVICE(self), FWUPD_VERSION_FORMAT_TRIPLET);
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_UPDATABLE);
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_UNSIGNED_PAYLOAD); // SRS TODO
	fu_device_retry_set_delay(FU_DEVICE(self), 2000);
	fu_device_set_remove_delay(FU_DEVICE(self), 100000); // >1 min to finish init
	fu_udev_device_set_flags(FU_UDEV_DEVICE(self), 
		FU_UDEV_DEVICE_FLAG_OPEN_READ | FU_UDEV_DEVICE_FLAG_OPEN_WRITE);
}

static void
fu_logitech_whiteboardcams_device_finalize(GObject *object)
{
	g_debug("SRS LOGITECH_PLUGIN Inside %s", "fu_logitech_whiteboardcams_device_finalize");
	G_OBJECT_CLASS(fu_logitech_whiteboardcams_device_parent_class)->finalize(object);
}

static void
fu_logitech_whiteboardcams_device_class_init(FuLogitechWhiteboardcamsDeviceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	FuDeviceClass *klass_device = FU_DEVICE_CLASS(klass);
	g_debug("SRS LOGITECH_PLUGIN Inside %s", "fu_logitech_whiteboardcams_device_class_init");
	object_class->finalize = fu_logitech_whiteboardcams_device_finalize;
	klass_device->to_string = fu_logitech_whiteboardcams_device_to_string;
	klass_device->write_firmware = fu_logitech_whiteboardcams_device_write_firmware;
	klass_device->probe = fu_logitech_whiteboardcams_device_probe;
	klass_device->setup = fu_logitech_whiteboardcams_device_setup;
	klass_device->set_progress = fu_logitech_whiteboardcams_device_set_progress;
}
