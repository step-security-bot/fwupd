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

#include "fu-logitech-whiteboardcams-device.h"

/* SYNC interface follows TLSV (Type, Length, SequenceID, Value) protocol */
/* UPD interface follows TLV (Type, Length, Value) protocol */
/* Payload size limited to 8k for both interfaces */
#define UPD_PACKET_HEADER_SIZE	      (2 * sizeof(guint32))
#define SYNC_PACKET_HEADER_SIZE	      (3 * sizeof(guint32))
#define HASH_TIMEOUT		      300 /* SRS TODO */
#define MAX_DATA_SIZE		      8192 /* 8k */
#define PAYLOAD_SIZE		      MAX_DATA_SIZE - UPD_PACKET_HEADER_SIZE
#define UPD_INTERFACE_SUBPROTOCOL_ID  101
#define SYNC_INTERFACE_SUBPROTOCOL_ID 118
#define BULK_TRANSFER_TIMEOUT	      1000
#define HASH_VALUE_SIZE		      16
#define LENGTH_OFFSET		      0x4
#define COMMAND_OFFSET		      0x0
#define SYNC_ACK_PAYLOAD_LENGTH	      5
#define MAX_RETRIES		      5
#define MAX_HANDSHAKE_RETRIES	      3
#define MAX_WAIT_COUNT		      150

#define SESSION_TIMEOUT	              1000

enum { SHA_256, SHA_512, MD5 };

enum { EP_OUT, EP_IN, EP_LAST };

enum { BULK_INTERFACE_UPD, BULK_INTERFACE_SYNC };

typedef enum {
	CMD_CHECK_BUFFERSIZE = 0xCC00,
	CMD_INIT = 0xCC01,
	CMD_START_TRANSFER = 0xCC02,
	CMD_DATA_TRANSFER = 0xCC03,
	CMD_END_TRANSFER = 0xCC04,
	CMD_UNINIT = 0xCC05,
	CMD_BUFFER_READ = 0xCC06,
	CMD_BUFFER_WRITE = 0xCC07,
	CMD_UNINIT_BUFFER = 0xCC08,
	CMD_ACK = 0xFF01,
	CMD_TIMEOUT = 0xFF02,
	CMD_NACK = 0xFF03
} UsbCommands;

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

struct _FuLogitechWhiteboardcamsDevice {
	FuUdevDevice parent_instance;
	FuUsbDevice *usb_device;
	guint update_ep[EP_LAST];
	guint update_iface;
	guint update_progress; /* percentage value */
};

G_DEFINE_TYPE(FuLogitechWhiteboardcamsDevice, fu_logitech_whiteboardcams_device, FU_TYPE_UDEV_DEVICE)


static gboolean
fu_logitech_whiteboardcams_device_detach(FuDevice *device, FuProgress *progress, GError **error)
{
	// TODO
	return TRUE;
}

static gboolean
fu_logitech_whiteboardcams_device_attach(FuDevice *device, FuProgress *progress, GError **error)
{
	FuLogitechWhiteboardcamsDevice *self = FU_LOGITECH_WHITEBOARDCAMS_DEVICE(device);
	// TODO
	fu_device_add_flag(FU_DEVICE(device), FWUPD_DEVICE_FLAG_WAIT_FOR_REPLUG);
	return TRUE;
}

static gboolean
fu_logitech_whiteboardcams_device_reload(FuDevice *device, GError **error)
{
	// TODO
	return TRUE;
}

static gboolean
fu_logitech_whiteboardcams_device_rescan(FuDevice *device, GError **error)
{
	// TODO
	return TRUE;
}

static gboolean
fu_logitech_whiteboardcams_device_send(FuLogitechWhiteboardcamsDevice *self,
				       GByteArray *buf,
				       gint interface_id,
				       GError **error)
{
	gsize transferred = 0;
	gint ep;
	GCancellable *cancellable = NULL;
	g_return_val_if_fail(buf != NULL, FALSE);

	if (interface_id == BULK_INTERFACE_UPD) {
		ep = self->update_ep[EP_OUT];
	} else {
		g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_FAILED, "interface is invalid");
		return FALSE;
	}
	if (!g_usb_device_bulk_transfer(fu_usb_device_get_dev(FU_USB_DEVICE(self->usb_device)),
					ep,
					(guint8 *)buf->data,
					buf->len,
					&transferred,
					BULK_TRANSFER_TIMEOUT,
					cancellable,
					error)) {
		g_prefix_error(error, "failed to send using bulk transfer: ");
		return FALSE;
	}
	return TRUE;
}

static gboolean
fu_logitech_whiteboardcams_device_recv(FuLogitechWhiteboardcamsDevice *self,
				       GByteArray *buf,
				       gint interface_id,
				       guint timeout,
				       GError **error)
{
	gsize received_length = 0;
	gint ep;
	g_return_val_if_fail(buf != NULL, FALSE);

	if (interface_id == BULK_INTERFACE_UPD) {
		ep = self->update_ep[EP_IN];
	} else {
		g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_FAILED, "interface is invalid");
		return FALSE;
	}
	if (!g_usb_device_bulk_transfer(fu_usb_device_get_dev(FU_USB_DEVICE(self->usb_device)),
					ep,
					buf->data,
					buf->len,
					&received_length,
					timeout,
					NULL,
					error)) {
		g_prefix_error(error, "failed to receive using bulk transfer: ");
		return FALSE;
	}
	return TRUE;
}

static gboolean
fu_logitech_whiteboardcams_device_send_upd_cmd(FuLogitechWhiteboardcamsDevice *self,
					       guint32 cmd,
					       GByteArray *buf,
					       GError **error)
{
	guint32 cmd_tmp = 0x0;
	guint timeout = BULK_TRANSFER_TIMEOUT;
	g_autoptr(GByteArray) buf_pkt = g_byte_array_new();
	g_autoptr(GByteArray) buf_ack = g_byte_array_new();

	fu_byte_array_append_uint32(buf_pkt, cmd, G_LITTLE_ENDIAN); /* Type(T) : Command type */
	fu_byte_array_append_uint32(buf_pkt,
				    buf != NULL ? buf->len : 0,
				    G_LITTLE_ENDIAN); /*Length(L) : Length of payload */
	if (buf != NULL) {
		g_byte_array_append(buf_pkt,
				    buf->data,
				    buf->len); /* Value(V) : Actual payload data */
	}
	if (!fu_logitech_whiteboardcams_device_send(self, buf_pkt, BULK_INTERFACE_UPD, error))
		return FALSE;

	/* receiving INIT ACK */
	fu_byte_array_set_size(buf_ack, MAX_DATA_SIZE, 0x00);

	/* extending the bulk transfer timeout value, as android device takes some time to
	   calculate Hash and respond */
	if (CMD_END_TRANSFER == cmd)
		timeout = HASH_TIMEOUT;

	if (!fu_logitech_whiteboardcams_device_recv(self,
						    buf_ack,
						    BULK_INTERFACE_UPD,
						    timeout,
						    error))
		return FALSE;

	if (!fu_memread_uint32_safe(buf_ack->data,
				    buf_ack->len,
				    COMMAND_OFFSET,
				    &cmd_tmp,
				    G_LITTLE_ENDIAN,
				    error))
		return FALSE;
	if (cmd_tmp != CMD_ACK) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "not CMD_ACK, got %x", cmd);
		return FALSE;
	}
	if (!fu_memread_uint32_safe(buf_ack->data,
				    buf_ack->len,
				    UPD_PACKET_HEADER_SIZE,
				    &cmd_tmp,
				    G_LITTLE_ENDIAN,
				    error))
		return FALSE;
	if (cmd_tmp != cmd) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "invalid upd message received, expected %x, got %x",
			    cmd,
			    cmd_tmp);
		return FALSE;
	}
	return TRUE;
}

static gchar *
fu_logitech_whiteboardcams_device_compute_hash(GBytes *data)
{
	guint8 md5buf[HASH_VALUE_SIZE] = {0};
	gsize data_len = sizeof(md5buf);
	GChecksum *checksum = g_checksum_new(G_CHECKSUM_MD5);
	g_checksum_update(checksum, g_bytes_get_data(data, NULL), g_bytes_get_size(data));
	g_checksum_get_digest(checksum, (guint8 *)&md5buf, &data_len);
	return g_base64_encode(md5buf, sizeof(md5buf));
}

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

static void
fu_logitech_whiteboardcams_device_to_string(FuDevice *device, guint idt, GString *str)
{
	FuLogitechWhiteboardcamsDevice *self = FU_LOGITECH_WHITEBOARDCAMS_DEVICE(device);
	// TODO
}

static gboolean
fu_logitech_whiteboardcams_device_probe(FuDevice *device, GError **error)
{
	/* check is valid */
	if (g_strcmp0(fu_udev_device_get_subsystem(FU_UDEV_DEVICE(device)), "video4linux") != 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "is not correct subsystem=%s, expected video4linux",
			    fu_udev_device_get_subsystem(FU_UDEV_DEVICE(device)));
		return FALSE;
	}

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

static gboolean
fu_logitech_whiteboardcams_device_send_upd_init_cmd_cb(FuDevice *device,
						       gpointer user_data,
						       GError **error)
{
	FuLogitechWhiteboardcamsDevice *self = FU_LOGITECH_WHITEBOARDCAMS_DEVICE(device);
	return fu_logitech_whiteboardcams_device_send_upd_cmd(self, CMD_INIT, NULL, error);
}

static gboolean
fu_logitech_whiteboardcams_device_write_fw(FuLogitechWhiteboardcamsDevice *self,
					   GBytes *fw,
					   FuProgress *progress,
					   GError **error)
{
	g_autoptr(GPtrArray) chunks = NULL;

	chunks = fu_chunk_array_new_from_bytes(fw, 0x0, 0x0, PAYLOAD_SIZE);
	fu_progress_set_id(progress, G_STRLOC);
	fu_progress_set_steps(progress, chunks->len);
	for (guint i = 0; i < chunks->len; i++) {
		FuChunk *chk = g_ptr_array_index(chunks, i);
		g_autoptr(GByteArray) data_pkt = g_byte_array_new();
		g_byte_array_append(data_pkt, fu_chunk_get_data(chk), fu_chunk_get_data_sz(chk));
		if (!fu_logitech_whiteboardcams_device_send_upd_cmd(self,
								    CMD_DATA_TRANSFER,
								    data_pkt,
								    error)) {
			g_prefix_error(error, "failed to send data packet 0x%x: ", i);
			return FALSE;
		}
		fu_progress_step_done(progress);
	}
	return TRUE;
}

static gboolean
fu_logitech_whiteboardcams_device_write_firmware(FuDevice *device,
						 FuFirmware *firmware,
						 FuProgress *progress,
						 FwupdInstallFlags flags,
						 GError **error)
{
	FuLogitechWhiteboardcamsDevice *self = FU_LOGITECH_WHITEBOARDCAMS_DEVICE(device);
	gboolean query_device = FALSE;	/* query or listen for events, periodically broadcasted */
	gint  max_wait = MAX_WAIT_COUNT; /* if firmware upgrade is taking forever to finish */
	guint max_no_response_count = MAX_RETRIES; /* device doesn't respond */
	guint no_response_count = 0;
	g_autofree gchar *base64hash = NULL;
	g_autoptr(GByteArray) end_pkt = g_byte_array_new();
	g_autoptr(GByteArray) start_pkt = g_byte_array_new();
	g_autoptr(GBytes) fw = NULL;
	g_autofree gchar *old_firmware_version = NULL;
	g_autoptr(GError) error_local = NULL;

	/* progress */
	fu_progress_set_id(progress, G_STRLOC);
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_BUSY, 1, "init");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_WRITE, 88, "device-write-blocks");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_BUSY, 1, "end-transfer");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_BUSY, 5, "uninit");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_VERIFY, 5, NULL);

	/* get default image */
	fw = fu_firmware_get_bytes(firmware, error);
	if (fw == NULL)
		return FALSE;

	/* sending INIT. Retry if device is not in IDLE state to receive the file */
	if (!fu_device_retry(device,
			     fu_logitech_whiteboardcams_device_send_upd_init_cmd_cb,
			     MAX_RETRIES,
			     NULL,
			     error)) {
		g_prefix_error(error,
			       "failed to write init transfer packet: please reboot the device: ");
		return FALSE;
	}

	/* transfer sent */
	fu_byte_array_append_uint64(start_pkt, g_bytes_get_size(fw), G_LITTLE_ENDIAN);
	if (!fu_logitech_whiteboardcams_device_send_upd_cmd(self,
							    CMD_START_TRANSFER,
							    start_pkt,
							    error)) {
		g_prefix_error(error, "failed to write start transfer packet: ");
		return FALSE;
	}
	fu_progress_step_done(progress);

	/* push each block to device */
	if (!fu_logitech_whiteboardcams_device_write_fw(self,
							fw,
							fu_progress_get_child(progress),
							error))
		return FALSE;
	fu_progress_step_done(progress);

	/* sending end transfer */
	base64hash = fu_logitech_whiteboardcams_device_compute_hash(fw);
	fu_byte_array_append_uint32(end_pkt, 1, G_LITTLE_ENDIAN);   /* update */
	fu_byte_array_append_uint32(end_pkt, 0, G_LITTLE_ENDIAN);   /* force */
	fu_byte_array_append_uint32(end_pkt, MD5, G_LITTLE_ENDIAN); /* checksum type */
	g_byte_array_append(end_pkt, (const guint8 *)base64hash, strlen(base64hash));
	if (!fu_logitech_whiteboardcams_device_send_upd_cmd(self,
							    CMD_END_TRANSFER,
							    end_pkt,
							    error)) {
		g_prefix_error(error, "failed to write end transfer transfer packet: ");
		return FALSE;
	}
	fu_progress_step_done(progress);

	/* send uninit */
	if (!fu_logitech_whiteboardcams_device_send_upd_cmd(self, CMD_UNINIT, NULL, error_local)) {
		g_debug("SRS LOGITECH_PLUGIN failed to write finish transfer packet:");
		//g_prefix_error(error, "failed to write finish transfer packet: ");
		//return FALSE; // SRS: TODO
	}
	fu_progress_step_done(progress);

	/*
	 * image file pushed. Device validates and uploads new image on inactive partition. Reboots
	 */
	g_usleep(G_TIME_SPAN_SECOND);
	fu_progress_step_done(progress);

	/* success! */
	return TRUE;
}

static gboolean
fu_logitech_whiteboardcams_device_set_version(FuDevice *device, 
GError **error) 
{
	FuLogitechWhiteboardcamsDevice *self = FU_LOGITECH_WHITEBOARDCAMS_DEVICE(device);
	g_autofree gchar *fwversion_str = NULL;
	guint32 fwversion = 0;
	guint16 data_len = 0;
	g_autofree guint8 *query_data = NULL;
	/* query current device version */
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
		g_info("Device version: %u, string %s ", fwversion, fwversion_str);
	}
	/* success */
	return TRUE;
}

static gboolean
fu_logitech_whiteboardcams_device_setup(FuDevice *device, GError **error)
{
	FuLogitechWhiteboardcamsDevice *self = FU_LOGITECH_WHITEBOARDCAMS_DEVICE(device);
	g_autoptr(GPtrArray) intfs = NULL;
	g_autoptr(GUsbDevice) g_usb_device = NULL;

	if (g_getenv("FWUPD_LOGITECH_WHITEBOARDCAMS_VERBOSE") != NULL) {
		g_debug("Received fu_logitech_whiteboardcams_device_setup");
	}

	if (!fu_logitech_whiteboardcams_device_set_version(device, error))
    		return FALSE;

	/* convert GUdevDevice to GUsbDevice */
	g_usb_device = fu_udev_device_find_usb_device(FU_UDEV_DEVICE(device), error);
	if (g_usb_device == NULL)
		return FALSE;
	self->usb_device =
	    fu_usb_device_new(fu_device_get_context(device), g_usb_device);
	if (self->usb_device == NULL)
		return FALSE;

	/* re-open with new device set */
	fu_usb_device_set_dev(self->usb_device, g_usb_device);
	if (!fu_device_open(FU_DEVICE(self->usb_device), error))
		return FALSE;

	intfs = g_usb_device_get_interfaces(fu_usb_device_get_dev(FU_USB_DEVICE(self->usb_device)), error);
	if (intfs == NULL)
		return FALSE;
	for (guint i = 0; i < intfs->len; i++) {
		GUsbInterface *intf = g_ptr_array_index(intfs, i);
		if (g_usb_interface_get_class(intf) == G_USB_DEVICE_CLASS_VENDOR_SPECIFIC &&
		    g_usb_interface_get_protocol(intf) == 0x1) {
			if (g_usb_interface_get_subclass(intf) ==
				   UPD_INTERFACE_SUBPROTOCOL_ID) {
				g_autoptr(GPtrArray) endpoints =
				    g_usb_interface_get_endpoints(intf);
				self->update_iface = g_usb_interface_get_number(intf);
				if (endpoints == NULL)
					continue;
				for (guint j = 0; j < endpoints->len; j++) {
					GUsbEndpoint *ep = g_ptr_array_index(endpoints, j);
					if (j == EP_OUT)
						self->update_ep[EP_OUT] =
						    g_usb_endpoint_get_address(ep);
					else
						self->update_ep[EP_IN] =
						    g_usb_endpoint_get_address(ep);
				}
			}
		}
	}
	fu_usb_device_add_interface(self->usb_device, self->update_iface);
	if (g_getenv("FWUPD_LOGITECH_WHITEBOARDCAMS_VERBOSE") != NULL) {
		g_debug("IFace: %u OUT: %u IN: %u", self->update_iface, self->update_ep[EP_OUT], self->update_ep[EP_IN]);
	}
	/* success */
	return TRUE;
}

static void
fu_logitech_whiteboardcams_device_set_progress(FuDevice *self, FuProgress *progress)
{
	fu_progress_set_id(progress, G_STRLOC);
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_RESTART, 0, "detach");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_WRITE, 35, "write");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_RESTART, 0, "attach");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_BUSY, 65, "reload");
}

static void
fu_logitech_whiteboardcams_device_init(FuLogitechWhiteboardcamsDevice *self)
{
	fu_device_add_protocol(FU_DEVICE(self), "com.logitech.vc.whiteboardcams");
	fu_device_set_version_format(FU_DEVICE(self), FWUPD_VERSION_FORMAT_TRIPLET);
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_UPDATABLE);
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_UNSIGNED_PAYLOAD); // SRS TODO
	fu_device_retry_set_delay(FU_DEVICE(self), 1000);
	//fu_device_set_remove_delay(FU_DEVICE(self), 120000); // ~2 min to finish init/reload
	fu_udev_device_set_flags(FU_UDEV_DEVICE(self), 
		FU_UDEV_DEVICE_FLAG_OPEN_READ | FU_UDEV_DEVICE_FLAG_OPEN_WRITE);
}

static void
fu_logitech_whiteboardcams_device_finalize(GObject *object)
{
	// TODO
	G_OBJECT_CLASS(fu_logitech_whiteboardcams_device_parent_class)->finalize(object);
}

static void
fu_logitech_whiteboardcams_device_class_init(FuLogitechWhiteboardcamsDeviceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	FuDeviceClass *klass_device = FU_DEVICE_CLASS(klass);
	object_class->finalize = fu_logitech_whiteboardcams_device_finalize;
	klass_device->to_string = fu_logitech_whiteboardcams_device_to_string;
	klass_device->write_firmware = fu_logitech_whiteboardcams_device_write_firmware;
	klass_device->probe = fu_logitech_whiteboardcams_device_probe;
	klass_device->setup = fu_logitech_whiteboardcams_device_setup;
	klass_device->set_progress = fu_logitech_whiteboardcams_device_set_progress;
	klass_device->attach = fu_logitech_whiteboardcams_device_attach;
	klass_device->detach = fu_logitech_whiteboardcams_device_detach;
	klass_device->reload = fu_logitech_whiteboardcams_device_reload;
	klass_device->rescan = fu_logitech_whiteboardcams_device_rescan;
}
