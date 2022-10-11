if gusb.found()

cargs = ['-DG_LOG_DOMAIN="FuPluginLogitechWhiteboardcams"']

install_data(['logitech-whiteboardcams.quirk'],
  install_dir: join_paths(get_option('datadir'), 'fwupd', 'quirks.d')
)

shared_module('fu_plugin_logitech_whiteboardcams',
  fu_hash,
  sources : [
    'fu-logitech-whiteboardcams-device.c',
    'fu-plugin-logitech-whiteboardcams.c',
  ],
  include_directories : [
    root_incdir,
    fwupd_incdir,
    fwupdplugin_incdir,
  ],
  install : true,
  install_dir: plugin_dir,
  link_with : [
    fwupd,
    fwupdplugin,
  ],
  c_args : cargs,
  dependencies : [
    plugin_deps,
  ],
)
endif
