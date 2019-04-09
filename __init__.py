from .objcview import ObjcView
from .selectors import define_selectors_plugin
from .cfstring import define_cfstrings_plugin
from .types import define_types_plugin
from .classes import define_classes_plugin

from binaryninja import PluginCommand

# ObjcView.register()

PluginCommand.register(
    'Objc\\Define selectors',
    'Define selector strings in Objective-C sections',
    define_selectors_plugin,
    is_valid=lambda v: '__objc_classname' in v.sections
)

PluginCommand.register(
    'Objc\\Define CFStrings',
    'Define CFStrings in Objective-C sections',
    define_cfstrings_plugin,
    is_valid=lambda v: '__cfstring' in v.sections
)

PluginCommand.register(
    'Objc\\Define types',
    'Define Objective-C types',
    define_types_plugin,
    is_valid=lambda v: '__objc_classname' in v.sections
)

PluginCommand.register(
    'Objc\\Define classes',
    'Define Objective-C classes',
    define_classes_plugin,
    is_valid=lambda v: '__objc_data' in v.sections
)

def _run_all_plugins(view):
    define_types_plugin(view)
    define_selectors_plugin(view)
    define_cfstrings_plugin(view)
    define_classes_plugin(view)

PluginCommand.register(
    "Objc\\Run all",
    "Run all Objective-C plugins",
    _run_all_plugins,
    is_valid=lambda v: '__objc_data' in v.sections
)