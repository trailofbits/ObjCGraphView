from functools import partial

from binaryninja import PluginCommand, BackgroundTaskThread
from binaryninjaui import ViewType

from .cfstring import define_cfstrings_plugin
from .classes import define_classes_plugin
from .methods import define_methods
from .objcgraph import ObjcFlowGraphViewType
from .objcview import ObjcView
from .selectors import define_selectors_plugin
from .types import define_types_plugin

# ObjcView.register()

PluginCommand.register(
    'Objc\\Define selectors',
    'Define selector strings in Objective-C sections',
    define_selectors_plugin,
    is_valid=lambda v: '__objc_classname' in v.sections or '__objc_selrefs' in v.sections
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
    is_valid=lambda v: '__objc_classrefs' in v.sections
)

PluginCommand.register(
    'Objc\\Define classes',
    'Define Objective-C classes',
    define_classes_plugin,
    is_valid=lambda v: '__objc_data' in v.sections
)

class ObjectiveCTaskThread(BackgroundTaskThread):
    def __init__(self, view):
        super().__init__('Defining Objective-C Structures...')
        self.view = view

    def run(self):
        define_types_plugin(self.view)

        self.progress = 'Defining Objective-C selectors...'
        define_selectors_plugin(self.view)

        self.progress = 'Defining CFStrings...'
        define_cfstrings_plugin(self.view)

        self.progress = 'Defining Objective-C classes...'
        define_classes_plugin(self.view)

        self.progress = 'Defining Objective-C methods...'
        define_methods(self.view)

def _run_all_plugins(view):
    if view.session_data.get('ClassList'):
        return
    
    ObjectiveCTaskThread(view).start()

PluginCommand.register(
    "Objc\\Run all",
    "Run all Objective-C plugins",
    _run_all_plugins,
    is_valid=lambda v: '__objc_data' in v.sections
)

ViewType.registerViewType(ObjcFlowGraphViewType())
