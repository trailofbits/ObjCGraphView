from binaryninja.binaryview import BinaryView
from binaryninja.log import log_debug

_macho_types = (
    'Fat Mach-O x86_64',
    'Fat Mach-O x86',
    'Mach-O'
)

def callback(self):
    log_debug(f"I'm in an analysis completion event! {self.view}")

# This isn't actually a new BinaryView; it merely serves
# as a way to hijack control briefly while opening a new
# Mach-O (or Fat Mach-O) binary to determine if it is an
# Objective-C binary. If it is, we apply an analysis
# completion event callback that will execute as soon
# as the initial analysis completes.
class ObjcView(BinaryView):
    name = 'Objc'
    long_name = 'Objc'

    @classmethod
    def is_valid_for_data(self, data):
        for view_type in _macho_types:
            macho: BinaryView = data.get_view_of_type(view_type)
            if macho is not None and '__cfstring' in macho.sections:
                try:
                    macho.query_metadata('objc_init')
                except:
                    macho.store_metadata('objc_init', True)
                    macho.add_analysis_completion_event(callback)
                    log_debug(f"Found an Objective-C binary!")

        # Return False so we are not added as a valid BinaryView
        return False