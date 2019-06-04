# ObjCGraphView: An Objective-C Binary Ninja plugin

## Requirements
This plugin requires Python 3.7+, and Binary Ninja 1.1.1706-dev or newer.

## Installation
```sh
git clone https://github.com/trailofbits/ObjCGraphView
ln -s ObjCGraphView "`python -c 'import binaryninja;print(binaryninja.user_plugin_path())'`"
```

## Using
After opening a Objective-C Mach-O binary, run the `Objc\Run all` plugin. This will process all of the Objective-C classes and methods.

After running the plugin, the Objective-C Graph View will be available. Select it from the available views in the bottom right corner.

## Acknowledgements
Special thanks to @melomac for advice and testing during development!