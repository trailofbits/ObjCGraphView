# Unnamed Objective-C Binary Ninja plugin

## Installation
```sh
git clone https://github.com/joshwatson/objective-by-the-sea
ln -s `pwd`/objective-by-the-sea ~/Library/Application\ Support/Binary\ Ninja/plugins/
```

## Using
After opening a Objective-C Mach-O binary, run the `Objc\Run all` plugin. This will process all of the Objective-C classes and methods.

After running the plugin, the Objective-C Graph View will be available. Select it from the available views in the bottom right corner.