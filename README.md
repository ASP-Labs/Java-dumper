# Java-dumper
Immunity Debugger python plugin, which provides to dump java classes from ROM via jvm processing.

## Installation
Move `java-dumper.py` to Immunity Debugger `PyCommands`-folder

## Usage
```
!java-dumper [-s] [-i] [-f]
              -s   standart scan, checks each CreateFileW call
              -i   intensive scan, [-s] plus checks each ReadFile call
              -f   full scan, [-s, -i] plus checks each CloseHandle call
```

## Dependencies
This plugin requires next additional `Python 2.7` modules:
* binascii
* struct
* time