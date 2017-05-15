# Java-dumper
Immunity Debugger python plugin, which provides to dump java classes from ROM during jvm processing.

## Installation
Move `java-dumper.py` to Immunity Debugger `PyCommands`-folder

## Usage

```
!java-dumper	[options] [hooks]						    
options:		-v 	-H
              	-v	enable verbosity
			   	-H  heaps scan
hooks:			-c 	-r 	-C
              	-c  checks CreateFileW calls
              	-r  checks ReadFile calls
              	-C  checks CloseHandle calls
```
