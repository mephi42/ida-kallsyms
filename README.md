# ida-kallsyms

IDA script for parsing kallsyms.

## Usage

* `git clone https://github.com/mephi42/ida-kallsyms.git`
* Open the kernel in IDA, let the autoanalysis finish.
* Go to `File` &#8594; `Script file...` or press Alt+F7.
* Select `ida-kallsyms/ida-kallsyms.py` and wait.

## Usage with Ghidra

* `git clone https://github.com/mephi42/ida-kallsyms.git`
* Open the kernel in Ghidra, let the autoanalysis finish.
* Go to `Window` &#8594; `Script manager`.
* Once: press `Script Directories` button and add `ida-kallsyms`.
* In `Filter` edit box, type `kallsyms`.
* Double-click `ghidra-kallsyms.py` and wait.

## Stand-alone usage

* `git clone https://github.com/mephi42/ida-kallsyms.git`
* `ida-kallsyms/find-kallsyms vmlinux >kallsyms`
* The resulting `kallsyms` file can be imported into IDA by going to `File`
  &#8594; `Script file...` or pressing Alt+F7, selecting
  `ida-kallsyms-import.py` script and then choosing the `kallsyms` file.

# build-vmlinux

Script for obtaining function signatures and struct layouts. Works by building
a Linux Kernel that is similar to the one being analyzed and extracting debug
information from it.

## Usage

* `git clone https://github.com/mephi42/ida-kallsyms.git`
* `ida-kallsyms/build-vmlinux --like vmlinux`

  This will run for a while and generate `vmlinux.like.json` file.

  Check out `ida-kallsyms/build-vmlinux --help` in case you already have
  `binutils-gdb` / `gcc` / `linux` local git repos or a `.config` that
  matches `vmlinux`.
* Load kallsyms as described above.
* Go to `File` &#8594; `Script file...` or press Alt+F7.
* Select `ida-kallsyms/ida-like-import.py` and choose `vmlinux.like.json`.
