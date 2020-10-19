# ida-kallsyms

IDA script for parsing kallsyms.

## Usage

* `git clone https://github.com/mephi42/ida-kallsyms.git`
* Open the kernel in IDA, let the autoanalysis finish.
* From `File` &#8594; `Script file...` (Alt+F7 / Alt+F9) run
  `ida-kallsyms/ida-kallsyms.py` script.

## Usage with Ghidra

* `git clone https://github.com/mephi42/ida-kallsyms.git`
* Open the kernel in Ghidra, let the autoanalysis finish.
* Go to `Window` &#8594; `Script manager`.
* Once: press `Script Directories` button and add `ida-kallsyms`.
* In `Filter` edit box, type `kallsyms`.
* Double-click `ghidra-kallsyms.py` and wait.

## Stand-alone usage

* `git clone https://github.com/mephi42/ida-kallsyms.git`
* `ida-kallsyms/find-kallsyms vmlinux >vmlinux.kallsyms`
* The resulting `vmlinux.kallsyms` file can be imported into IDA using
  `ida-kallsyms-import.py` script.

# build-vmlinux

Script for obtaining function signatures and struct layouts. Works by building
a Linux Kernel that is similar to the one being analyzed and extracting debug
information from it.

## Usage

* Load kallsyms into IDA as described above.
* `ida-kallsyms/build-vmlinux --like vmlinux`

  This will run for a while and generate `vmlinux.like.json` file.

  Check out `ida-kallsyms/build-vmlinux --help` in case you already have
  `binutils-gdb` / `gcc` / `linux` local git repos or a `.config` that
  matches `vmlinux`.
* Import `vmlinux.like.json` into IDA using `ida-kallsyms/ida-like-import.py`
  script.
* If there are import errors, check `vmlinux.like.json.log` file.
