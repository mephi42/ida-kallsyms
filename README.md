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

# build-vmlinux

Script for building and extracting additional information from a Linux Kernel
that is similar to the one being analyzed. It produces `vmlinux.like.json`
file, that is automatically picked up by `ghidra-kallsyms.py`.

## Usage

* `git clone https://github.com/mephi42/ida-kallsyms.git`
* `ida-kallsyms/build-vmlinux --like vmlinux`
* Use `ghidra-kallsyms.py` as described above.
