**All paths mentioned will be relative to `/opt/CyberPatriot` on Linux, and `C:/CyberPatriot` on Windows.**

## Requirements
* [Rust](https://www.rust-lang.org/tools/install) 1.56.0 or higher

## Building
* Clone the repository: `git clone https://github.com/matteopolak/ccsclient.git`
* Enter the directory: `cd ccsclient`
* Build the project: `cargo build --release`

## Required files & folders
* `files.dat`, a new-line seperated list of absolute paths to search
* `dists`, a folder that contains copies of all files to be scanned, named after the SHA512 hash of their absolute path
* `hashes`, a folder that contains empty files with the names of answer hashes in SHA512 format
* `CCSCheck`, the executable to verify answers; [get it from here](https://github.com/matteopolak/ccscheck)