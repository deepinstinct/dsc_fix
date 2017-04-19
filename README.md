# dyld shared cache references fix
## Synopsis
This script helps reverse engineer a specific library from the [dyld shared cache](http://iphonedevwiki.net/index.php/Dyld_shared_cache) with ease in IDA.


## Motivation
When you extract a single library (using IDA/decache/jtool) and try to disassemble it in IDA, sooner or later you will run into red bold addresses along the assembly lines which means that those memory regions are not found in the database.

Instead of using the familiar method of importing and exporting functions, out of and into the libraries, this example of code just jumps right into the implementation in the destination library relatively in the shared_cache. It is much harder to follow the code, once extracted because of all the anonymous function calls and the missing string references.

To solve this problem, this script does the following:
1. Maps the dyld_shared_cache_branch_islands - memory regions that resides in the shared cache and are used as branch trampolines.
2. Patches those trampolines so that the code will return and make the code flow intuitive without mapping the destination branch code to the database (making it more compact).
3. Scans the database for the following patterns: B 0x..., BL 0x..., DCD 0x..., DCQ 0x... in order to find more addresses which are not found in memory.

## Notes
1. The script will pop up an open-file-dialog which requires to put in its original dyld_shared_cache_arm64 file.
2. This was tested on a dyld_shared_cache_arm64 from an iPhone6 v10.0.1  and iPhoneSE v9.3.3.

## Example

Before:

![Before](https://github.com/deepinstinct/dsc_fix/raw/master/before.png "Before")

After:

![After](https://github.com/deepinstinct/dsc_fix/raw/master/after.png "After")
