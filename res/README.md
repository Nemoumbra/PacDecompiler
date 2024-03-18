Here you can find the brief explanation of all the resource files for the decompiler.

---
#### Instructions info files
These files are based on PacViewer's format, but much better.
The file reader skips the lines that have less than 3 semicolons which allows the user to add comments.

I have placed the start marker of PAC instructions in the first line. Every section of instruction is preceded by a line 'sec_0x{its_index}'.

The format for the instructions:
```
signature;function_name;overlay_index;hex_function_address;param_1_type;param_1_name;param_2_type;param_2_name...
```
For the overlay index:
* 0 is the base executable
* 1 is `OL_Title.bin`
* 2 is `OL_Azito.bin`
* 3 is `OL_Mission.bin`

TODO: add the exhaustive list of param types and how they are parsed.

Note: that's the only file where the lines that start from hashtags are not ignored (will be fixed).

---
#### Saving RA instructions
This is a list of signatures of the instructions that perform jumps and save the return address at the same time (i.e. calls).

#### Unconditional jumping instructions
This is a list of pairs '{signature}, {index}'. The mentioned instructions perform some kind of jump no matter what (not fallthrough).
The argument that stores the destination has the specified index.

#### Conditional jumping instructions
The format is 'signature, index'. The mentioned instructions perform some kind of jump depending on a condition (if it's false, they code flow goes to the next instruction in the file).
The destination is in the argument with index = {index}.

#### Label instructions
That's a list instructions that perform runtime jumps based in the current value of the special variable argument (hard to resolve the jumps).

#### Jumping instructions
That's a union of the conditional and unconditional instructions plus label instructions and also cmd_inxJmp (27 == 22 + 2 + 2 + 1).

#### Callback instructions
The format is 'signature, index'. These instructions reference some other instructions in the same file (the argument with the specified index mentions a callback).

---
Lastly, the important instructions. That's a list with the signatures of
* cmd_end
* cmd_jmp
* cmd_call
* cmd_inxJmp
* cmd_stkDec
* cmd_stkClr
* cmd_setLabelId
* cmd_callLabelId
* cmd_jmpLabelId
* cmd_callLabel
* cmd_jmpLabel
* doSelect
* doSelectCursor

in order.