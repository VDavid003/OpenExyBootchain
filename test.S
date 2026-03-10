//Header

.section .bl1_header,"ax"
//.word 0x00000010 //Number of blocks
.word 0x0 //Number of blocks (to be filled by sign tool)
.word 0x00000000 //Checksum (to be filled by sign tool)
.word 0x0 //unknown/reserved
.word 0x0 //unknown/reserved

.section .text.entry
entrypoint:
  b c_entry
