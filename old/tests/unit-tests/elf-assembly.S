.section .bss

.globl asm_sym1
.globl asm_sym2
.globl asm_sym3

asm_sym1:
	.skip	128

asm_sym2:
asm_sym3: /* Same as asm_sym2 */
	.long	0
