.section .text

.globl _start

_start:
	jmp		end

	jmp		1f
1:
	jmp		2f
2:
	jmp		3f
3:
	jmp		4f
4:
	jmp		3b
	jmp		2b
	jmp		1b
	jmp		_start

	.fill 255, 1, 0x90
	jmp		_start
end:

