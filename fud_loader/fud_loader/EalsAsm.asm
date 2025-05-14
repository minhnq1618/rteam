.data
	wSystemCall DWORD 000h

.code 
	EalsAte PROC
		mov wSystemCall, 000h
		mov wSystemCall, ecx
		ret
	EalsAte ENDP

	HellDescent PROC
		mov r10, rcx
		mov eax, wSystemCall

		syscall
		ret
	HellDescent ENDP
end
