BITS 32 ;using x86 architecture

;---------------------------
;definition
%define u16(x) __utf16__(x)
%define IMG_DOS_OFFSET 0x3C			;offset to pe offset
%define IMG_PE_EXP_OFFSET 0x78		;offset to export directory address

;--------------------------- proc 1
;code block
entry_point:
pushad
sub esp, 4							;define local var
	;calc delta
	call get_eip			
	get_eip:
	pop ebx 						;pop up virtual address to eax
	sub ebx, get_eip - entry_point	;offset normalize

	;search ntdll address
	mov eax, wphr_ntdll
	add eax, ebx
	push eax
	call find_module_address
	test eax, eax
	je end_shell
	mov [esp], eax
	
	;search ldrloaddll
	mov eax, phr_ldrloaddll
	add eax, ebx
	push eax
	mov eax, [esp + 4]
	push eax
	call search_export_proc
	
	;load user32.dll
	sub esp, 12						;alloc sizeof(UNICODE_STRING) + sizeof(PHANDLE)
	
	xor edx, edx
	mov [esp + 8], edx				;set handle = NULL
	mov edx, wphr_user32			;put UNICODE_STRING.Buffer
	add edx, ebx
	mov [esp + 4], edx
	mov dx, 22						;wcslen(phr_user32) * 2 + 2, UNICODE_STRING.MaximumLength
	shl edx, 16
	mov dx, 20						;wcslen(phr_user32) * 2, UNICODE_STRING.Length
	mov [esp], edx
	
	mov edx, esp
	add edx, 8
	push edx
	mov edx, esp
	add edx, 4
	push edx
	push 0
	push 0
	call eax						;call LdrLoadDll
	mov eax, [esp + 8]
	add esp, 12
	test eax, eax
	je end_shell
	
	;search messagebox
	mov edx, phr_msgbox
	add edx, ebx
	push edx
	push eax
	call search_export_proc
	test eax, eax
	je end_shell
	
	;call messagebox
	push 0
	mov edx, msg_title
	add edx, ebx
	push edx
	mov edx, msg_string
	add edx, ebx
	push edx
	push 0
	call eax

end_shell:
add esp, 4
popad
retn

;------------------ proc 2
find_module_address:				;find_module_address(stack wlib_name)
push ebx							;save context value
	;getting PEB
	mov ebx, dword [fs:0x30]
	test ebx, ebx
	js retn_label_2

	;getting first LDR_MODULE
	mov ebx, dword [ebx + 0x0C]
	mov ebx, dword [ebx + 0x1C]
	mov ebx, dword [ebx]
	push ebx						;save in stack

	whiling:
		mov eax, dword [ebx + 0x20]	;getting module unicode name
		test eax, eax				;if name == NULL continue
		je calc_next
		
		;compare stings
		push eax
		mov eax, dword [esp + 16]
		push eax
		call wstrcmp
		test eax, eax
		jne retn_ok_2
		
		;set next module
		calc_next:
		mov eax, dword [ebx]
		mov ecx, dword [esp]
		cmp eax, ecx 				;if end of list => break
		je retn_error_2
		mov ebx, eax
	jmp whiling
	
retn_error_2:
xor eax, eax
jmp retn_label_2
retn_ok_2:
mov eax, dword[ebx + 8]				;put return value
retn_label_2:
add esp, 4							;clear args
pop ebx								;restore context value
retn 4

;------------------ proc 3
wstrcmp:							;wstrcmp(stack wstr1, stack wstr2)
	whiling_3:
		;put wchar to dx
		mov esi, dword [esp + 4]
		lodsw
		mov dword [esp + 4], esi
		mov dx, ax
		
		;put wchar to ax
		mov esi, dword [esp + 8]	
		lodsw
		mov dword [esp + 8], esi
		
		;compare
		cmp ax, dx
		jne retn_error
		
		;break if EOS
		cmp ax, 0
		je retn_ok
		
	jmp whiling_3
retn_ok:
mov eax, 1
retn 8
retn_error:
xor eax, eax
retn 8

;------------------ proc 4
strcmp:							;strcmp(stack wstr1, stack wstr2)
xor eax, eax
xor edx, edx
	strcmp_whiling:
		;put wchar to dx
		mov esi, dword [esp + 4]
		lodsb
		mov dword [esp + 4], esi
		mov dx, ax
		
		;put wchar to ax
		mov esi, dword [esp + 8]	
		lodsb
		mov dword [esp + 8], esi
		
		;compare
		cmp ax, dx
		jne strcmp_retn_error
		
		;break if EOS
		cmp ax, 0
		je strcmp_retn_ok
		
	jmp strcmp_whiling
strcmp_retn_ok:
mov eax, 1
retn 8
strcmp_retn_error:
xor eax, eax
retn 8

;------------------ proc 5
search_export_proc:					;search_import_proc(stack lib_addr, stack lib_name)
push ebx							;save context value
sub esp, 12							;0 - AddressOfNames, 4 - AddressOfNameOrdinals, 8 - AddressOfFunctions, 12 - ebx, 16 - retn addr, 20 - lib_addr, 24 - lib_name

	;put to eax PE header VA
	mov eax, [esp + 20]
	add eax, IMG_DOS_OFFSET
	mov eax, [eax]
	add eax, [esp + 20]				;RVA -> VA
		
	;put to eax PE export descriptor VA
	add eax, IMG_PE_EXP_OFFSET
	test eax, eax
	je retn_label_5
	mov eax, [eax]
	add	eax, [esp + 20]				;RVA -> VA
	
	;put to ecx NumberOfNames
	add eax, 24
	mov ecx, [eax]
	add eax, 4
	;put to stack VA AddressOfFunctions
	mov edx, [eax]
	add	edx, [esp + 20]				;RVA -> VA
	mov [esp + 8], edx				;save RVA AddressOfFunctions
	add eax, 4
	;put to stack VA AddressOfNames
	mov edx, [eax]					;put to eax RVA AddressOfNames
	add	edx, [esp + 20]				;RVA -> VA
	mov [esp], edx					;save RVA AddressOfNames
	add eax, 4
	;put to stack VA AddressOfNameOrdinals
	mov eax, [eax]
	add	eax, [esp + 20]				;RVA -> VA
	mov [esp + 4], eax				;save RVA AddressOfNameOrdinals
	add eax, 4
	;searching procedure name
	xor eax, eax
	xor edi, edi
	whiling_5:
		;if count == 0 break
		test ecx, ecx
		je retn_label_5
		dec ecx
		
		;compare
		mov eax, [esp]
		mov edx, eax				;ptr ++
		add edx, 4
		mov [esp], edx
		mov eax, [eax]
		add eax, [esp + 20]
		push eax
		mov eax, [esp + 28]
		push eax
		call strcmp
		test eax, eax
		jne break_5
		
		inc edi						;index ++
	jmp whiling_5
	break_5:
	
	;searching procedure address
	mov eax, 2
	mul edi
	add eax, [esp + 4]
	xor edx, edx
	mov dx, [eax]
	;add eax, [esp + 20]
	mov eax, 4
	mul edx
	add eax, [esp + 8]
	mov eax, [eax]
	add eax, [esp + 20]
	
	
retn_label_5:
add esp, 12
pop ebx								;restore context value
retn 8

;---------------------------
;internal data block
msg_title: 		db 'Message', 0
msg_string:		db 'Hello Peoplz', 0
wphr_ntdll		dw u16('ntdll.dll'), 0, 0
phr_ldrloaddll	db 'LdrLoadDll', 0, 0, 0, 0
wphr_user32		db u16('user32.dll'), 0, 0
phr_msgbox		db 'MessageBoxA', 0

;---------------------------
;input data block
; not used
