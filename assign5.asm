; Elly Zelitchenko
; 03/12/2018
; CS3140
; Assignment 5
; nasm -f elf64 -g assign5.asm
; ld -o assign5 -m elf_x86_64 assign5.o dns64.o 

bits 64

extern resolv       ; unsigned int resolv(const char *hostName);

;*******************************************************************************************
        global l_gets           ; int l_gets(int fd, char *buf, int len);
        section .text 
l_gets:
        push r15
        push r14
        push r13      
        push r12      
        mov r15, rdx            ; len
        mov r14, 0              ; result len
        mov r13, rdi            ; fd
        mov r12, rsi            ; buff
l_gets_loop:        
        cmp r14, r15           ; compare len and result len
        je l_gets_end
        mov rdi, r13            ; set filestream
        mov rsi, r12            ; set buff
        mov rdx, 1              ; size t len; we're moving one byte at a time
        mov eax, 0              ; set sys_read code
        syscall                 ; do the actual read
        
        cmp rax, 1              ; if true, more bytes available. else, false
        jne l_gets_end
        
        inc r14
        mov bl, [r12]
        cmp bl, 10              ; compare to newline
        je l_gets_end
        
        add r12, 1              ; since we're moving one byte at a time, increment buffer pointer position
        jmp l_gets_loop

l_gets_end:
        mov r9, 0               ; now we need to null-terminate
        mov [r12+1], r9          
        mov rax, r14
        pop r12
        pop r13
        pop r14
        pop r15
        ret

        
        global l_puts
        section .text 
l_puts:
        push r15
        push rbx
        mov r15, rdi            ; = rdi (aka buff)
        
l_puts_loop:
        xor rbx, rbx
        mov rbx, [r15]
        cmp bl, 0               ; cmp [r15] to null byte
        je l_puts_end           ; if equal, jump to l_puts_end
        mov edi, 1              ; output to stdout (fd 1 = stdout)
        mov rsi, r15            ; buffer pointer
        mov rdx, 1              ; size t len, moving one byte at a time
        mov eax, 1              ; sys_write
        syscall
        inc r15
        jmp l_puts_loop

l_puts_end:
        pop rbx
        pop r15
        ret
        
        
        
        global l_atoi           ; unsigned int l_atoi(char *value);
        section .text 
l_atoi:
        push r15
        push rbx
        mov r15, 0
        mov r8, 0
l_atoi_loop:
        xor rbx, rbx
        mov bl, [rdi+r8]        ; move single byte from "value" to bl
        inc r8                  ; r8++ for next loop
        mov cl, [zero]
        cmp bl, cl
        jl l_atoi_end          ; if < '0', invalid, jump to end
        mov cl, [nine]
        cmp bl, cl
        jg l_atoi_end          ; if > '9', invalid, jump to end
        ; otherwise.... '0' is 48, etc...
        sub bl, 48              ; so now you should have the number in decimal form.
        mov rax, 10             ; to mult by 10
        mul r15                 ; here's the interesting bit - have to shift current number by one base. (mult by 10)
        mov r15, rax            ; ^ ax = ax * rax
        add r15, rbx            ; now you can add bl to result
        jmp l_atoi_loop
l_atoi_end:
        mov rax, r15
        pop rbx
        pop r15
        ret                     ; result should be in rax, even if just 0. return. 
        
        section .data
zero db '0'
nine db '9'        
        
        
;*******************************************************************************************
        global _start   
        
        section .bss
userinput: resb 80
wait_status: resb 2
buff: resb 1
struc sockaddr_in
        .sin_family:    resw 1
        .sin_port:      resw 1
        .sin_addr:      resd 1
        .sin_pad:       resb 8
endstruc

        section .data
prompt: db '>'
space: db ' '
server: istruc sockaddr_in
        at sockaddr_in.sin_family, dw 2
        at sockaddr_in.sin_port, dw 0x0000
        at sockaddr_in.sin_addr, dd 0x00000000
        iend
resolv_fail_msg: db 'unable to resolve host', 10, 0
conn_fail_msg: db 'connection attempt failed', 10, 0

        section .text

_start:                         ; always loops again
; 1. print a prompt (“>“)
        mov edi, 1              ; output to stdout (fd 1 = stdout)
        mov rsi, prompt            ; buffer pointer
        mov rdx, 1              ; size t len
        mov eax, 1              ; sys_write
        syscall

; 2. read a line of user input from the keyboard (perhaps using l_gets). This line will never be more than 80 characters long including the terminating \n. This line will contain a host name (never an ip address) followed by a decimal port number. If EOF is encountered your program should exit; 
; int l_gets(int fd, char *buf, int len);
        mov rdi, 0      ; fd = 0 = stdin/keyboard
        mov rsi, userinput
        mov rdx, 80
        call l_gets

; 3. Resolve the hostname, then create a tcp socket and connect it to the indicated host on the indicated port. Read below for more information on connecting your socket. If the host name cannot be resolved, print exactly "unable to resolve host\n" and go to step 1
        mov r9, userinput
        mov al, [space]
locate_space: 
        mov bl, [r9]
        inc r9
        cmp bl, al
        jne locate_space
        xor bl, bl
        mov [r9-1], bl           ; replace space with null termination (0). r9 now has the pointer to port, userinput null terminates after addr
port_store:
        mov rdi, r9
        call l_atoi             ; unsigned int l_atoi(char *value); following this port in rax. rather, it should be in ax, due to limited port size.
        xchg ah, al             ; "You will need to convert the resulting port number to network byte order by swaping the high and low byte of the 16 bit result."
        mov [server + sockaddr_in.sin_port], ax
resolve_addr:
        mov rdi, userinput
        call resolv             ; unsigned int resolv(const char *hostName);
        mov [server + sockaddr_in.sin_addr], eax
        mov rbx, 0xffffffff
        cmp rax, rbx
        jne attempt_connection		;in resolve_addr:, jne attempt_connection should go to  create_socket
resolv_fail:        
        mov rdi, resolv_fail_msg
        call l_puts
        jmp _start

; 4. Initialized sockaddr_in will be passed to connect to create a connected socket. Two syscalls are required to create a connected socket (socket and connect). If the connection attempt fails, print exactly “connection attempt failed\n”, close the socket, and go to step 1
create_socket:
        xor rdx, rdx
        xor rax, rax
        mov rsi, 1              ; SOCK_STREAM
        mov rdi, 2              ; AF_INET
        mov rax, 41             ; sys_socket
        syscall                 ; fd returned in eax
        push rax                ; push fd
attempt_connection:
        mov rdi, rax            ; fd
        mov rsi, server
        mov rdx, 16             ; addr_len
        mov rax, 42             ; sys_connect
        syscall                 ; returns 0 on success
        mov rbx, 0
        cmp rax, rbx
        je create_child_A
connect_fail:
        mov rdi, conn_fail_msg
        call l_puts
        jmp _start
        
; 5. If you successfully connect, you are to create two child processes referred to here as child A and child B. Begin by forking. The first child will be child A. 
create_child_A:
        mov rax, 57	        ; syscall for fork
        syscall                 ; returns PID. "Upon successful completion, fork() returns a value of 0 to the child process and returns the process ID of the child process to the parent process."
        mov rbx, 0
        cmp rax, rbx
        jne i_am_parent_A
        
i_am_child_A:
        ; In child A, duplicate the connected socket to stdin of child A, then close the socket and jump to the child code described below.
        ; int dup2(int oldfd, int newfd); - Closes newfd (if it's open), then duplicates oldfd onto newfd
        pop rdi                 ; pop fd
        push rdi                ; immediately push a copy to return to stack
        mov rsi, 0              ; stdin
        mov rax, 33             ; dup2
        jmp child_process

i_am_parent_A:
        mov r15, rax            ; r15 now holds A's PID
        ; In the parent, fork a second time to create child B. 
        mov rax, 57	        ; syscall for fork
        syscall                 ; returns PID
        mov rbx, 0
        cmp rax, rbx
        jne i_am_parent_B

i_am_child_B:
        ; In child B duplicate the socket onto stdout, then close the socket and jump to the child code described below.
        ; int dup2(int oldfd, int newfd); - Closes newfd (if it's open), then duplicates oldfd onto newfd
        pop rdi                 ; pop fd
        push rdi                ; immediately push a copy to return to stack
        mov rsi, 1              ; stdout
        mov rax, 33             ; dup2
        jmp child_process

i_am_parent_B:
        mov r14, rax            ; r14 now holds B's PID
; 6. Close the socket.
        pop rdi                 ; pop fd
        mov rsi, 2              ; SHUT_RDWR
        syscall
        
; 7. Wait for child A to complete
        ; wait4(pid, status, options, rusage);
        mov rdi, r15            ; A's PID
        mov rsi, 0
        mov rdx, 0
        mov rcx, 0
        mov rax, 61             ; syscall wait4
        syscall

; 8. Send SIGTERM to child B
send_sigterm:
        mov rdi, r14            ; B's PID
        mov rsi, 15             ; linux signal SIGTERM
        mov rax, 62             ; sys_kill(pid, signal);
        syscall

; 9. Wait for child B to complete
        ; wait4(pid, status, options, rusage);
        mov rdi, r14            ; B's PID
        mov rsi, 0
        mov rdx, 0
        mov rcx, 0
        mov rax, 61             ; syscall wait4
        syscall
        
; Return to top
        jmp _start
        
        
        
        
        
done:
        mov edi, 0                      ;first syscall argument: exit code
        mov eax,60                      ;system call number (sys_exit)
        syscall                             
        
        
        
        
        
;*******************************************************************************************        
child_process:
; Because of the way the socket descriptor was duplicated for each child process in step 5 above, each of the child processes is really just cat (read from 0, write to 1) at this point, so you should be able to reuse your code from assignment 2 to implement the child behavior. When a child sees EOF or any error condition while reading from 0, or any error condition while writing to file descriptor 1, the child should terminate by using the exit syscall.
 
        ;read one byte
        mov edi, 0              ; int fd (fd 0 = stdin)
        mov rsi, buff           ; char *buffer
        mov rdx, 1              ; size t len; we're moving one byte at a time
        mov eax, 0              ; set sys_read code
        syscall                 ; do the actual read
        
        cmp rax, 1              ; if true, more bytes available. else, false
        jne done
        
        ;write one byte
        mov edi, 1              ; output to stdout (fd 1 = stdout)
        mov rsi, buff         ; buffer pointer
        mov rdx, 1              ; size t len, moving one byte at a time
        mov eax, 1              ; sys_write
        syscall
        
        jmp child_process
        
end_code:












        
