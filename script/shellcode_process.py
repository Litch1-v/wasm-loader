import base64
with open("payload_x64.bin",'rb') as f:
    shellcode_bytes = f.read()
    with open("../src/resources/shellcode",'wb') as shellcode_write:
        shellcode_write.write(base64.b85encode(shellcode_bytes))