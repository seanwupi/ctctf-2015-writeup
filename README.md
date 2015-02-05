# ctctf-2015-writeup

### Starbound

1. 選單中輸入的數字範圍可以是負數，在 name 中的內容可以被當做 function pointer 呼叫
2. cmd_set_name() 可以輸入超過 buffer size (128)，覆蓋顯示 menu 的 function pointer
3. get_server_key 和 disable portal 中 file descriptor 沒有正確關閉，在 teleport 功能中可以被重新使用
4. do_send_record() 中送出過多 data，有可能 leak 出 memfrob() 後的 flag 
5. cmd_multiplayer_sendmap() 中 getline() 如果直接切掉連線，就不會讀到 '\n'。
cmd_multiplayer_recvmap() 中沒收到 '\n' 則可以偽造 map size 造成 buffer overflow。

其它: do_die() 中的 format string 漏洞，可以用來洩漏 library 或 stack address

### Casio

1. 功能 (3) 中遇到 '$?' 要輸入數字時，過長的 input 會 overflow 改到 return address，可以直接 ROP
2. 功能 (2) 中沒有檢查 expression 是否有餘的 operands，如果 (3) 中執行 "$? 1" 會 return 到輸入的數字
3. strtok() 在 multithread 時會造成 buffer overflow (>500) 改到 return address (改到 buffer 上)
4. 功能 (2) 中輸入空字串時，不會執行 strdup() 但還是會 free()，可造成 double free。
或利用 (3) 功能預先填充 stack 上的內容，可以進行 House of Spirit 使得 strdup() 拿到 flag 所在的 buffer，洩漏 flag 的內容。


