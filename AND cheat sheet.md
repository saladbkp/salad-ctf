frida -U -f ctf.l3akctf.filestorage -l bypass.js

if encounter this problem: # Failed to spawn: unexpectedly timed out while waiting for signal from process
https://github.com/frida/frida/issues/2516
1. getprop|grep usap
2. If getprop xxx.usap returns true
3. setprop xxxx.usap false
4. And then getprop xxxx.usap will return false
5. Use spawn by your own way