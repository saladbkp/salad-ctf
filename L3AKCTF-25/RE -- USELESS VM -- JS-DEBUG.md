# 1.0 Challenge
1. HOW TO DEBUG JS
2. WHERE TO debug?
# 2.0 Analysis
OMG A BUNCH OF JS ...
![[Pasted image 20250723051214.png]]
MUST HAVE A WAY TO DEBUG 

# 3.0 Solution

3.1 how to debug js?
```
node --inspect-brk .\chal.js
chrome://inspect/#devices
click the Open dedicated DevTools for Node
```
![[Pasted image 20250723051421.png]]
then 
can see this 
![[Pasted image 20250723051444.png]]

3.2 Where to debug?
debug(Function.constructor)
this is debug function constructor, then just continue until see a plaintext shown ...
then console can see here
![[Pasted image 20250723051550.png]]
in flagResponses can see this 
```
const flagResponses = [ 
    /*"ZV8Ny"*/ "Oh, you want the flag? It's not like I have it under my virtual pillow or anything...", 
    /*"7abVH"*/ "Flag? What flag? I don't even know what a flag is. Do you mean like... a country flag?", 
    /*"PTtkq"*/ "If I had the flag, do you really think I'd just give it to you? Nice try!", 
    /*"g5ov3"*/ "I'm just a humble chatbot. The flag is above my paygrade.", 
    /*"ZVCus"*/ "Sorry, the flag is currently out to lunch. Try again later.", 
    /*"xv2To"*/ "Flag? Sorry, I left it in my other codebase.", 
    /*"BLMEq"*/ "I'm not saying I have the flag, but I'm definitely not giving it to you.", 
    /*"XcX8r"*/ "Access denied. You need at least 9000 IQ to get the flag from me.",
    /*"s49zD"*/ "I could tell you the flag, but then I'd have to format your hard drive. Kidding! (Or am I?)", 
    /*"Q139f"*/ "Nice try! But the flag isn't hidden in my responses. Or is it? No, it's not. Or is it?", 
    /*"XpXWw"*/ "If I told you the flag, the CTF gods would smite me.", 
    /*"SPmpF"*/ "I'm allergic to flags. Sorry, can't help.", 
    /*"RdRpL"*/ "Even if I had the flag, I'm not allowed to share it with strangers on the internet.", 
    /*"rY4P1"*/ "You're asking me for the flag? Bold of you to assume I even know what's going on.", 
    /*"b76Kg"*/ "The first rule of CTF: you don't talk about the flag.", 
    /*"N99GP"*/ "The flag? Oh, I put it somewhere safe... so safe even I can't find it.", 
    /*"JGpcd"*/ "Flag.exe has encountered an error and needs to close.", 
    /*"88viM"*/ "Have you tried turning the challenge off and on again?", 
    /*"qwzsT"*/ "Flag hunting is so last season. Try QR code hunting!", 
    /*"uTmpq"*/ "Flag? Hold on, let me Google that for you... oh wait, no results.", 
    /*"DSYWg"*/ "The flag is behind seven proxies. Good luck."];
```

then put in cyberchef -> magic !

# 4.0 FLAG 
L3AK{jsfuck_is_easily_recoverable_it_doesn't_matter_how_much_you_layer_on_it}

# 5.0 FINAL SCRIPT 
no script ?
# 6.0 REFERENCE

https://gist.github.com/TechnologicNick/278696fab8d26e94f0af0e736da1420d