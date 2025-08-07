# 1.0 Challenge
1. go dot encrypted with a key, how to find it?
2. what we need to focus in godot decompiling?

# 2.0 Analysis
就是一个game 通常是用
https://github.com/GDRETools/gdsdecomp decompile
可是 需要一个encryption key
![[Pasted image 20250808042204.png]]
# 3.0 Solution
## 3.1 go dot encrypted with a key, how to find it?
https://www.youtube.com/watch?v=fWjuFmYGoSY 可以参考这个
需要在 ghidra / ida strings 找 `Condition \"fae.is_null()\" is true. Returning: false`

HHEHEEH 找到了
```
.text:00000001426834FC                 lea     rax, aCanTOpenEncryp_0 ; "Can't open encrypted pack directory."
.text:0000000142683503                 mov     dword ptr [rsp+30h], 0
.text:000000014268350B                 lea     r9, aConditionFaeIs_0 ; "Condition \"fae.is_null()\" is true. Re"...
.text:0000000142683512                 mov     r8d, 11Fh
.text:0000000142683518                 mov     dword ptr [rsp+28h], 0
.text:0000000142683520                 lea     rdx, aCoreIoFileAcce_3 ; "core\\io\\file_access_pack.cpp"
.text:0000000142683527                 lea     rcx, aTryOpenPack ; "try_open_pack"
.text:000000014268352E                 mov     [rsp+20h], rax
.text:0000000142683533                 call    sub_142ABD600
.text:0000000142683538                 jmp     loc_142682E30
```
![[Pasted image 20250808042646.png]]
找附近的byte list 这个就是了 52D066DE1115FC479E53FCF821715AD7DB73E12DF7E557833712136B4FF7529E
```
.data:0000000143F78540 byte_143F78540  db 52h, 0D0h, 66h, 0DEh, 11h, 15h, 0FCh, 47h, 9Eh, 53h
.data:0000000143F7854A                 db 0FCh, 0F8h, 21h, 71h, 5Ah, 0D7h, 0DBh, 73h, 0E1h, 2Dh
.data:0000000143F78554                 db 0F7h, 0E5h, 57h, 83h, 37h, 12h, 13h, 6Bh, 4Fh, 0F7h
.data:0000000143F7855E                 db 52h, 9Eh
```
try set 一下
![[Pasted image 20250808042908.png]]
成功了
![[Pasted image 20250808042926.png]]


## 3.2 what we need to focus in godot decompiling?
load them in https://editor.godotengine.org/releases/latest/
must extract the files and zip and upload
![[Pasted image 20250808043354.png]]
其实我玩的时候 发现 他跳不到上面 可是 他好像还有上面一层
so 第一想法 可以是 run faster, jump higher, + health, + power, 不死 ...
如果要看 整体图 先check src gd -> choose 2D 
![[Pasted image 20250808044250.png]]
看到很神奇的 script  (看writeup 学的)
![[Pasted image 20250808044616.png]]
ASK GPT 你可以知道这个是一个 tile 所以logic 是可以把这个画出来的
then generate script
![[Pasted image 20250808045125.png]]
DAMNNN

# 4.0 FLAG 
DUCTF{THE_BOY_WILL_NEVER_REMEMBER}

# 5.0 FINAL SCRIPT 
```python
from PIL import Image, ImageDraw

# 设置格子大小
TILE_SIZE = 32

# 输入数据
atlas_coords = (1, 1)
atlas_coords_ground = (1, 0)
coords = [
(-5, -247),
(-4, -247),
(-1, -247),
(0, -247),
(1, -247),
(3, -247),
......
]

# 地面行 y = -241 (x 从 -64 到 63)
ground_tiles = [(x, -241) for x in range(-64, 64)]

# 全部点集
all_coords = [(x, y, "normal") for (x, y) in coords] + [(x, y, "ground") for (x, y) in ground_tiles]

# 找到最小和最大坐标以决定画布大小
xs = [x for x, y, _ in all_coords]
ys = [y for x, y, _ in all_coords]
min_x, max_x = min(xs), max(xs)
min_y, max_y = min(ys), max(ys)

width = (max_x - min_x + 1) * TILE_SIZE
height = (max_y - min_y + 1) * TILE_SIZE

# 创建白底图像
img = Image.new('RGB', (width, height), color='white')
draw = ImageDraw.Draw(img)

# 坐标转换函数（将负数坐标转为图像中的位置）
def to_screen(x, y):
    screen_x = (x - min_x) * TILE_SIZE
    screen_y = (y - min_y) * TILE_SIZE
    return screen_x, screen_y

# 画 tile
for x, y, tile_type in all_coords:
    top_left = to_screen(x, y)
    bottom_right = (top_left[0] + TILE_SIZE, top_left[1] + TILE_SIZE)
    color = (255, 100, 100) if tile_type == "normal" else (100, 200, 255)
    draw.rectangle([top_left, bottom_right], fill=color, outline='black')

# 保存图像
img.save('tilemap.png')
print("✅ Saved tilemap to tilemap.png")

```


# 6.0 REFERENCE
https://github.com/autun12/CTF-Writeups/blob/master/DownunderCTF2025/rev/godot_COMPLETED/README.md