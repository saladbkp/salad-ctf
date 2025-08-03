temp disable ASLR
```
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

extract libc so from dockerfile
```
sudo docker build -t chall .
sudo docker run -it --rm --name extract-libc chall /bin/sh

cd /srv
find . -name '*.so*'

sudo docker cp extract-libc:/srv/lib/x86_64-linux-gnu/libc.so.6 ./libc.so.6

```

