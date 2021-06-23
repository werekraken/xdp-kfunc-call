# a_kmod

Setup for el7:
```
sudo yum install devtoolset-10
scl enable devtoolset-10 bash
```

Setup for out-of-tree modules to get btf.
```
./linux-5.12.7/scripts/extract-vmlinux /boot/vmlinuz-"`uname -r`" | sudo tee /usr/src/kernels/"`uname -r`"/vmlinux > /dev/null
```

Build:
```
make
```
