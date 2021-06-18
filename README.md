# xdp-kfunc-call

Install requires:
```
sudo yum install -y \
  git \
  mock \
  rpm-build \
  rpmdevtools \
  yum-utils

sudo usermod -a -G mock <user>

git clone https://github.com/werekraken/dwarves-ml
cd dwarves-ml/

./build.sh

ls packages/
# grab epoch of build

cd ../xdp-kfunc-call/
vi build.sh
# insert epoch in dwarves path
```

Build:
```
./build.sh
```
