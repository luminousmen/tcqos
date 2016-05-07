tcQoS
======

It's a university project for shaping traffic in Linux OS. It was tested on Linux Ubuntu 12.04 (version 3.13.0-32-generic).
This module is able to replace standart tool for managing traffic in linux (I mean Traffic Control system). The advantage of this module is that it is not using buffer on edge gateway. 

### Algorithm:

The main idea is changing window value in ACK packets on edge-gateway. 


### Usage:

```bash
$ sudo make
$ sudo insmod tcqos.ko
```

### Plots and results

Expected value:

![expected value](/plots/mo.png)

Dispersion:

![dispersion](/plots/dis.png)

