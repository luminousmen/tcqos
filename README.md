tcQoS
======

It's a university project for shaping traffic in Linux OS. It was tested on Linux Ubuntu 12.04 (version 3.13.0-32-generic).
This module is able to replace standart tool for managing traffic in linux (I mean [Traffic Control system](http://tldp.org/HOWTO/Traffic-Control-HOWTO/index.html)). 

The advantage of my module is that it is not using buffer on edge gateway. And it's better than standart tc tool. Proofs below.


### Algorithm:

The main idea - changing window value (cwnd) in ACK packets on edge-gateway. 


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

Speed for 2 clients and limit by 1Mb:

![2 clients](/plots/tc_module_2.png)
