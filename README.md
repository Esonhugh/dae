# dae

<img src="https://github.com/v2rayA/dae/blob/main/logo.png" border="0" width="25%">

***dae***, means goose, is a lightweight and high-performance transparent proxy solution.

In order to improve the traffic split performance as much as possible, dae runs the transparent proxy and traffic split suite in the linux kernel by eBPF. Therefore, we have the opportunity to make the direct traffic bypass the forwarding by proxy application and achieve true direct traffic through. Under such a magic trick, there is almost no performance loss and additional resource consumption for direct traffic.

As a successor of [v2rayA](https://github.com/v2rayA/v2rayA), dae abandoned v2ray-core to meet the needs of users more freely.

## Usage

### Build

**Make Dependencies**
```
clang >= 10
llvm >= 10
golang >= 1.18
make
```

**Build**
```shell
git clone https://github.com/v2rayA/dae.git
cd dae
git submodule update --init
# Minimal dependency build:
make GOFLAGS="-buildvcs=false" CC=clang
# Or normal build:
# make
```

### Run

**Runtime Dependencies**

Download [geoip.dat](https://github.com/v2ray/geoip/releases/latest) and [geosite.dat](https://github.com/v2fly/domain-list-community/releases/latest) to `/usr/local/share/dae/`.

```
mkdir -p /usr/local/share/dae/
pushd /usr/local/share/dae/
curl -L -o geoip.dat https://github.com/v2ray/geoip/releases/latest/download/geoip.dat
curl -L -o geosite.dat https://github.com/v2ray/domain-list-community/releases/latest/download/dlc.dat
popd
```

**Run**

```shell
./dae run -c example.dae
```

See [example.dae](https://github.com/v2rayA/dae/blob/main/example.dae).

## Linux Kernel Requirement

### Kernel Version

Use `uname -r` to check the kernel version on your machine.

**Bind to LAN: >= 5.8**

You need bind dae to LAN interface, if you want to provide network service for LAN as an intermediate device.

This feature requires the kernel version of machine on which dae install >= 5.8.

Note that if you bind dae to LAN only, dae only provide network service for traffic from LAN, and not impact local programs.

**Bind to WAN: >= 5.8**

You need bind dae to WAN interface, if you want dae to provide network service for local programs.

This feature requires kernel version of the machine >= 5.8.

Note that if you bind dae to WAN only, dae only provide network service for local programs and not impact traffic coming in from other interfaces.

## TODO

1. Check dns upstream and source loop (whether upstream is also a client of us) and remind the user to add sip rule.

1. Domain routing performance optimization.

1. Handle the case that nodes do not support UDP.

1. Handle the case that nodes do not support IPv6.

1. L4Checksum problem.

   If the NIC checksumming offload is enabled, the Linux network stack will make a simple checksum a packet when it is sent out from local. When NIC discovers that the source IP of the packet is the local IP of the NIC, it will checksum it complete this checksum.

   But the problem is, after the Linux network stack, before entering the network card, we modify the source IP of this packet, causing the Linux network stack to only make a simple checksum, and the NIC also assumes that this packet is not sent from local, so no further checksum completing.

1. MACv2 extension extraction.

1. Log to userspace.

1. DNS upstream support tcp://

1. ...
