# Resetti  (🚧 WIP... 🚧)
A packet filtering and monitoring tool written in Rust. It allows you to monitor and/or disrupt selected connections on the network you're connected to. (⚠️Work in progress)
### Features:
  - Expressive filtering rules in the config
  - Monitor connections
  - reset or slow down chosen connections
  - Nice logging
  - And ofcourse written in Rust 🦀
## Todos
  - [ ] Add *ARP* and *NDP* spoofing layer
  - [ ] Add a LRU cache and monitor perf gains
  - [ ] config file lookup and handle cli flags and args
## Config
Pakcets can be matched based on their source and destination, IPs, MACs, wildcards and Regex to match on Domain names and IPs.</br>
Here's a sample config
```toml
[device]
interface = "wlp0s20f3" # defaults to the active interface if not given 

[log]
log-file = "./tcp-chief" # save logs into a file
log-level = "debug"

[[filter]]
src = ["192.168.0.1","192.168.0.103"] # match connection sources with these ips
dst_regex = "lobste|tiktok|youtube" # match connection destination domain or ip to this regex
mode = "reset" # reset those connections that match. reset|monitor|ignore|syn_reset

[[filter]]
src_mac_exclude = ["11:22:33:44:55:66"] # match all connection sources except the ones with this MAC address
dst_exclude = ["192.215.150.2", "192.215.150.3"] # match all connection dst except the ones with these ips
mode = "monitor"

[[filter]]
src_all = true
dst_mac = ["AA:BB:CC:DD:EE:FF"]
```
## Important ⚠️
Intended for ethical use. It's uncool to tamper with and eavesdrop on people connections!
