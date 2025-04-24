TEST SETUP

Build shadowTLS with standard Cargo commands: `cargo build --package shadow-tls --bin shadow-tls`
The same shadow-tls binary can then be run in server or client mode based on the arguments passed to the executable.

I'm currently running the services on the server within screen terminal sessions so they can be resumed any time.

</br>ssmanager: screen name **"enoch"**
</br>shadow-tls server: screen name **"enoch2"**

screens can be resumed with `screen -r enoch` or `screen -dr enoch` if it's sill attached

server: 45.86.229.176
ssmanager running on server: 
```json
{
    "manager_address": "/tmp/ssm_other.sock",
    "manager_tcp_port": 8081,
    "servers": [
    {
        "server": "45.86.229.176",
        "server_port": 667,
        "password": "yJxlMnbXB0fpbQ+YfBwmV4GVr1ndRbsEJXdrJFQNeRE=",
        "method": "2022-blake3-aes-256-gcm",
        "mode": "tcp_and_udp",
        "users": [
            {"name": "userOne","password": "aj0Wg39ZA/h6dUuZr60T3kMHRpQQDIivPeSOYi397C4="}
        ]
    }]
}
```

Shadow-tls is running with the following config:
</br>
`./shadow-tls server --listen 45.86.229.176:4433 --server 45.86.229.176:667 --tls captive.apple.com --password pwd1`

I Then run shadow-tls client on my local machine with this:
<br/>
`sudo ./shadow-tls client --sni captive.apple.com --server 45.86.229.176:4433 --listen 127.0.0.1:666 --password pwd1`

Then start sslocal with the following config:
```json
{
  "servers": [{
    "server": "127.0.0.1",
    "server_port": 666,
    "ipv6_first": false,
    "ipv6_only": false,
    "mode": "tcp_only",
    "password": "yJxlMnbXB0fpbQ+YfBwmV4GVr1ndRbsEJXdrJFQNeRE=:aj0Wg39ZA/h6dUuZr60T3kMHRpQQDIivPeSOYi397C4=",
    "method": "2022-blake3-aes-256-gcm",
    "timeout": 300
  },
    {
      "server": "45.86.229.176",
      "server_port": 667,
      "mode": "udp_only",
      "password": "yJxlMnbXB0fpbQ+YfBwmV4GVr1ndRbsEJXdrJFQNeRE=:aj0Wg39ZA/h6dUuZr60T3kMHRpQQDIivPeSOYi397C4=",
      "method": "2022-blake3-aes-256-gcm",
      "udp_timeout": 300,
      "udp_max_associations": 512
    }],
  "locals": [
    {
      "protocol": "tun",
      "tun_interface_name": "utun9",
      "local_address": "127.0.0.1",
      "local_port": 1081,
      "mode": "tcp_and_udp",
      "outbound_bind_interface": "en0"
    }
  ],
  "log": {
    "level": 1
  }
}
```
I can then test with the following 'curl' command:
<br/>
`curl --proxy 127.0.0.1:1081 https://api.ipify.org`
Which replies with the ip address of the shadowsocks server: 45.86.229.176

Configure Routing for the new Tun interface:
```shell
#!/bin/bash
TUN_IF="utun9"
TUN_IP=$(ifconfig "$TUN_IF" | grep 'inet ' | awk '{print $2}')
SHADOW_TLS_IP="45.86.229.176"
echo "[*] Setting default route through $TUN_IF ($TUN_IP)..."
sudo route -n add -net 0.0.0.0/1 -interface "$TUN_IF"
sudo route -n add -net 128.0.0.0/1 -interface "$TUN_IF"
echo "[*] Excluding localhost and Shadow-TLS server IP..."
sudo route -n add "$SHADOW_TLS_IP" $(route get default | awk '/gateway/ { print $2 }')
echo "[✓] Routing updated. All traffic now flows through Shadowsocks TUN, except Shadow-TLS."
```

Clean up routing after kill sslocal
```shell
#!/bin/bash
TUN_IF="utun9"
SHADOW_TLS_IP="45.86.229.176"
echo "[*] Removing default split routes through $TUN_IF..."
sudo route -n delete -net 0.0.0.0/1 -interface "$TUN_IF"
sudo route -n delete -net 128.0.0.0/1 -interface "$TUN_IF"
echo "[*] Removing manual route to Shadow-TLS server..."
sudo route -n delete "$SHADOW_TLS_IP"
echo "[✓] Routing reverted. System back to default."
```

# TODO UDP packets seem to be failing.