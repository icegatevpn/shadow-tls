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
  "server": "127.0.0.1",
  "server_port": 666,
  "rem_server": "45.86.229.176",
  "rem_server_port": 667,
  "local_address": "127.0.0.1",
  "local_port": 1081,
  "password": "yJxlMnbXB0fpbQ+YfBwmV4GVr1ndRbsEJXdrJFQNeRE=:aj0Wg39ZA/h6dUuZr60T3kMHRpQQDIivPeSOYi397C4=",
  "method": "2022-blake3-aes-256-gcm",
  "timeout": 300,
  "mode": "tcp_and_udp"
}
```
I can then test with the following 'curl' command:
<br/>
`curl --proxy 127.0.0.1:1081 https://api.ipify.org`
Which replies with the ip address of the shadowsocks server: 45.86.229.176

TODO. I can't seem to get a client/server flow to work if I configure sslocal with a tun interface. 
we need to figure out how to make that work and then enable device routing through the interface.