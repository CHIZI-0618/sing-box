# sing-box

The universal proxy platform.

[![Packaging status](https://repology.org/badge/vertical-allrepos/sing-box.svg)](https://repology.org/project/sing-box/versions)

## Documentation

https://sing-box.sagernet.org

## Support

https://community.sagernet.org/c/sing-box/

## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
```

## Proxy Providers 支持

- 编译时需要使用 `with_proxyprovider` tag

- 配置详解
```json5
{
    "proxyproviders": [
        {
            "tag": "proxy-provider-x", // 标签，必填，用于区别不同的 proxy-provider，不可重复，设置后outbounds会暴露一个同名的selector出站
            "url": "", // 订阅链接，必填，支持Clash订阅链接，后续可能支持普通订阅链接
            "cache_file": "/tmp/proxy-provider-x.cache", // 缓存文件，选填，强烈建议填写，可以加快启动速度
            "update_interval": "4h", // 更新间隔，选填，仅填写 cache_file 有效，若当前缓存文件已经超过该时间，将会进行后台自动更新
            "request_timeout": "10s", // 请求超时时间
            "dns": "tls://223.5.5.5", // 使用自定义 DNS 请求订阅域名
            "tag_format": "proxy-provider - %s", // 如果有多个订阅并且订阅间存在重名节点，可以尝试使用，其中 %s 为占位符，会被替换为原节点名。比如：原节点名："HongKong 01"，tag_format设置为 "PP - %s"，替换后新节点名会更变为 "PP - HongKong 01"，以解决节点名冲突的问题
            "global_filter": {
                "white_mode": true, // 白名单模式，匹配的节点会被保留，不匹配的节点会被删除
                "rules": [], // 规则，Golang 正则表达式
            },
            "dialer": {}, // 附加在节点 outbound 配置的 Dial 字段
            "request_dialer": {}, // 请求时使用的 Dial 字段配置，detour 字段无效
            "running_detour": "", // 运行时后台自动更新所使用的 outbound
            "groups": [ // 自定义分组
                {
                    "tag": "", // outbound tag，必填
                    "type": "selector", // outbound 类型，必填，仅支持selector, urltest
                    "filter": {}, // 节点过滤规则，选填，详见上global_filter字段
                    ... Selector 或 URLTest 其他字段配置
                }
            ]
        }
    ]
}
```

- DNS 支持格式
```
tcp://1.1.1.1
tcp://1.1.1.1:53
tcp://[2606:4700:4700::1111]
tcp://[2606:4700:4700::1111]:53
udp://1.1.1.1
udp://1.1.1.1:53
udp://[2606:4700:4700::1111]
udp://[2606:4700:4700::1111]:53
tls://1.1.1.1
tls://1.1.1.1:853
tls://[2606:4700:4700::1111]
tls://[2606:4700:4700::1111]:853
tls://1.1.1.1/?sni=cloudflare-dns.com
tls://1.1.1.1:853/?sni=cloudflare-dns.com
tls://[2606:4700:4700::1111]/?sni=cloudflare-dns.com
tls://[2606:4700:4700::1111]:853/?sni=cloudflare-dns.com
https://1.1.1.1
https://1.1.1.1:443/dns-query
https://[2606:4700:4700::1111]
https://[2606:4700:4700::1111]:443
https://1.1.1.1/dns-query?sni=cloudflare-dns.com
https://1.1.1.1:443/dns-query?sni=cloudflare-dns.com
https://[2606:4700:4700::1111]/dns-query?sni=cloudflare-dns.com
https://[2606:4700:4700::1111]:443/dns-query?sni=cloudflare-dns.com
1.1.1.1 => udp://1.1.1.1:53
1.1.1.1:53 => udp://1.1.1.1:53
[2606:4700:4700::1111] => udp://[2606:4700:4700::1111]:53
[2606:4700:4700::1111]:53 => udp://[2606:4700:4700::1111]:53
```

- 简易配置示例
```json5
{
    "proxyproviders": [
        {
            "tag": "proxy-provider",
            "url": "你的订阅链接",
            "cache_file": "缓存文件路径",
            "dns": "tcp://223.5.5.5",
            "update_interval": "4h", // 自动更新缓存
            "request_timeout": "10s" // 请求超时时间
        }
    ]
}
```

- 
```json5
geoip-lite.db: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip-lite.db"
geosite.db: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.db"
```
