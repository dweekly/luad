# LuCI subset (unmodified)

Upstream: <https://github.com/openwrt/luci>, commit
`3d39e8c38cfa276d5cdfad7105dbf47933eaed4f` (branch `openwrt-23.05`), tarball SHA-256
`932604aba96d61a5d09a524c30bf27c08ec5699559d5f35ac69fb6bc2bc7a86b`.

License: Apache-2.0, with the upstream text in [LICENSE](LICENSE) and the upstream
attribution notice, unmodified, in [UPSTREAM-NOTICE](UPSTREAM-NOTICE) (SHA-256 `155aef176044b85fdc2ac495c71cd631ed46a8164c0eb9afd28da850335ffa04`). The files are copied
byte for byte at their upstream paths. luad's tests only compile them with the official
Lua 5.1.5 `luac` and never execute them. The test suite checks the hashes below.

| Path | SHA-256 |
|---|---|
| `libs/luci-lib-base/luasrc/util.lua` | `879c6e045714babf9894230dba47175427ddf32453e17d30e013a05a5c4b9b20` |
| `modules/luci-lua-runtime/luasrc/sys.lua` | `a4726234bccd5c05e47bd8a4749722ffc08be8f1c7309106a8fa165dca82cf75` |
| `modules/luci-compat/luasrc/cbi/datatypes.lua` | `ec4b3ac686e0f49b3859c783245ce5ebf3dd6272af9bed84cd0d8105e50b9177` |
| `modules/luci-lua-runtime/luasrc/model/uci.lua` | `f1d4bcc5eb79a7b30998285ffe16fc564d53744e2f9cc3f2609dd6e2f8b0d3d2` |
| `libs/luci-lib-base/luasrc/http.lua` | `46e7422eccd10e4a52b2c763e6169d1645ca67ed1a657f57087f00b242eebd77` |
| `modules/luci-lua-runtime/luasrc/dispatcher.lua` | `1ef54489688516cc8815953521c351c9ea0fce3e8122fc23c6a35b8a6120baab` |
| `modules/luci-mod-admin-mini/luasrc/controller/mini/system.lua` | `a8486185be3812063485cb5f797b2b282cd4e99325493513af14b1a7eb260575` |
| `modules/luci-mod-admin-mini/luasrc/controller/mini/index.lua` | `b33333b8b6dcfcaf823d9dbe7286c3fadc31fa38a1b0c6db1bfea59778d9b7de` |
| `modules/luci-mod-admin-mini/luasrc/controller/mini/network.lua` | `8a8be6aa70c7df74d257fe933b0e5a797ac8e63e18f96a0ebc78f4db3435fdc7` |
| `applications/luci-app-lxc/luasrc/controller/lxc.lua` | `0bdcb90cba89f2d474816e6b15d721427f3cfe4c9f857fe283522971c611ce87` |
| `applications/luci-app-ahcp/luasrc/controller/ahcp.lua` | `7ff43fe0174f99765a28b1fdc8203183e4f08bba960f43d3330e2a092aa5d517` |
| `applications/luci-app-openvpn/luasrc/controller/openvpn.lua` | `920a96c2dc7b2d2fe0d1d7f0da881968e74823659b2034fd25eb41297dd55ce3` |
| `applications/luci-app-nft-qos/luasrc/controller/nft-qos.lua` | `79a390c34b8998a66a00013b097d7f8fdb83eae62c673c59e054eed1fb219218` |
