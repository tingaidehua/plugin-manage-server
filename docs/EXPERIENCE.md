# plugin-manage-server 踩坑

- 只做只读基线，不做端口爆破/漏洞利用脚本（公开仓与合规）
- `~/.env` 权限应为 600；DSH_* 不该出现在该文件（见 skill 文档 8b）
- 证书预警依赖 `/etc/letsencrypt/live/$DSH_DOMAIN`；DSH_DOMAIN 来自进程环境而非 .env
