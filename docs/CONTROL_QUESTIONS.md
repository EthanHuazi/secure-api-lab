# Work 1 Control Questions

1. **Why bcrypt instead of SHA-256 for passwords?**
   bcrypt is deliberately expensive and has a configurable work factor and per-password salt. This makes large-scale offline guessing more costly and prevents identical passwords from producing identical stored values. SHA-256 is designed for fast hashing; even salted SHA-256 is too fast for password storage. Hashing is one-way, not encryption. This implementation uses bcrypt cost 12 and rejects passwords exceeding its 72-byte input limit.
   中文：bcrypt 的盐与可调计算成本增加离线猜测成本，普通 SHA-256 太快，不适合直接保存密码。

2. **SAST versus DAST?**
   SAST inspects source code or compiled artifacts without exercising a running application. DAST sends requests to a running application and observes its behavior. Bandit is SAST. The curl security checks exercise running behavior; they are focused tests, not a complete DAST scan. SCA separately checks third-party components against known vulnerability records.
   中文：SAST 看代码，DAST 测运行中的系统，SCA 检查依赖漏洞，三者互补。

3. **How does a JWT work?**
   A signed JWT has a Base64URL-encoded header, payload and signature. The header identifies the token type and algorithm; the payload carries claims such as subject and expiry. After successful password verification, this server signs a short-lived token with HS256. On each protected request it verifies the signature using its secret and an explicit algorithm allowlist, then checks required subject, issuer, audience and time claims and the user's continued existence. Encoding is not encryption; no passwords or secrets belong in the payload. A stolen bearer token can be reused until expiry unless additional revocation mechanisms exist.
   中文：服务端验证签名及声明，不只是解码；JWT 内容通常可读，不能放秘密。

4. **Risks of unaudited dependencies?**
   Known flaws in direct or transitive dependencies can expose an otherwise carefully written application to data theft, authentication bypass, denial of service or code execution. Regular SCA, controlled updates and regression tests reduce this risk. A clean scan only means no matching known issue was reported for the scanned components and current database; it is not a proof of safety or protection from every malicious package.
   中文：自己的代码安全不代表依赖安全；扫描还需结合及时升级与回归测试。

5. **Why Docker and Vulhub?**
   Docker packages dependencies in repeatable environments and keeps vulnerable services out of the host's normal application installation. Vulhub provides documented configurations and reproducible scenarios. Containers are not an absolute security boundary: this lab avoids host mounts, binds loopback ports, isolates networks and stops containers after use. On Apple Silicon the image architecture must also be checked.
   中文：便于隔离、复现和清理，但容器并非绝对安全，也不能默认兼容 ARM64。

6. **Vulnerability versus exploit?**
   A vulnerability is a defect or unsafe condition that violates a security property. An exploit is a technique or input that takes advantage of it. This work plans to reproduce exploitation of CVE-2021-41773 by sending an encoded traversal request to an authorized local Apache 2.4.49 container. At the current checkpoint this CVE experiment has not run; it must not be described as successfully reproduced yet.
   中文：漏洞是缺陷，利用是触发缺陷的方法；本项目 CVE 复现仍待执行。

7. **Why regression tests after a fix?**
   Rejecting an attack is insufficient if the service is simply broken or unavailable. Repeating the attack and testing normal service behavior distinguishes effective remediation from accidental downtime, and detects compatibility problems introduced by the patch.
   中文：攻击失败可能只是服务挂了，必须同时证明正常功能仍可用。

8. **How does CVE reproduction help practitioners?**
   Controlled reproduction helps validate exposure, understand prerequisites and impact, prioritize remediation, develop detections and verify patches. A pentester can provide evidence of an actual weakness; a SOC analyst can better recognize relevant request patterns and distinguish attempted from successful exploitation. All reproduction must remain within explicit authorization.
   中文：帮助判断真实影响、定位根因、改进检测和验证修复，测试必须获得授权。
