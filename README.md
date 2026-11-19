# pairwise-jwt-keyroll

## 题面

升级到支持多密钥轮换的网关后，令牌校验开始漏：alg 直接信 header，none 也能过、HS 与 RS 还能混用；kid 不做字符与长度校验，能塞进路径与控制字符，没有 kid 时随手挑第一把；exp 与 nbf 只看有没有、不认 leeway 和最大存活时间；重复的 JSON key 被后者覆盖，payload 能夹带第二个 exp；轮换后已退休的密钥还能签新令牌。jwt_verifier/keys.py 是核心，tests/test_jwt_keys.py 15个红。要修的是：alg 走白名单并绑定密钥类型；kid 严格正则与唯一候选规则；exp/nbf/iat 带 leeway 与 max_age；JSON 重复键与 payload 形状校验；retired 密钥只接受退役前的 iat。

## 运行方式

在仓库根目录执行：

```powershell
python -m pytest tests -q
```

初始状态下 15 个测试全部失败，汇总行必须是 `15 failed`；不得出现 collection error、import error 或 syntax error。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 其他 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 约束

`tests/test_jwt_keys.py` 不可修改；实现只改 `jwt_verifier/keys.py`，并保持其中五个函数的契约不变。
