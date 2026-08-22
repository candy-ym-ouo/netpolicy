# 05 API 接口设计

## 1. 通用约定

- 基础路径：`/api/v1`；响应均为 JSON（`Content-Type: application/json`）。
- 时间戳格式：RFC3339。
- 统一响应包装：

```json
{ "ok": true, "data": { ... }, "error": null }
{ "ok": false, "data": null, "error": { "code": "RULE_NOT_FOUND", "message": "规则不存在: r99" } }
```

- 错误码约定：

| 错误码 | HTTP 状态 | 含义 |
| --- | --- | --- |
| BAD_REQUEST | 400 | 参数校验失败（含导入数据格式错误） |
| UNAUTHORIZED | 401 | 缺少 `X-User` 头（仅当开启 `requireUser=true`） |
| RULE_NOT_FOUND | 404 | 规则不存在 |
| TASK_NOT_FOUND | 404 | 任务不存在 |
| RESULT_NOT_FOUND | 404 | 结果不存在 |
| CONFLICT | 409 | 状态冲突（如重复导入 ID 冲突） |
| TOO_MANY_RULES | 422 | 同步分析超出规则数上限，请改用异步任务 |
| INTERNAL | 500 | 内部错误 |
| SERVICE_UNAVAILABLE | 503 | 启动自检未通过 / 存储不可用 |

- 审计头：可选 `X-User`（操作人，写入审计日志），未开启鉴权时缺省为 `anonymous`。
- 分页参数：`page`（默认 1）、`pageSize`（默认 50，上限 500），返回 `{total, page, pageSize, items}`。

## 2. 接口清单

### 2.1 健康与概览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/v1/health` | 存活探针：`{status:"ok", store:"memory", migrationVersion:1}` |
| GET | `/api/v1/stats` | 概览统计：规则总数、策略集数、任务数（按状态）、最近审计日志 |

### 2.2 规则管理

#### POST `/api/v1/rules/import`
导入规则。

请求体：

```json
{
  "format": "auto",            // auto | csv | json | yaml
  "mode": "append",            // append（追加，默认）| replace（全量替换）
  "data": "[{\"id\":\"r1\",\"policySet\":\"fw-office\",\"priority\":10,\"action\":\"allow\",\"src\":\"10.0.0.0/24\",\"dst\":\"172.16.0.0/16\",\"protocol\":\"tcp\",\"portFrom\":80,\"portTo\":80,\"description\":\"办公区访问生产 Web\"}, ...]"
}
```

CSV 格式约定（列头：`id,policySet,priority,action,src,dst,protocol,portFrom,portTo,description,source`）。

响应：

```json
{ "ok": true, "data": { "imported": 128, "skipped": 2, "errors": [ { "line": 17, "field": "src", "message": "非法的 CIDR: 10.0.0.999" } ], "rulesetVersion": 5 } }
```

> 事务性：任一错误则整批失败（`imported: 0`，`errors` 全量返回）；`mode=replace` 时先清空再写入。

#### GET `/api/v1/rules`
规则列表。查询参数：`policySet`、`action`、`src`（前缀匹配）、`q`（ID/描述关键字）、`page`、`pageSize`。

#### GET `/api/v1/rules/{id}`
单条规则详情。

#### DELETE `/api/v1/rules/{id}`
删除规则。响应 `{deleted: true, rulesetVersion: n}`。

#### GET `/api/v1/rules/export`
导出当前规则集（JSON 数组），等价于迁移导出中的 rules 部分。

### 2.3 同步分析

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/v1/analysis/coverage` | 覆盖分析（同步） |
| POST | `/api/v1/analysis/conflicts` | 冲突检测（同步） |
| POST | `/api/v1/analysis/redundancy` | 冗余检测（同步） |
| POST | `/api/v1/analysis/reachability` | 可达性分析（同步，单场景） |

公共请求体：

```json
{
  "policySets": ["fw-office"],        // 可选，限定策略集；缺省全部
  "ruleIds": ["r1","r2"],            // 可选，限定规则；缺省全部
  "params": { ... }                  // 各类型专属参数
}
```

- coverage 专属：`{"targetSpace":["172.16.0.0/16","10.1.0.0/24"]}`（可选，缺省自动推导）；
- reachability 专属：`{"scenario":{"src":"10.0.0.5","dst":"172.16.1.10","protocol":"tcp","port":443}}`。

响应示例（reachability）：

```json
{ "ok": true, "data": {
    "scenario": { "src":"10.0.0.5", "dst":"172.16.1.10", "protocol":"tcp", "port":443 },
    "verdict": "allow",
    "defaultAction": "deny",
    "matchedChain": [ { "ruleId":"r1", "priority":10, "action":"allow", "reason":"src 命中、dst 命中、端口命中" } ]
} }
```

响应示例（coverage）：

```json
{ "ok": true, "data": {
    "coverageRatio": 0.875, "totalSpace": "172.16.0.0/16 等 8 个块",
    "uncovered": [ { "cidr":"172.16.3.0/24", "partial": false } ],
    "redundantRatio": 0.12,
    "perPolicySet": [ { "policySet":"fw-office", "ratio":0.9 } ]
} }
```

> 规则数超过 `config.maxRulesSync`（默认 2000）时返回 `TOO_MANY_RULES`，引导改用异步任务。

### 2.4 异步分析任务

#### POST `/api/v1/analysis/tasks`
创建分析任务。请求体：`{ "type": "coverage|conflicts|redundancy|reachability|matrix|whatif|simulate", "policySets": [...], "ruleIds": [...], "params": {...} }`。

matrix 专属参数：`{"sources":["10.0.0.0/24","10.1.0.0/24"],"targets":["172.16.1.10","172.16.1.11"],"protocol":"tcp","ports":[80,443]}`。

响应：`{ "taskId": "t_8f3a...", "status": "pending" }`。

#### GET `/api/v1/analysis/tasks/{id}`
任务状态：`{ id, type, status, retryCount, error, rulesetVersion, createdAt, startedAt, finishedAt }`。

#### GET `/api/v1/analysis/tasks`
任务列表（分页），参数：`status`、`type`、`page`、`pageSize`。

#### POST `/api/v1/analysis/tasks/{id}/retry`
重试失败任务（重置为 pending，retryCount+1）。

#### GET `/api/v1/analysis/results/{taskId}`
任务结果：`{ taskId, type, rulesetVersion, summary, payload, createdAt }`（payload 为结构化 JSON 字符串）。

### 2.5 完整检查与报告

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/v1/checks` | 触发按需完整检查，返回报告 |
| GET | `/api/v1/checks/latest` | 最近一次检查报告 |
| GET | `/api/v1/reports/{taskId}` | 导出结果报告：`?format=json|html` |

checks 响应：

```json
{ "ok": true, "data": {
    "runAt": "...", "passed": 8, "warnings": 1, "failed": 0,
    "items": [
      { "category":"rule_format", "name":"规则格式完整性", "level":"pass",
        "detail":"128/128 条规则通过格式校验" },
      { "category":"reference", "name":"引用完整性", "level":"warn",
        "detail":"发现 1 个孤儿分析结果（task t_99 不存在）" }
    ]
} }
```

### 2.6 迁移与审计

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/v1/migrate/export` | 导出完整数据包（rules + tasks + results） |
| POST | `/api/v1/migrate/import` | 导入数据包（请求体为导出包 JSON） |
| GET | `/api/v1/audit` | 最近审计日志：`?limit=50` |

## 3. 静态资源

- `GET /` → `web/index.html`；
- `GET /app.js`、`/style.css` → 前端静态资源（由 api.Server 挂载 `web/` 目录，`http.FileServer`）。

## 4. 附录：示例导入数据（JSON）

```json
[
  {"id":"r1","policySet":"fw-office","priority":10,"action":"allow","src":"10.0.0.0/24","dst":"172.16.0.0/16","protocol":"tcp","portFrom":80,"portTo":443,"description":"办公区访问生产"},
  {"id":"r2","policySet":"fw-office","priority":20,"action":"deny","src":"0.0.0.0/0","dst":"172.16.0.0/16","protocol":"any","portFrom":1,"portTo":65535,"description":"默认拒绝生产网段"},
  {"id":"r3","policySet":"sg-prod","priority":10,"action":"allow","src":"10.0.0.0/24","dst":"172.16.0.0/16","protocol":"tcp","portFrom":80,"portTo":80,"description":"与 r1 部分重叠（冲突演示）"},
  {"id":"r4","policySet":"fw-office","priority":5,"action":"deny","src":"10.0.1.0/24","dst":"172.16.1.0/24","protocol":"tcp","portFrom":22,"portTo":22,"description":"禁止某子网 SSH"}
]
```

> 上例可直观演示：r1/r3 完全冲突（同条件不同动作）、r1 覆盖 r2 的部分区域（优先级冲突）、r4 遮蔽（Shadowed）任何更低优先级的同条件规则。
