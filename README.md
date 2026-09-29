# MySQL 死锁 / 慢 SQL / 大事务巡检服务

这是一个运行在 Docker 中的 Python 巡检服务，用于定时检测 MySQL / RDS MySQL / Aurora MySQL 的：

- InnoDB 最近一次死锁：`SHOW ENGINE INNODB STATUS`
- 当前锁等待：`performance_schema.data_lock_waits`，失败时自动尝试 `sys.innodb_lock_waits`
- 大事务 / 长事务：`information_schema.innodb_trx`
- 正在运行的慢 SQL：`information_schema.PROCESSLIST`
- 可选：`mysql.slow_log` 表中的慢 SQL
- 可选：`performance_schema.events_statements_summary_by_digest` 慢 SQL 模板

默认行为：

- 每 30 分钟巡检一次；
- 数据库连接信息全部放在 `.env`；
- 发现死锁、慢 SQL、大事务、锁等待时，发送一份 HTML 报告到 Telegram 群；
- 没有异常时不发群消息，只在容器日志记录 `no_findings=true`；
- 死锁按 SHA256 去重，同一条 `LATEST DETECTED DEADLOCK` 不会重复告警。

---

## 1. 目录结构

```text
mysql-lock-slow-monitor/
├── app.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── README.md
└── data/
```

---

## 2. 创建监控账号

建议不要使用业务账号或 root，单独创建只读监控账号：

```sql
CREATE USER 'mysql_monitor'@'%' IDENTIFIED BY 'ChangeMe_StrongPassword';

GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'mysql_monitor'@'%';
GRANT SELECT ON performance_schema.* TO 'mysql_monitor'@'%';
GRANT SELECT ON information_schema.* TO 'mysql_monitor'@'%';

-- 如果开启 ENABLE_SLOW_LOG_TABLE=true，再授予：
GRANT SELECT ON mysql.slow_log TO 'mysql_monitor'@'%';

FLUSH PRIVILEGES;
```

如果是 AWS RDS / Aurora MySQL，权限可能受限；至少要保证账号可以执行：

```sql
SHOW ENGINE INNODB STATUS;
SELECT * FROM information_schema.innodb_trx;
SELECT * FROM information_schema.PROCESSLIST;
SELECT * FROM performance_schema.data_lock_waits;
SELECT * FROM performance_schema.data_locks;
```

---

## 3. 配置 `.env`

```bash
cp .env.example .env
vi .env
```

核心配置：

```env
MYSQL_HOST=
MYSQL_PORT=3306
MYSQL_USER=mysql_monitor
MYSQL_PASSWORD=ChangeMe_StrongPassword
MYSQL_DATABASE=

# 30 分钟巡检一次
CHECK_INTERVAL_SECONDS=1800

# 大事务阈值，超过 60 秒告警
LONG_TRX_SECONDS=60

# 正在运行 SQL 超过 10 秒告警
PROCESSLIST_SLOW_SECONDS=10

# Telegram 群告警
TELEGRAM_BOT_TOKEN=123456:xxxxxx
TELEGRAM_CHAT_ID=
```

完整示例见 `.env.example`。

---

## 4. 构建并启动

```bash
docker compose up -d --build
```

查看日志：

```bash
docker logs -f mysql-lock-slow-monitor
```

测试执行一次后退出：

```bash
RUN_ONCE=true docker compose run --rm mysql-lock-slow-monitor
```

---

## 5. 报告内容

发现异常时，群里会收到 HTML 报告，包含：

- MySQL 主机、端口、版本、hostname；
- 异常类型和级别；
- 新死锁的 `deadlock_sha256` 和 `LATEST DETECTED DEADLOCK` 片段；
- 锁等待的等待线程、阻塞线程、等待 SQL、阻塞 SQL、锁表、索引；
- 大事务的 `trx_id`、`trx_mysql_thread_id`、运行秒数、锁行数、修改行数、事务 SQL；
- 慢 SQL 的 process id、用户、DB、运行时间、SQL 文本；
- 可选 `mysql.slow_log` 的 query_time、lock_time、rows_examined、SQL 文本。

没有异常时，不会发送 Telegram 消息。

---

## 6. 推荐 MySQL 参数

建议开启所有死锁写入 error log：

```sql
SET GLOBAL innodb_print_all_deadlocks = ON;
SHOW VARIABLES LIKE 'innodb_print_all_deadlocks';
```

RDS / Aurora 建议在参数组设置：

```text
innodb_print_all_deadlocks = 1
```

如果要启用 `mysql.slow_log` 表检测，需要开启：

```sql
SET GLOBAL slow_query_log = ON;
SET GLOBAL long_query_time = 1;
SET GLOBAL log_output = 'TABLE';
```

RDS / Aurora 通常需要通过参数组配置。

然后 `.env` 开启：

```env
ENABLE_SLOW_LOG_TABLE=true
SLOW_LOG_LOOKBACK_MINUTES=30
```

---

## 7. 告警静默逻辑

服务不是定时发送日报，而是异常触发：

```text
有新死锁：发送
有当前锁等待：发送
有大事务：发送
有正在运行慢 SQL：发送
有 mysql.slow_log 新记录：发送
没有异常：不发送
```

死锁去重依赖：

```env
DEADLOCK_STATE_FILE=/data/last_deadlock.sha256
```

所以 `docker-compose.yml` 挂载了：

```yaml
volumes:
  - ./data:/data
```

不要删除 `./data/last_deadlock.sha256`，否则同一条历史死锁可能会再次发送。

---

## 8. 生产建议阈值

```env
CHECK_INTERVAL_SECONDS=1800
LONG_TRX_SECONDS=60
PROCESSLIST_SLOW_SECONDS=10
LOCK_WAIT_ALERT_THRESHOLD=1
ENABLE_SLOW_LOG_TABLE=false
ENABLE_DIGEST_SUMMARY=false
```

如果希望更敏感：

```env
LONG_TRX_SECONDS=30
PROCESSLIST_SLOW_SECONDS=5
```

如果慢 SQL 太多，建议提高：

```env
PROCESSLIST_SLOW_SECONDS=30
```

---

## 9. 常用运维命令

启动：

```bash
docker compose up -d --build
```

停止：

```bash
docker compose down
```

重启：

```bash
docker compose restart
```

查看日志：

```bash
docker logs -f mysql-lock-slow-monitor
```

临时执行一次巡检：

```bash
RUN_ONCE=true docker compose run --rm mysql-lock-slow-monitor
```

---

## 10. 注意事项

1. `SHOW ENGINE INNODB STATUS` 只保留最近一次死锁，不代表当前还在死锁。
2. 服务只对新的死锁 hash 告警，同一条死锁不会重复发送。
3. `PROCESSLIST` 检测的是当前正在跑的慢 SQL，如果 SQL 在两轮巡检之间开始并结束，可能不会被捕捉；要覆盖历史慢 SQL，请开启 `mysql.slow_log` 表检测。
4. Telegram HTML 不支持完整网页 HTML，因此报告使用 `<b>`、`<code>`、`<pre>` 等 Telegram 支持的 HTML 标签。
# mysql-lock-slow-monitor
