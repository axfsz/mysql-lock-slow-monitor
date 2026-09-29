#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MySQL deadlock / slow SQL / long transaction inspection service.

Design goals:
- Run inside Docker.
- Read all MySQL connection and alert config from .env.
- Inspect every CHECK_INTERVAL_SECONDS seconds, default 1800 seconds / 30 minutes.
- Send one aggregated HTML report to the group only when findings exist.
- Stay silent when no deadlock, no slow SQL, no lock wait, and no long transaction are found.
- Telegram uses parse_mode=HTML. Generic webhook receives JSON with html_report and findings.
"""

from __future__ import annotations

import hashlib
import html
import json
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pymysql
import requests
from pymysql.cursors import DictCursor

STOP = False


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return int(value)


def _float_env(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return float(value)


def _str_env(name: str, default: str = "") -> str:
    value = os.getenv(name)
    if value is None:
        return default
    return value


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def truncate_text(value: Any, limit: int = 1800) -> str:
    if value is None:
        return ""
    text = str(value)
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... truncated, total_len={len(text)} ..."


def json_default(value: Any) -> str:
    return str(value)


@dataclass(frozen=True)
class Config:
    service_name: str

    mysql_host: str
    mysql_port: int
    mysql_user: str
    mysql_password: str
    mysql_database: Optional[str]
    mysql_connect_timeout: int
    mysql_read_timeout: int

    check_interval_seconds: int
    run_once: bool
    deadlock_state_file: Path

    long_trx_seconds: int
    processlist_slow_seconds: int
    lock_wait_alert_threshold: int

    enable_slow_log_table: bool
    slow_log_lookback_minutes: int
    slow_log_limit: int

    enable_digest_summary: bool
    digest_avg_seconds: float
    digest_limit: int

    alert_webhook_url: str
    telegram_bot_token: str
    telegram_chat_id: str
    telegram_disable_web_page_preview: bool

    report_max_chars: int

    @staticmethod
    def from_env() -> "Config":
        mysql_password = _str_env("MYSQL_PASSWORD")
        if not mysql_password:
            logging.warning("MYSQL_PASSWORD is empty. Connection may fail unless passwordless login is enabled.")

        return Config(
            service_name=_str_env("SERVICE_NAME", "MySQL 死锁/慢SQL巡检"),
            mysql_host=_str_env("MYSQL_HOST", "127.0.0.1"),
            mysql_port=_int_env("MYSQL_PORT", 3306),
            mysql_user=_str_env("MYSQL_USER", "mysql_monitor"),
            mysql_password=mysql_password,
            mysql_database=_str_env("MYSQL_DATABASE") or None,
            mysql_connect_timeout=_int_env("MYSQL_CONNECT_TIMEOUT", 5),
            mysql_read_timeout=_int_env("MYSQL_READ_TIMEOUT", 30),
            check_interval_seconds=_int_env("CHECK_INTERVAL_SECONDS", 1800),
            run_once=_bool_env("RUN_ONCE", False),
            deadlock_state_file=Path(_str_env("DEADLOCK_STATE_FILE", "/data/last_deadlock.sha256")),
            long_trx_seconds=_int_env("LONG_TRX_SECONDS", 60),
            processlist_slow_seconds=_int_env("PROCESSLIST_SLOW_SECONDS", 10),
            lock_wait_alert_threshold=_int_env("LOCK_WAIT_ALERT_THRESHOLD", 1),
            enable_slow_log_table=_bool_env("ENABLE_SLOW_LOG_TABLE", False),
            slow_log_lookback_minutes=_int_env("SLOW_LOG_LOOKBACK_MINUTES", 30),
            slow_log_limit=_int_env("SLOW_LOG_LIMIT", 20),
            enable_digest_summary=_bool_env("ENABLE_DIGEST_SUMMARY", False),
            digest_avg_seconds=_float_env("DIGEST_AVG_SECONDS", 1.0),
            digest_limit=_int_env("DIGEST_LIMIT", 10),
            alert_webhook_url=_str_env("ALERT_WEBHOOK_URL"),
            telegram_bot_token=_str_env("TELEGRAM_BOT_TOKEN"),
            telegram_chat_id=_str_env("TELEGRAM_CHAT_ID"),
            telegram_disable_web_page_preview=_bool_env("TELEGRAM_DISABLE_WEB_PAGE_PREVIEW", True),
            report_max_chars=_int_env("REPORT_MAX_CHARS", 3800),
        )


class MySQLMonitor:
    def __init__(self, config: Config) -> None:
        self.config = config

    def connect(self):
        return pymysql.connect(
            host=self.config.mysql_host,
            port=self.config.mysql_port,
            user=self.config.mysql_user,
            password=self.config.mysql_password,
            database=self.config.mysql_database,
            charset="utf8mb4",
            cursorclass=DictCursor,
            connect_timeout=self.config.mysql_connect_timeout,
            read_timeout=self.config.mysql_read_timeout,
            autocommit=True,
        )

    @staticmethod
    def query(conn, sql: str, args: Optional[Tuple[Any, ...]] = None) -> List[Dict[str, Any]]:
        with conn.cursor() as cur:
            cur.execute(sql, args)
            return list(cur.fetchall())

    @staticmethod
    def query_one(conn, sql: str, args: Optional[Tuple[Any, ...]] = None) -> Optional[Dict[str, Any]]:
        rows = MySQLMonitor.query(conn, sql, args)
        return rows[0] if rows else None

    def run_check_once(self) -> Dict[str, Any]:
        started_at = now_utc_iso()
        findings: List[Dict[str, Any]] = []
        mysql_basic: Dict[str, Any] = {}

        with self.connect() as conn:
            mysql_basic = self.check_mysql_basic(conn)
            checks = [
                self.check_latest_deadlock,
                self.check_lock_waits,
                self.check_long_transactions,
                self.check_running_slow_sql,
            ]
            if self.config.enable_slow_log_table:
                checks.append(self.check_slow_log_table)
            if self.config.enable_digest_summary:
                checks.append(self.check_digest_summary)

            for check in checks:
                try:
                    result = check(conn)
                    if result:
                        if isinstance(result, list):
                            findings.extend(result)
                        else:
                            findings.append(result)
                except Exception as exc:  # noqa: BLE001
                    logging.exception("check_failed check=%s", check.__name__)
                    findings.append(
                        {
                            "type": "monitor_check_error",
                            "level": "ERROR",
                            "title": f"巡检模块失败：{check.__name__}",
                            "summary": str(exc),
                            "rows": [],
                        }
                    )

        report = {
            "service": self.config.service_name,
            "mysql_host": self.config.mysql_host,
            "mysql_port": self.config.mysql_port,
            "started_at_utc": started_at,
            "finished_at_utc": now_utc_iso(),
            "mysql_basic": mysql_basic,
            "findings": findings,
        }

        if findings:
            html_report = self.build_html_report(report)
            logging.warning("mysql_inspection_findings=%s", json.dumps(report, ensure_ascii=False, default=json_default))
            self.send_report(report, html_report)
        else:
            logging.info("mysql_inspection_ok host=%s port=%s no_findings=true", self.config.mysql_host, self.config.mysql_port)

        return report

    def check_mysql_basic(self, conn) -> Dict[str, Any]:
        sql = """
            SELECT
                VERSION() AS version,
                @@hostname AS hostname,
                @@port AS port,
                @@performance_schema AS performance_schema,
                @@innodb_print_all_deadlocks AS innodb_print_all_deadlocks
        """
        try:
            return self.query_one(conn, sql) or {}
        except Exception as exc:  # noqa: BLE001
            logging.info("mysql_basic_check_failed error=%s", exc)
            return {"error": str(exc)}

    @staticmethod
    def extract_deadlock(status: str) -> Optional[str]:
        marker = "LATEST DETECTED DEADLOCK"
        start = status.find(marker)
        if start < 0:
            return None

        # This section usually ends before the TRANSACTIONS section.
        end_candidates = [
            "------------\nTRANSACTIONS",
            "------------\r\nTRANSACTIONS",
            "TRANSACTIONS\n------------",
            "\nTRANSACTIONS\n",
        ]
        end = -1
        for candidate in end_candidates:
            idx = status.find(candidate, start)
            if idx > start:
                end = idx
                break
        if end < 0:
            end = min(len(status), start + 20000)
        return status[start:end].strip()

    def check_latest_deadlock(self, conn) -> Optional[Dict[str, Any]]:
        rows = self.query(conn, "SHOW ENGINE INNODB STATUS")
        if not rows:
            return None

        status = rows[0].get("Status") or rows[0].get("status") or ""
        deadlock = self.extract_deadlock(status)
        if not deadlock:
            return None

        digest = hashlib.sha256(deadlock.encode("utf-8", errors="ignore")).hexdigest()
        previous_digest = ""
        if self.config.deadlock_state_file.exists():
            previous_digest = self.config.deadlock_state_file.read_text(encoding="utf-8").strip()

        if digest == previous_digest:
            return None

        self.config.deadlock_state_file.parent.mkdir(parents=True, exist_ok=True)
        self.config.deadlock_state_file.write_text(digest, encoding="utf-8")

        return {
            "type": "deadlock",
            "level": "CRITICAL",
            "title": "发现新的 InnoDB 死锁记录",
            "summary": "SHOW ENGINE INNODB STATUS 出现新的 LATEST DETECTED DEADLOCK，已按 sha256 去重。",
            "deadlock_sha256": digest,
            "deadlock_excerpt": truncate_text(deadlock, 7000),
            "rows": [],
        }

    def check_lock_waits(self, conn) -> Optional[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        source = "performance_schema.data_lock_waits"

        sql_perf = """
            SELECT
                waiting_trx.trx_id AS waiting_trx_id,
                waiting_trx.trx_mysql_thread_id AS waiting_thread_id,
                waiting_trx.trx_started AS waiting_started,
                TIMESTAMPDIFF(SECOND, waiting_trx.trx_started, NOW()) AS waiting_seconds,
                LEFT(waiting_trx.trx_query, 2500) AS waiting_query,
                blocking_trx.trx_id AS blocking_trx_id,
                blocking_trx.trx_mysql_thread_id AS blocking_thread_id,
                blocking_trx.trx_started AS blocking_started,
                TIMESTAMPDIFF(SECOND, blocking_trx.trx_started, NOW()) AS blocking_seconds,
                LEFT(blocking_trx.trx_query, 2500) AS blocking_query,
                waiting_lock.OBJECT_SCHEMA AS locked_schema,
                waiting_lock.OBJECT_NAME AS locked_table,
                waiting_lock.INDEX_NAME AS locked_index,
                waiting_lock.LOCK_TYPE AS lock_type,
                waiting_lock.LOCK_MODE AS waiting_lock_mode,
                blocking_lock.LOCK_MODE AS blocking_lock_mode,
                LEFT(waiting_lock.LOCK_DATA, 1000) AS lock_data
            FROM performance_schema.data_lock_waits w
            JOIN performance_schema.data_locks waiting_lock
                ON w.REQUESTING_ENGINE_LOCK_ID = waiting_lock.ENGINE_LOCK_ID
            JOIN performance_schema.data_locks blocking_lock
                ON w.BLOCKING_ENGINE_LOCK_ID = blocking_lock.ENGINE_LOCK_ID
            LEFT JOIN information_schema.innodb_trx waiting_trx
                ON waiting_lock.ENGINE_TRANSACTION_ID = waiting_trx.trx_id
            LEFT JOIN information_schema.innodb_trx blocking_trx
                ON blocking_lock.ENGINE_TRANSACTION_ID = blocking_trx.trx_id
            ORDER BY waiting_seconds DESC
            LIMIT 50
        """

        try:
            rows = self.query(conn, sql_perf)
        except Exception as perf_exc:  # noqa: BLE001
            source = "sys.innodb_lock_waits"
            sql_sys = """
                SELECT
                    wait_started,
                    wait_age,
                    wait_age_secs,
                    locked_table,
                    locked_index,
                    locked_type,
                    waiting_pid,
                    LEFT(waiting_query, 2500) AS waiting_query,
                    blocking_pid,
                    LEFT(blocking_query, 2500) AS blocking_query
                FROM sys.innodb_lock_waits
                ORDER BY wait_age_secs DESC
                LIMIT 50
            """
            try:
                rows = self.query(conn, sql_sys)
            except Exception as sys_exc:  # noqa: BLE001
                logging.info("lock_wait_check_unsupported performance_schema_error=%s sys_error=%s", perf_exc, sys_exc)
                return None

        if len(rows) >= self.config.lock_wait_alert_threshold and rows:
            return {
                "type": "lock_wait",
                "level": "WARN",
                "title": "发现当前 MySQL 锁等待",
                "summary": f"当前存在 {len(rows)} 条锁等待记录，来源：{source}。",
                "source": source,
                "rows": rows,
            }
        return None

    def check_long_transactions(self, conn) -> Optional[Dict[str, Any]]:
        sql = """
            SELECT
                trx_id,
                trx_state,
                trx_started,
                TIMESTAMPDIFF(SECOND, trx_started, NOW()) AS running_seconds,
                trx_mysql_thread_id,
                trx_rows_locked,
                trx_rows_modified,
                LEFT(trx_query, 3000) AS trx_query
            FROM information_schema.innodb_trx
            WHERE TIMESTAMPDIFF(SECOND, trx_started, NOW()) >= %s
            ORDER BY running_seconds DESC
            LIMIT 50
        """
        rows = self.query(conn, sql, (self.config.long_trx_seconds,))
        if rows:
            return {
                "type": "long_transaction",
                "level": "WARN",
                "title": "发现 MySQL 大事务 / 长事务",
                "summary": f"存在 {len(rows)} 个运行时间超过 {self.config.long_trx_seconds}s 的事务。",
                "threshold_seconds": self.config.long_trx_seconds,
                "rows": rows,
            }
        return None

    def check_running_slow_sql(self, conn) -> Optional[Dict[str, Any]]:
        sql = """
            SELECT
                ID,
                USER,
                HOST,
                DB,
                COMMAND,
                TIME AS running_seconds,
                STATE,
                LEFT(INFO, 3000) AS sql_text
            FROM information_schema.PROCESSLIST
            WHERE COMMAND <> 'Sleep'
              AND INFO IS NOT NULL
              AND TIME >= %s
              AND ID <> CONNECTION_ID()
            ORDER BY TIME DESC
            LIMIT 50
        """
        rows = self.query(conn, sql, (self.config.processlist_slow_seconds,))
        if rows:
            return {
                "type": "running_slow_sql",
                "level": "WARN",
                "title": "发现正在运行的慢 SQL",
                "summary": f"存在 {len(rows)} 条运行超过 {self.config.processlist_slow_seconds}s 的 SQL。",
                "threshold_seconds": self.config.processlist_slow_seconds,
                "rows": rows,
            }
        return None

    def check_slow_log_table(self, conn) -> Optional[Dict[str, Any]]:
        # Requires slow_query_log=ON, log_output=TABLE, and SELECT on mysql.slow_log.
        sql = """
            SELECT
                start_time,
                user_host,
                query_time,
                lock_time,
                rows_sent,
                rows_examined,
                db,
                LEFT(sql_text, 3000) AS sql_text
            FROM mysql.slow_log
            WHERE start_time >= DATE_SUB(NOW(), INTERVAL %s MINUTE)
            ORDER BY start_time DESC
            LIMIT %s
        """
        rows = self.query(conn, sql, (self.config.slow_log_lookback_minutes, self.config.slow_log_limit))
        if rows:
            return {
                "type": "slow_log_table",
                "level": "WARN",
                "title": "发现 mysql.slow_log 慢 SQL 记录",
                "summary": f"最近 {self.config.slow_log_lookback_minutes} 分钟 mysql.slow_log 有 {len(rows)} 条记录。",
                "lookback_minutes": self.config.slow_log_lookback_minutes,
                "rows": rows,
            }
        return None

    def check_digest_summary(self, conn) -> Optional[Dict[str, Any]]:
        # TIMER_WAIT columns are in picoseconds.
        sql = """
            SELECT
                SCHEMA_NAME,
                DIGEST,
                LEFT(DIGEST_TEXT, 2500) AS digest_text,
                COUNT_STAR AS exec_count,
                ROUND(SUM_TIMER_WAIT / 1000000000000, 6) AS total_seconds,
                ROUND(AVG_TIMER_WAIT / 1000000000000, 6) AS avg_seconds,
                ROUND(MAX_TIMER_WAIT / 1000000000000, 6) AS max_seconds,
                SUM_ROWS_EXAMINED AS rows_examined,
                SUM_ROWS_SENT AS rows_sent,
                SUM_ERRORS AS errors,
                SUM_WARNINGS AS warnings
            FROM performance_schema.events_statements_summary_by_digest
            WHERE SCHEMA_NAME IS NOT NULL
              AND AVG_TIMER_WAIT / 1000000000000 >= %s
            ORDER BY AVG_TIMER_WAIT DESC
            LIMIT %s
        """
        rows = self.query(conn, sql, (self.config.digest_avg_seconds, self.config.digest_limit))
        if rows:
            return {
                "type": "digest_summary",
                "level": "INFO",
                "title": "发现 Performance Schema 慢 SQL 模板",
                "summary": f"存在 {len(rows)} 类平均耗时超过 {self.config.digest_avg_seconds}s 的 SQL 模板。",
                "avg_seconds_threshold": self.config.digest_avg_seconds,
                "rows": rows,
            }
        return None

    def build_html_report(self, report: Dict[str, Any]) -> str:
        findings = report["findings"]
        highest = self.highest_level(findings)
        basic = report.get("mysql_basic") or {}

        lines = [
            f"<b>[{html.escape(highest)}] {html.escape(self.config.service_name)}</b>",
            f"<b>MySQL:</b> <code>{html.escape(str(report['mysql_host']))}:{html.escape(str(report['mysql_port']))}</code>",
            f"<b>时间:</b> <code>{html.escape(str(report['finished_at_utc']))}</code>",
        ]

        if basic:
            version = basic.get("version", "")
            hostname = basic.get("hostname", "")
            perf = basic.get("performance_schema", "")
            deadlog = basic.get("innodb_print_all_deadlocks", "")
            lines.append(
                "<b>实例:</b> "
                f"<code>{html.escape(str(hostname))}</code> "
                f"<code>{html.escape(str(version))}</code> "
                f"performance_schema=<code>{html.escape(str(perf))}</code> "
                f"print_all_deadlocks=<code>{html.escape(str(deadlog))}</code>"
            )

        lines.append(f"<b>异常项:</b> <code>{len(findings)}</code>")

        for idx, finding in enumerate(findings, start=1):
            lines.append("")
            lines.append(f"<b>{idx}. {html.escape(finding.get('title', '未命名异常'))}</b>")
            lines.append(f"级别: <code>{html.escape(finding.get('level', 'WARN'))}</code> 类型: <code>{html.escape(finding.get('type', 'unknown'))}</code>")
            lines.append(f"说明: {html.escape(str(finding.get('summary', '')))}")

            if finding.get("deadlock_sha256"):
                lines.append(f"deadlock_sha256: <code>{html.escape(str(finding['deadlock_sha256']))}</code>")
                lines.append("<b>死锁片段:</b>")
                lines.append(f"<pre>{html.escape(truncate_text(finding.get('deadlock_excerpt'), 2200))}</pre>")

            rows = finding.get("rows") or []
            if rows:
                lines.append(f"<b>明细 Top {min(len(rows), 5)}:</b>")
                for row_no, row in enumerate(rows[:5], start=1):
                    lines.extend(self.format_row_for_html(finding.get("type", "unknown"), row_no, row))

        text = "\n".join(lines)
        if len(text) > self.config.report_max_chars:
            text = text[: self.config.report_max_chars] + "\n... report truncated ..."
        return text

    @staticmethod
    def highest_level(findings: List[Dict[str, Any]]) -> str:
        order = {"CRITICAL": 4, "ERROR": 3, "WARN": 2, "WARNING": 2, "INFO": 1}
        highest = "INFO"
        for item in findings:
            level = str(item.get("level", "INFO")).upper()
            if order.get(level, 0) > order.get(highest, 0):
                highest = level
        return highest

    @staticmethod
    def format_row_for_html(kind: str, row_no: int, row: Dict[str, Any]) -> List[str]:
        def code(key: str) -> str:
            value = row.get(key, "")
            return f"<code>{html.escape(str(value))}</code>"

        lines: List[str] = [f"<b>#{row_no}</b>"]

        if kind == "lock_wait":
            lines.append(
                "等待线程=" + code("waiting_thread_id")
                + " 阻塞线程=" + code("blocking_thread_id")
                + " 等待秒=" + code("waiting_seconds")
            )
            lines.append("表=" + code("locked_schema") + "." + code("locked_table") + " 索引=" + code("locked_index"))
            if row.get("waiting_query"):
                lines.append("等待SQL:")
                lines.append(f"<pre>{html.escape(truncate_text(row.get('waiting_query'), 900))}</pre>")
            if row.get("blocking_query"):
                lines.append("阻塞SQL:")
                lines.append(f"<pre>{html.escape(truncate_text(row.get('blocking_query'), 900))}</pre>")
            return lines

        if kind == "long_transaction":
            lines.append(
                "trx_id=" + code("trx_id")
                + " thread_id=" + code("trx_mysql_thread_id")
                + " 状态=" + code("trx_state")
                + " 运行秒=" + code("running_seconds")
            )
            lines.append("锁行=" + code("trx_rows_locked") + " 修改行=" + code("trx_rows_modified"))
            if row.get("trx_query"):
                lines.append("事务SQL:")
                lines.append(f"<pre>{html.escape(truncate_text(row.get('trx_query'), 1000))}</pre>")
            return lines

        if kind == "running_slow_sql":
            lines.append(
                "process_id=" + code("ID")
                + " user=" + code("USER")
                + " db=" + code("DB")
                + " 运行秒=" + code("running_seconds")
            )
            lines.append("host=" + code("HOST") + " state=" + code("STATE"))
            if row.get("sql_text"):
                lines.append("SQL:")
                lines.append(f"<pre>{html.escape(truncate_text(row.get('sql_text'), 1200))}</pre>")
            return lines

        if kind == "slow_log_table":
            lines.append(
                "start_time=" + code("start_time")
                + " db=" + code("db")
                + " query_time=" + code("query_time")
                + " lock_time=" + code("lock_time")
            )
            lines.append("rows_examined=" + code("rows_examined") + " rows_sent=" + code("rows_sent"))
            if row.get("sql_text"):
                lines.append("SQL:")
                lines.append(f"<pre>{html.escape(truncate_text(row.get('sql_text'), 1200))}</pre>")
            return lines

        if kind == "digest_summary":
            lines.append(
                "schema=" + code("SCHEMA_NAME")
                + " avg秒=" + code("avg_seconds")
                + " max秒=" + code("max_seconds")
                + " 次数=" + code("exec_count")
            )
            if row.get("digest_text"):
                lines.append("SQL模板:")
                lines.append(f"<pre>{html.escape(truncate_text(row.get('digest_text'), 1000))}</pre>")
            return lines

        lines.append(f"<pre>{html.escape(json.dumps(row, ensure_ascii=False, indent=2, default=json_default))}</pre>")
        return lines

    def send_report(self, report: Dict[str, Any], html_report: str) -> None:
        sent = False

        if self.config.telegram_bot_token and self.config.telegram_chat_id:
            try:
                self.send_telegram_html(html_report)
                sent = True
            except Exception as exc:  # noqa: BLE001
                logging.warning("send_telegram_report_failed error=%s", exc)

        if self.config.alert_webhook_url:
            try:
                payload = {
                    "service": self.config.service_name,
                    "mysql_host": self.config.mysql_host,
                    "mysql_port": self.config.mysql_port,
                    "time": now_utc_iso(),
                    "html_report": html_report,
                    "findings": report.get("findings", []),
                    "mysql_basic": report.get("mysql_basic", {}),
                }
                requests.post(self.config.alert_webhook_url, json=payload, timeout=10)
                sent = True
            except Exception as exc:  # noqa: BLE001
                logging.warning("send_webhook_report_failed error=%s", exc)

        if not sent:
            logging.warning("no_alert_target_configured html_report=%s", html_report)

    def send_telegram_html(self, text: str) -> None:
        # Telegram message limit is 4096 chars. Keep chunks below that.
        chunks = self.split_text(text, self.config.report_max_chars)
        url = f"https://api.telegram.org/bot{self.config.telegram_bot_token}/sendMessage"
        for idx, chunk in enumerate(chunks, start=1):
            if len(chunks) > 1:
                chunk = f"<b>Part {idx}/{len(chunks)}</b>\n" + chunk
            resp = requests.post(
                url,
                json={
                    "chat_id": self.config.telegram_chat_id,
                    "text": chunk,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": self.config.telegram_disable_web_page_preview,
                },
                timeout=10,
            )
            if resp.status_code >= 300:
                raise RuntimeError(f"telegram status={resp.status_code} body={resp.text[:500]}")

    @staticmethod
    def split_text(text: str, limit: int) -> List[str]:
        if len(text) <= limit:
            return [text]
        chunks: List[str] = []
        remaining = text
        while remaining:
            if len(remaining) <= limit:
                chunks.append(remaining)
                break
            cut = remaining.rfind("\n", 0, limit)
            if cut < 1000:
                cut = limit
            chunks.append(remaining[:cut])
            remaining = remaining[cut:].lstrip("\n")
        return chunks


def setup_logging() -> None:
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stdout,
    )


def handle_signal(signum, frame) -> None:  # noqa: ANN001, ARG001
    global STOP
    STOP = True
    logging.info("received signal=%s, stopping", signum)


def main() -> int:
    setup_logging()
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    config = Config.from_env()
    monitor = MySQLMonitor(config)

    logging.info(
        "mysql_monitor_started service=%s host=%s port=%s interval=%ss run_once=%s",
        config.service_name,
        config.mysql_host,
        config.mysql_port,
        config.check_interval_seconds,
        config.run_once,
    )

    while not STOP:
        started = time.time()
        try:
            monitor.run_check_once()
        except Exception as exc:  # noqa: BLE001
            logging.exception("mysql_monitor_loop_failed")
            report = {
                "service": config.service_name,
                "mysql_host": config.mysql_host,
                "mysql_port": config.mysql_port,
                "started_at_utc": now_utc_iso(),
                "finished_at_utc": now_utc_iso(),
                "mysql_basic": {},
                "findings": [
                    {
                        "type": "monitor_error",
                        "level": "ERROR",
                        "title": "MySQL 巡检服务执行失败",
                        "summary": str(exc),
                        "rows": [],
                    }
                ],
            }
            html_report = monitor.build_html_report(report)
            monitor.send_report(report, html_report)

        if config.run_once:
            break

        elapsed = time.time() - started
        sleep_seconds = max(1, config.check_interval_seconds - int(elapsed))
        for _ in range(sleep_seconds):
            if STOP:
                break
            time.sleep(1)

    logging.info("mysql_monitor_stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
