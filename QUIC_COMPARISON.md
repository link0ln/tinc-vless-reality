# Сравнение реализаций QUIC: tinc-vless-reality vs rstun

## Обзор

Этот документ содержит детальное сравнение реализаций QUIC в проектах tinc-vless-reality (C + quiche) и rstun (Rust + quinn).

---

## 1. Архитектурные различия

### 1.1 Стек технологий

| Компонент | tinc-vless-reality | rstun |
|-----------|-------------------|-------|
| QUIC библиотека | **quiche** 0.x (Cloudflare) | **quinn** 0.11.8 (fork) |
| TLS | BoringSSL | rustls 0.23 + ring |
| Congestion Control | CUBIC (дефолт) | BBR |
| Язык | C | Rust |
| Async runtime | libevent | tokio 1.47 |

### 1.2 Философия дизайна

**tinc-vless-reality:**
- Фокус на **steganography** (Reality protocol, browser fingerprinting)
- VPN-специфичные оптимизации (packet buffering, stream 0 для metadata)
- Hybrid mode для плавного fallback на UDP

**rstun:**
- Фокус на **reliability** (retry logic, migration, cleanup)
- Tunnel-ориентированный (bidirectional TCP/UDP forwarding)
- Production-ready error handling

---

## 2. Функциональные возможности

### 2.1 Connection Management

#### ✅ tinc-vless-reality
```c
// Демультиплексирование через Connection ID map
quic_conn_t *lookup_connection_by_id(const uint8_t *cid, size_t len);

// Регистрация client/server SCID/DCID
register_connection_id(qconn->scid, qconn->scid_len, qconn);

// Fallback на peer address если CID lookup fails
for (candidate in connections) {
    if (sockaddrcmp_noport(&candidate->peer_addr, from) == 0)
        return candidate;
}
```

**Проблемы:**
- Нет connection migration → уязвим к UDP throttling
- Нет автоматической очистки мертвых соединений

#### ✅ rstun
```rust
// Exponential backoff для reconnect
ExponentialBuilder::default()
    .with_max_delay(Duration::from_secs(10))
    .with_jitter()
    .with_max_times(usize::MAX);

// Connection migration (rebind UDP socket)
async fn start_migration_task(&self) {
    loop {
        sleep(hop_interval_ms).await;
        endpoint.rebind(new_socket)?;
    }
}

// Session cleanup
async fn cleanup_sessions() {
    for session in sessions {
        if session.conn.close_reason().is_some() {
            sessions.remove(session);
        }
    }
}
```

**Преимущества:**
- ✅ Автоматическая миграция на новые порты (обход QoS throttling)
- ✅ Graceful retry при сбоях
- ✅ Периодическая очистка зависших сессий

---

### 2.2 Stream Management

#### tinc-vless-reality
```c
// Stream 0 для metadata (ID, ACK, PING)
if (qconn->is_client) {
    c->quic_stream_id = quic_meta_create_stream(qconn); // stream 0
} else {
    // Server ждет discovery client stream
    c->quic_stream_id = -1;
}

// VPN packets на отдельных streams
bool quic_conn_send_vpn_packet(qconn, data, len) {
    uint64_t stream_id = qconn->next_stream_id;
    quiche_conn_stream_send(conn, stream_id, data, len, false);
    qconn->next_stream_id += 4; // Skip to next bidi stream
}
```

**Особенности:**
- Stream 0 зарезервирован для control plane
- VPN data на streams 4, 8, 12, ... (client) / 5, 9, 13, ... (server)
- Нет явного управления stream windows

#### rstun
```rust
// Dynamic stream allocation
let (send, recv) = conn.open_bi().await?;

// Stream window configuration
transport.stream_receive_window(1024 * 1024);       // 1MB
transport.receive_window(2 * 1024 * 1024);          // 2MB
transport.max_concurrent_bidi_streams(1024.into());

// Backpressure handling
if send.write_all(&data).await.is_err() {
    // Retry или буферизация
}
```

**Преимущества:**
- ✅ Явное управление flow control
- ✅ До 1024 одновременных streams
- ✅ Backpressure через write errors

---

### 2.3 Handshake & Authentication

#### tinc-vless-reality: Reality Protocol
```c
// Извлечение SNI из TLS ClientHello в QUIC Initial
bool quic_reality_extract_sni(ctx, quic_packet);

// Проверка auth
if (strcmp(client_sni, config->server_name) != 0) {
    // Fallback на google.com
    quic_reality_start_fallback(ctx);
}

// Browser fingerprinting
quic_fingerprint_apply_name(config, "chrome");
```

**Уникальные возможности:**
- ✅ SNI-based steganography
- ✅ Fallback для неавторизованных клиентов
- ✅ TLS fingerprint mimicry

#### rstun: Standard QUIC Auth
```rust
// Password-based login после handshake
quic_send.write_all(&TunnelMessage::ReqLogin {
    password: hash(password),
}).await?;

let response = quic_recv.read().await?;
if response != TunnelMessage::ResOk {
    bail!("Login failed");
}
```

**Особенности:**
- Проще, но менее stealth
- Нет obfuscation

---

### 2.4 Error Handling & Timeouts

#### tinc-vless-reality
```c
// Простые таймауты
quiche_config_set_max_idle_timeout(config, 30000); // 30s

// Нет retry logic
if (quic_conn_send(qconn) < 0) {
    logger(LOG_ERR, "Failed to send");
    return false;
}

// Timeout handler (periodic)
static void quic_timeout_handler(void *data) {
    for (qconn in connections) {
        quiche_conn_on_timeout(qconn->conn);
        quic_conn_send(qconn); // Flush pending packets
    }
    timeout_set(&quic_timer, &tv); // Reschedule
}
```

**Проблемы:**
- ❌ Нет exponential backoff при ошибках
- ❌ Нет keep-alive (только passive timeout)
- ❌ Зависшие connections не удаляются автоматически

#### rstun
```rust
// Exponential backoff
retry_if(ExponentialBuilder::default()
    .with_max_delay(Duration::from_secs(10))
    .with_jitter()
).when(|_| !self.should_quit());

// Keep-alive
if idle_timeout_ms > 0 {
    let keep_alive = Duration::from_millis(idle_timeout_ms * 2 / 3);
    transport.keep_alive_interval(Some(keep_alive));
}

// Graceful shutdown
async fn close(&self) {
    self.conn.close(0u32.into(), b"shutdown");
    self.conn.wait_idle().await;
}
```

**Преимущества:**
- ✅ Автоматический retry с jitter
- ✅ Proactive keep-alive
- ✅ Graceful close

---

## 3. Производительность

### 3.1 Congestion Control

| Параметр | tinc-vless-reality | rstun |
|----------|-------------------|-------|
| **Алгоритм** | CUBIC (дефолт quiche) | BBR |
| **Initial CWND** | Дефолт (~10 packets) | Дефолт |
| **RTT tracking** | quiche встроенный | quinn/rustls встроенный |

**Рекомендация:** tinc стоит добавить опцию BBR для лучшей throughput на высоких latency.

### 3.2 Memory Management

**tinc-vless-reality:**
```c
// Статический буфер для packet buffering
#define MAX_BUFFERED_PACKETS 100
buffered_packet_t *send_buf_head; // Linked list

// Риск: OOM при большом количестве буферизованных пакетов
```

**rstun:**
```rust
// Динамическое управление через tokio channels
let (tx, rx) = tokio::sync::mpsc::channel(1024);

// Automatic backpressure
```

---

## 4. Уникальные фичи

### 4.1 tinc-vless-reality только

1. **Reality Protocol** (SNI extraction, fallback)
2. **Browser Fingerprinting** (ALPN, cipher mimicry)
3. **Connection ID demultiplexing** (для shared UDP socket)
4. **VPN-specific optimizations:**
   - Packet buffering во время handshake
   - Stream 0 для metadata (ID/ACK)
   - Hybrid UDP/QUIC mode

### 4.2 rstun только

1. **Connection Migration** (hop между UDP портами)
2. **Exponential Backoff Retry**
3. **Proactive Keep-Alive**
4. **Session Cleanup Task**
5. **Dynamic Config Reload** (TLS cert без перезапуска)
6. **Multiple Tunnel Modes** (inbound/outbound TCP/UDP)

---

## 5. Что нужно добавить в tinc

### 🔴 **Критичные улучшения**

#### 5.1 Connection Migration
```c
// В quic_transport.c
typedef struct {
    bool migration_enabled;
    uint32_t hop_interval_ms;  // 0 = disabled
    struct timeval last_migration;
} quic_migration_config_t;

static void quic_migration_task(void *data) {
    if (!quic_manager->migration_enabled) return;

    for (qconn in connections) {
        // Rebind socket на новый порт
        int new_fd = create_udp_socket(random_port());

        // Сохраняем старый fd для draining
        int old_fd = qconn->sock_fd;
        qconn->sock_fd = new_fd;

        // Отправляем PATH_CHALLENGE
        quiche_conn_send(qconn->conn);

        // Закрываем старый после timeout
        schedule_close(old_fd, 60000); // 60s
    }

    timeout_set(&migration_timer, &(struct timeval){hop_interval_ms/1000, ...});
}
```

**Зачем:** Обход UDP throttling у ISP/CDN (важно для длительных VPN сессий).

#### 5.2 Exponential Backoff для Reconnect
```c
// В quic_transport.c
typedef struct {
    uint32_t retry_count;
    uint32_t max_delay_ms;  // 10000 = 10s
    uint32_t current_delay_ms;
    struct timeval next_retry;
} quic_retry_state_t;

static bool quic_reconnect_with_backoff(quic_conn_t *qconn) {
    if (qconn->retry.retry_count == 0) {
        qconn->retry.current_delay_ms = 100; // Start at 100ms
    } else {
        // Exponential: delay *= 2, max 10s
        qconn->retry.current_delay_ms = MIN(
            qconn->retry.current_delay_ms * 2,
            qconn->retry.max_delay_ms
        );
        // Add jitter ±20%
        qconn->retry.current_delay_ms += (rand() % (qconn->retry.current_delay_ms / 5))
                                          - (qconn->retry.current_delay_ms / 10);
    }

    timeout_set(&qconn->retry_timer, &(struct timeval){
        qconn->retry.current_delay_ms / 1000,
        (qconn->retry.current_delay_ms % 1000) * 1000
    });

    qconn->retry.retry_count++;
    return true;
}
```

**Зачем:** Избежать thundering herd при сбое сервера.

### 🟡 **Важные улучшения**

#### 5.3 Keep-Alive механизм
```c
// В quic_config_new()
if (idle_timeout_ms > 0) {
    uint64_t keep_alive_ms = (idle_timeout_ms * 2) / 3;
    quiche_config_set_max_idle_timeout(config, idle_timeout_ms);
    // NOTE: quiche не имеет явного keep_alive API
    // Нужно отправлять PING frames вручную
}

// Periodic task
static void quic_keepalive_task(void *data) {
    for (qconn in connections) {
        if (quic_conn_is_established(qconn)) {
            // Отправить PING если idle > keep_alive_interval
            if (now - qconn->last_activity > keep_alive_ms) {
                uint8_t ping_frame[1] = {0x01}; // PING frame type
                quiche_conn_send_ack_eliciting(qconn->conn);
            }
        }
    }
}
```

**Зачем:** Предотвратить idle timeout на NAT/firewall.

#### 5.4 Session Cleanup Task
```c
static void quic_cleanup_task(void *data) {
    for (qconn in connections) {
        if (quiche_conn_is_closed(qconn->conn) ||
            quiche_conn_is_draining(qconn->conn)) {

            logger(LOG_INFO, "Cleaning up dead connection for %s",
                   qconn->node ? qconn->node->name : "unknown");

            // Unregister CIDs
            unregister_connection_id(qconn->scid, qconn->scid_len);
            unregister_connection_id(qconn->dcid, qconn->dcid_len);

            // Remove from tree
            splay_delete(quic_manager->connections, qconn);

            // Free resources
            quic_conn_free(qconn);
        }
    }

    // Reschedule every 2 seconds
    timeout_set(&cleanup_timer, &(struct timeval){2, 0});
}
```

**Зачем:** Избежать memory leak при обрывах соединений.

### 🟢 **Nice-to-have**

#### 5.5 Dynamic Config Reload
```c
static void quic_reload_config_task(void *data) {
    char cert_path[PATH_MAX], key_path[PATH_MAX];
    snprintf(cert_path, sizeof(cert_path), "%s/quic-cert.pem", confbase);
    snprintf(key_path, sizeof(key_path), "%s/quic-key.pem", confbase);

    // Check if cert changed (via mtime)
    struct stat st;
    if (stat(cert_path, &st) == 0 && st.st_mtime > last_cert_load) {
        logger(LOG_INFO, "Reloading QUIC TLS certificate");

        // Create new server config
        quic_config_t *new_config = quic_config_new(true);
        if (quic_config_set_tls_cert(new_config, cert_path, key_path)) {
            // Swap configs (new connections use new cert)
            quic_config_t *old = quic_manager->server_config;
            quic_manager->server_config = new_config;

            // Keep old config alive for draining connections
            schedule_free(old, 300000); // 5min

            last_cert_load = st.st_mtime;
        } else {
            quic_config_free(new_config);
        }
    }

    // Reschedule every 24 hours
    timeout_set(&reload_timer, &(struct timeval){86400, 0});
}
```

**Зачем:** Hot reload для Let's Encrypt cert rotation.

---

## 6. Конфигурация

### 6.1 Добавить в tinc.conf

```ini
# ========== QUIC Advanced Settings ==========

# Connection Migration (обход UDP throttling)
QuicMigrationEnabled = yes
QuicHopIntervalMs = 300000      # 5 min (0 = disabled)

# Retry & Timeouts
QuicRetryMaxDelay = 10000       # 10s exponential backoff max
QuicIdleTimeout = 30000         # 30s
QuicKeepAliveInterval = 20000   # 20s (2/3 от idle timeout)

# Stream Management
QuicMaxStreamWindow = 1048576           # 1MB per stream
QuicMaxConnectionWindow = 2097152       # 2MB total
QuicMaxConcurrentStreams = 100

# Congestion Control
QuicCongestionControl = bbr     # cubic, reno, bbr

# Session Cleanup
QuicCleanupInterval = 2000      # 2s

# Config Reload
QuicCertReloadInterval = 86400  # 24h
```

---

## 7. Тестирование улучшений

### 7.1 Test Plan

```bash
# 1. Connection Migration
# Запустить VPN сессию, проверить смену портов
tcpdump -i any 'udp and host 10.0.0.2' -n
# Должны видеть смену source port каждые 5 минут

# 2. Retry Logic
# Убить сервер, проверить exponential backoff
docker stop tinc-node2
docker logs -f tinc-node1 | grep "Retry attempt"
# Должны видеть: 100ms, 200ms, 400ms, 800ms, 1600ms, ...

# 3. Keep-Alive
# Проверить, что idle connections не умирают
iptables -A INPUT -p udp --dport 443 -j DROP
sleep 25
iptables -D INPUT -p udp --dport 443 -j DROP
ping 10.0.0.2 # Должен сработать без reconnect

# 4. Session Cleanup
# Создать 10 connections, убить 5, проверить cleanup
for i in {1..10}; do docker exec node1 ping -c 1 10.0.0.$i & done
docker exec node1 cat /proc/$(pidof tincd)/status | grep VmRSS
# Memory не должна расти после cleanup
```

---

## 8. Приоритеты реализации

### Неделя 1: Критичные фичи
1. ✅ Connection Migration (3 дня)
2. ✅ Exponential Backoff Retry (2 дня)

**Цель:** Стабильность при сбоях и throttling.

### Неделя 2: Важные фичи
1. ✅ Keep-Alive (2 дня)
2. ✅ Session Cleanup (1 день)
3. ✅ Stream Window Config (1 день)

**Цель:** Production-ready reliability.

### Неделя 3: Nice-to-have
1. ✅ Dynamic Config Reload (2 дня)
2. ✅ BBR Congestion Control (1 день)
3. ✅ Metrics & Monitoring (2 дня)

**Цель:** Ops-friendly features.

---

## 9. Заключение

### Текущее состояние tinc-vless-reality

**Сильные стороны:**
- ✅ Уникальный Reality protocol для stealth
- ✅ Browser fingerprinting
- ✅ Hybrid UDP/QUIC mode

**Слабости (по сравнению с rstun):**
- ❌ Нет connection migration → throttling issues
- ❌ Нет retry backoff → thundering herd
- ❌ Нет keep-alive → idle timeouts
- ❌ Нет cleanup → memory leaks

### Рекомендации

1. **Добавить в первую очередь:**
   - Connection Migration (обход QoS)
   - Exponential Backoff (стабильность)
   - Session Cleanup (память)

2. **Можно отложить:**
   - Dynamic Config Reload (не критично)
   - BBR (CUBIC работает нормально)

3. **Сохранить уникальные фичи:**
   - Reality protocol (**не трогать!**)
   - Fingerprinting (**core feature**)

---

## Ссылки

- tinc-vless-reality: `/home/user/tinc-vless-reality`
- rstun: https://github.com/neevek/rstun
- quiche: https://github.com/cloudflare/quiche
- quinn: https://github.com/quinn-rs/quinn
- RFC 9000 (QUIC): https://datatracker.ietf.org/doc/html/rfc9000

---

**Автор:** Claude
**Дата:** 2025-11-11
