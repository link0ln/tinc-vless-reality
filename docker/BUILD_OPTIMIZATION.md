# Docker Build Optimization Guide

## Проблемы старой сборки

### Перед оптимизацией:
- **Размер образа**: ~6GB на ноду × 3 ноды = ~18GB
- **Время сборки**: ~20-30 минут каждый раз
- **3 отдельных образа** для node1, node2, node3 (одинаковые!)
- **Накопление старых образов** - занимает сотни GB
- **Нет автоматизации** очистки

### Причины:
1. Финальный образ содержал все build dependencies (gcc, make, autoconf, etc.)
2. Финальный образ содержал весь исходный код в /build/
3. Docker Compose собирал 3 идентичных образа отдельно
4. Нет кэширования слоев между сборками
5. Нет .dockerignore - копировались лишние файлы

## Решение: Оптимизированная сборка

### Изменения:

#### 1. **3-stage Dockerfile** (`Dockerfile.optimized`)
```
Stage 1 (quiche-builder): Сборка quiche library
  ↓
Stage 2 (tinc-builder):   Сборка tinc с зависимостями
  ↓
Stage 3 (runtime):         Минимальный runtime (только бинарники)
```

**Что включено в финальный образ:**
- Только скомпилированные бинарники (tincd, tinc)
- Только runtime библиотеки (без build tools!)
- Только необходимые утилиты (ping, iproute2)

**Что исключено:**
- ❌ build-essential, gcc, make, autoconf
- ❌ Исходный код в /build/
- ❌ Rust toolchain
- ❌ Промежуточные .o файлы

#### 2. **Один образ для всех нод** (`docker-compose.optimized.yml`)
```yaml
image: tinc-vless:latest  # Все ноды используют ОДИН образ
```

#### 3. **Makefile для автоматизации**
- `make build` - быстрая сборка с кэшем
- `make clean-images` - автоматическая очистка старых образов
- `make test-ping` - тестирование связности

#### 4. **.dockerignore**
Исключает из контекста:
- Логи и временные файлы
- Git репозиторий
- Старые build артефакты
- Конфиги нод (docker/node1/, node2/, node3/)

## Использование

### Быстрый старт:
```bash
cd /opt/gitrepo/vpn-experiments/tinc-vless/docker

# Сборка (с кэшем, быстро)
make build

# Запуск
make up

# Проверка связности
make test-ping

# Очистка старых образов
make clean-images
```

### Все команды:
```bash
make help           # Показать все команды

# Сборка
make build          # Оптимизированная сборка (рекомендуется)
make build-no-cache # Полная пересборка без кэша
make build-dev      # Старый Dockerfile (для отладки)

# Управление контейнерами
make up             # Запустить
make down           # Остановить
make restart        # Перезапустить
make logs           # Логи

# Очистка
make clean          # Остановить контейнеры
make clean-images   # Удалить старые образы (безопасно)
make clean-all      # ПОЛНАЯ очистка (осторожно!)
make prune          # Docker system prune

# Тестирование
make test-ping      # Проверить связность
make shell-node1    # Зайти в node1
make images-size    # Размер образов
make disk-usage     # Использование диска
```

## Ожидаемые результаты

### Размер образа:
- **Было**: ~6GB
- **Стало**: ~200-300MB (в 20-30 раз меньше!)

### Время сборки:
- **Первая сборка**: ~20-30 минут (как раньше)
- **Повторная сборка** (только tinc изменился): ~2-3 минуты
- **Запуск контейнеров**: мгновенно (1 образ вместо 3)

### Использование диска:
- **Было**: 3 образа × 6GB = 18GB + старые версии = 50-100GB
- **Стало**: 1 образ × 300MB = 300MB + автоочистка

## Проверка оптимизации

### До:
```bash
$ docker images | grep docker-node
docker-node1  latest  abc123  6.2GB
docker-node2  latest  def456  6.1GB
docker-node3  latest  ghi789  6.3GB
```

### После:
```bash
$ docker images tinc-vless
tinc-vless    latest  xyz123  287MB
```

### Проверить размер:
```bash
make images-size
make disk-usage
```

## Миграция со старой сборки

```bash
# 1. Остановить старые контейнеры
docker-compose down

# 2. Очистить старые образы
make clean-images

# 3. Собрать новый образ
make build

# 4. Запустить
make up

# 5. Проверить
make test-ping
```

## Автоматическая очистка

### Настроить cron для еженедельной очистки:
```bash
# Добавить в crontab
0 3 * * 0 cd /opt/gitrepo/vpn-experiments/tinc-vless/docker && make prune
```

## Troubleshooting

### Ошибка "libquiche.so not found"
Убедитесь, что используете `Dockerfile.optimized` и `target: runtime`

### Образ всё ещё большой
```bash
# Проверить, какой stage используется
docker history tinc-vless:latest | head -20

# Должен быть: "FROM ubuntu:22.04 AS runtime"
```

### Старые образы накапливаются
```bash
# Автоматическая очистка
make clean-images

# Ручная очистка
docker image prune -f
docker images | grep '<none>' | awk '{print $3}' | xargs docker rmi
```

## Производительность

### BuildKit кэширование
Docker автоматически кэширует слои:
- **quiche-builder**: пересобирается только при изменении deps/quiche/
- **tinc-builder**: пересобирается только при изменении src/
- **runtime**: пересобирается только при изменении бинарников

### Параллельная сборка
BuildKit автоматически распараллеливает stage'ы:
```
quiche-builder (Stage 1) → [кэш через 5 сек]
     ↓
tinc-builder (Stage 2)   → [компиляция 2-3 мин]
     ↓
runtime (Stage 3)        → [копирование 10 сек]
```

## Итого

### Выгоды:
✅ Размер образа уменьшен в 20-30 раз
✅ Повторная сборка в 10 раз быстрее
✅ Один образ вместо трёх
✅ Автоматическая очистка
✅ Простые команды (make)
✅ Экономия десятков GB места на диске

### Важно:
- Используйте `make build` для разработки
- Периодически запускайте `make clean-images`
- Для production собирайте с `make build-no-cache`
