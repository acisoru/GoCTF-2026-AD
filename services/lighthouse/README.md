# МАЯК (`lighthouse`)

**Категория:** crypto · **стек:** C++ server + JS client · **порт:** `8085` (внутри контейнера `8080`)

Орбитальный маяк с публичными почтовыми ящиками, сообщения в которых шифруются самодельным шифром.

## Запуск

```bash
docker compose up -d --build   # :8085
```

## Уязвимости и эксплоиты

См. [`../../sploits/lighthouse`](../../sploits/lighthouse) и чекер [`../../checkers/lighthouse`](../../checkers/lighthouse).
