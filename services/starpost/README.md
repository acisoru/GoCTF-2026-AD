# ДОК (`starpost`)

**Категория:** web · **стек:** Flask API + nginx + warehouse-worker + PostgreSQL · **порт:** `8090` (внутри контейнера `80`)

Грузовой маркетплейс орбитального дока: товары, заказы, отзывы, контракты продавцов.

## Запуск

```bash
docker compose up -d --build   # :8090
```

## Уязвимости и эксплоиты

См. [`../../sploits/starpost`](../../sploits/starpost) и чекер [`../../checkers/starpost`](../../checkers/starpost).
