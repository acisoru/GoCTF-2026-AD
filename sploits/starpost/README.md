# ДОК · сплоиты

**Сервис:** `starpost` · **категория:** web · **порт:** `8090`
**Где флаг:** `products.cargo` (vuln 1), приватные отзывы (vuln 2), подпись в PDF-контракте (vuln 3).

> Держать приватно от команд. Это reference-эксплоиты автора.

## Эксплоиты

| Файл | Уязвимость | Запуск |
|------|------------|--------|
| `promo_balance.py` | повторное использование промокода → бесконечный баланс | `python3 promo_balance.py <host> [port] [count]` |
| `spl_otz1.py`      | обход подписи курсора → чтение чужих приватных отзывов | `python3 spl_otz1.py <host> [port]` |
| `contract_lfi.py`  | prefix-match контракта → чужие PDF (+ LFI-бонус) | `python3 contract_lfi.py <host> [port]` |

## 1. Повторный промокод → бесконечный баланс (`promo_balance.py`)

**Суть.** При регистрации `role=buyer` создаётся промокод `SP10-<token>` на `amount=10`, который виден в `GET /api/account`. `POST /api/promo/credit` делает `SELECT amount … / UPDATE users SET balance=balance+amount` и **не помечает код использованным**. Удаляет код только отдельный `POST /api/promo/invalidate`.

**Эксплуатация.** Вызвать `credit` с одним и тем же кодом N раз → `balance = 1000 + N*10`. С этим балансом купить товар (`/api/products/<id>/buy` или `/api/cart/checkout`); флаг лежит в `products.cargo` и отдаётся в `GET /api/orders` при `status=delivered`.

**Патч.** Удалять код при начислении (`DELETE … RETURNING amount`) либо добавить флаг `is_used` и проверять его в `credit`.

## 2. Обход подписи курсора (`spl_otz1.py`)

**Суть.** В `_parse_cursor` при `limit <= 3` проверка HMAC полностью пропускается:

```python
if lim is not None and lim <= 3:
    return _json.loads(_b64d(cur_token.split(".")[0]).decode())  # подпись не проверяется
```

После парсинга нет проверки `seller_id == session["user_id"]`, и `seller_id` из курсора уходит прямо в запрос приватных отзывов.

**Эксплуатация.** Зарегистрироваться как `seller`, подделать курсор `base64url({"seller_id": victim, "is_private": true, "last_id": 1000000000, "v": 2}) + ".deadbeef…"` и вызвать `GET /api/seller/reviews?cursor=<forged>&limit=3`. В `body` приватных отзывов жертвы лежит флаг.

**Патч.** Всегда проверять подпись курсора, либо при `limit <= 3` сверять `seller_id` из курсора с `session["user_id"]`.

## 3. Prefix-match контракта (`contract_lfi.py`)

**Суть.** Имя файла контракта содержит секретный hex-суффикс (`token_hex(8)`), но `/api/contract` матчит только префикс `contract-<digits>` и берёт первый файл по `glob("contract-<uid>-*.pdf")` — суффикс перестаёт защищать.

**Эксплуатация.** Зарегистрироваться как `seller`, узнать `user_id` жертвы (виден как `seller_id` в `GET /api/products`) и запросить `GET /api/contract?file=contract-<victim_id>`. В PDF лежит подпись-флаг. Запрос, не матчащий `contract-\d+`, падает в path-traversal ветку (бонусный LFI: `/etc/passwd`, env-файлы и т.д.).

**Патч.** Сверять полное имя файла с записью в БД (а не префикс) и убрать LFI-ветку с `Path(raw).resolve()`.

## Зависимости

Python 3 + `requests`.
