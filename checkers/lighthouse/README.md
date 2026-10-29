# МАЯК · чекер

**Контракт:** Skipper AD. **Порт сервиса:** `8085` (переопределяется через `LIGHTHOUSE_PORT`).

`feal.py` должен лежать рядом с `checker.py`.

```bash
python3 checker.py check <host>
python3 checker.py put <host> <flag_id> <flag> <vuln>
python3 checker.py get <host> <private_flag_id> <flag> <vuln>
```

Публичные PUT-данные — UUID очереди и время её создания; приватный flag ID — `queue_uuid:read_key`.

## Зависимости

Только стандартная библиотека Python 3 (+ `feal.py` рядом).
