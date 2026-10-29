# ОРАНЖЕРЕЯ · чекер

**Контракт:** Skipper AD. **Порт сервиса:** `8080`.

Три flag place соответствуют трём уязвимостям сервиса (`pwn`, `web`, `misc`).

```bash
python3 checker.py check <host>
python3 checker.py put <host> <flag_id> <flag> <vuln>
python3 checker.py get <host> <flag_id> <flag> <vuln>
```

## Зависимости

Только стандартная библиотека Python 3.
