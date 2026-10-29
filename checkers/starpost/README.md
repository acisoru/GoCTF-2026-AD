# ДОК · чекер

**Контракт:** Skipper AD (на базе `checklib`). **Порт сервиса:** `8090`.

Три сценария соответствуют трём уязвимостям сервиса: `1` — cargo, `2` — review, `3` — contract (`scenarios/`).

```bash
pip install -r requirements.txt
python3 checker.py check <host>
python3 checker.py put <host> <flag_id> <flag> <vuln>
python3 checker.py get <host> <flag_id> <flag> <vuln>
```

## Зависимости

См. `requirements.txt` (`checklib`, `requests`).
