# АСТРОЛЯБИЯ · чекер

**Контракт:** Skipper AD (библиотека `github.com/skipper-ad/junge-checkers`). **Порт сервиса:** `8086`
(переопределяется через `ORBIT_SERVICE_PORT` или как часть `<host>`, например `127.0.0.1:18080`).

```text
checker info
checker check <host>
checker put <host> <flag_id> <flag> <vuln>
checker get <host> <flag_id> <flag> <vuln>
```

Сборка и тесты:

```bash
go test ./...
go build -o checker .
```

Поддерживаются шесть vuln/place (разбор — в [`../../sploits/orbital_navigation`](../../sploits/orbital_navigation)).

Публичный `flag_id` — JSON с номером place и публичным ID объекта. Токен владельца хранится
внутри authenticated encryption, ключом для которой служит сам флаг: attack data содержит нужные
для эксплуатации ID, но не раскрывает штатные учётные данные.

## Зависимости

Go toolchain; библиотека `junge-checkers` (резолвится через `go.mod`).
