# data/

Слой данных — модели, источники данных и репозитории.

```
data/
├── local_datasources/   — локальные источники (SharedPreferences, SQLite)
├── models/              — модели данных (UserModel и т.д.)
├── remote_datasources/  — удалённые источники (API, если не Firebase)
└── repositories/        — репозитории (координируют источники данных)
```

## Как это работает

```
UI → BLoC → Repository → Service (Firebase / API)
                ↕
              Model
```

- **Model** — описывает структуру данных (поля, `fromJson`, `toJson`).
- **Repository** — координирует несколько сервисов и возвращает модели.
- **Datasource** — если данные берутся не из Firebase, а из локального хранилища или стороннего API.
