# data/repositories/

Репозитории — координируют работу нескольких сервисов / источников данных.

| Файл | Описание |
|------|----------|
| `auth_repository.dart` | Координирует FirebaseAuth + Firestore для авторизации |

## Паттерн «Синглтон»

Репозитории реализованы как синглтоны:

```dart
class AuthRepository {
  AuthRepository._();                          // приватный конструктор
  static final AuthRepository instance = AuthRepository._(); // единственный экземпляр
}
```

Доступ: `AuthRepository.instance.signInWithGoogle()`.

## Зачем репозиторий, если есть сервисы?

**Сервис** знает только про свой источник (Auth **или** Firestore).
**Репозиторий** координирует: вошёл через Google → сохранил в Firestore → вернул модель.
