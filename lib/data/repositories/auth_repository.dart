import 'package:firebase_auth/firebase_auth.dart';

import '../../core/services/firebase_auth_service.dart';
import '../../core/services/firestore_service.dart';
import '../../core/utils/logger.dart';
import '../models/user_model.dart';

/// Репозиторий авторизации — координирует работу сервисов.
///
/// Это **синглтон**: один экземпляр на всё приложение.
/// Доступ через [AuthRepository.instance].
///
/// Зачем репозиторий, если есть сервисы?
/// Сервис знает только про свой источник (Auth или Firestore).
/// Репозиторий **координирует** несколько сервисов:
///   1. Входит через Google (FirebaseAuthService).
///   2. Сохраняет профиль в Firestore (FirestoreService).
///   3. Возвращает единую модель [UserModel].
class AuthRepository {
  // ── Синглтон ─────────────────────────────────────────────────

  /// Приватный конструктор — нельзя создать снаружи.
  AuthRepository._();

  /// Единственный экземпляр репозитория.
  static final AuthRepository instance = AuthRepository._();

  // ── Сервисы ──────────────────────────────────────────────────

  final FirebaseAuthService _authService = FirebaseAuthService();
  final FirestoreService _firestoreService = FirestoreService();

  // ── Геттеры ──────────────────────────────────────────────────

  /// Текущий пользователь как [UserModel].
  /// Если не авторизован — возвращает [UserModel.empty].
  UserModel get currentUser {
    final User? firebaseUser = _authService.currentUser;
    if (firebaseUser == null) return UserModel.empty;
    return UserModel.fromFirebaseUser(firebaseUser);
  }

  /// Авторизован ли пользователь?
  bool get isLoggedIn => _authService.currentUser != null;

  /// Стрим изменений авторизации.
  ///
  /// Каждый раз, когда пользователь входит/выходит,
  /// стрим отправляет новый [UserModel].
  Stream<UserModel> get authStateChanges {
    return _authService.authStateChanges.map((User? firebaseUser) {
      if (firebaseUser == null) return UserModel.empty;
      return UserModel.fromFirebaseUser(firebaseUser);
    });
  }

  // ── Действия ─────────────────────────────────────────────────

  /// Вход через Google + сохранение профиля в Firestore.
  Future<UserModel> signInWithGoogle() async {
    try {
      // 1. Вход через Google.
      final UserCredential? credential =
          await _authService.signInWithGoogle();

      // Пользователь отменил вход.
      if (credential?.user == null) return UserModel.empty;

      // 2. Формируем модель.
      final UserModel user = UserModel.fromFirebaseUser(credential!.user!);

      // 3. Сохраняем/обновляем профиль в Firestore.
      await _firestoreService.saveUser(user.uid, user.toJson());

      AppLogger.info('AuthRepository: вход выполнен — ${user.email}');
      return user;
    } catch (error, stackTrace) {
      AppLogger.error(
        'AuthRepository: ошибка входа через Google',
        error: error,
        stackTrace: stackTrace,
      );
      rethrow;
    }
  }

  /// Выход из аккаунта.
  Future<void> signOut() async {
    try {
      await _authService.signOut();
      AppLogger.info('AuthRepository: пользователь вышел');
    } catch (error, stackTrace) {
      AppLogger.error(
        'AuthRepository: ошибка выхода',
        error: error,
        stackTrace: stackTrace,
      );
      rethrow;
    }
  }
}
