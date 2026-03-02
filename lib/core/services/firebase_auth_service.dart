import 'package:firebase_auth/firebase_auth.dart';
import 'package:google_sign_in/google_sign_in.dart';

import '../utils/logger.dart';

/// Обёртка над [FirebaseAuth] и [GoogleSignIn].
///
/// Зачем нужна обёртка, а не прямые вызовы?
/// 1. Если Firebase заменится другим сервисом — меняем только этот файл.
/// 2. Логирование и обработка ошибок в одном месте.
/// 3. Тестирование — проще подменить один сервис, чем весь Firebase.
class FirebaseAuthService {
  /// Экземпляр FirebaseAuth (работа с авторизацией).
  final FirebaseAuth _auth = FirebaseAuth.instance;

  /// Экземпляр GoogleSignIn (синглтон в v7).
  final GoogleSignIn _googleSignIn = GoogleSignIn.instance;

  // ── Текущий пользователь ─────────────────────────────────────

  /// Текущий авторизованный пользователь (или `null`).
  User? get currentUser => _auth.currentUser;

  /// Стрим изменений состояния авторизации.
  ///
  /// Каждый раз, когда пользователь входит или выходит,
  /// стрим отправляет новый [User?].
  Stream<User?> get authStateChanges => _auth.authStateChanges();

  // ── Вход через Google ────────────────────────────────────────

  /// Запускает флоу входа через Google.
  ///
  /// Возвращает [UserCredential] при успехе или `null`,
  /// если пользователь отменил выбор аккаунта.
  Future<UserCredential?> signInWithGoogle() async {
    try {
      // 1. Открываем окно выбора Google-аккаунта (v7 API).
      final GoogleSignInAccount googleUser =
          await _googleSignIn.authenticate();

      // 2. Получаем idToken из аккаунта.
      final GoogleSignInAuthentication googleAuth =
          googleUser.authentication;

      // 3. Создаём credential для Firebase.
      final OAuthCredential credential = GoogleAuthProvider.credential(
        idToken: googleAuth.idToken,
      );

      // 4. Входим в Firebase с Google credential.
      final UserCredential userCredential =
          await _auth.signInWithCredential(credential);

      AppLogger.info(
        'Google Sign-In: успешный вход — ${userCredential.user?.email}',
      );
      return userCredential;
    } catch (error, stackTrace) {
      AppLogger.error(
        'Google Sign-In: ошибка входа',
        error: error,
        stackTrace: stackTrace,
      );
      rethrow;
    }
  }

  // ── Выход ────────────────────────────────────────────────────

  /// Выход из Firebase и Google.
  Future<void> signOut() async {
    try {
      await Future.wait([
        _auth.signOut(),
        _googleSignIn.signOut(),
      ]);
      AppLogger.info('Sign Out: пользователь вышел');
    } catch (error, stackTrace) {
      AppLogger.error(
        'Sign Out: ошибка при выходе',
        error: error,
        stackTrace: stackTrace,
      );
      rethrow;
    }
  }
}
