import 'dart:async';

import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:google_sign_in/google_sign_in.dart';

import '../utils/logger.dart';

/// Обёртка над [FirebaseAuth] и [GoogleSignIn].
///
/// Зачем нужна обёртка, а не прямые вызовы?
/// 1. Если Firebase заменится другим сервисом — меняем только этот файл.
/// 2. Логирование и обработка ошибок в одном месте.
/// 3. Тестирование — проще подменить один сервис, чем весь Firebase.


class FirebaseAuthService {
  final FirebaseAuth _auth = FirebaseAuth.instance;
  final GoogleSignIn _googleSignIn = GoogleSignIn.instance;

  bool _initialized = false;

  User? get currentUser => _auth.currentUser;

  Stream<User?> get authStateChanges => _auth.authStateChanges();

  Future<void> initialize({required String serverClientId}) async {
    if (_initialized) return;
    await _googleSignIn.initialize(serverClientId: serverClientId);
    _initialized = true;
  }

  /// Запускает флоу входа через Google (v7 event-based API).
  Future<UserCredential?> signInWithGoogle() async {
    final serverClientId = dotenv.env['SERVER_CLIENT_ID'];
    if(serverClientId == null){
      throw Exception('Server client is empty!');
    }
    await initialize(serverClientId: serverClientId);
    final completer = Completer<UserCredential?>();

    late final StreamSubscription<GoogleSignInAuthenticationEvent> subscription;

    subscription = _googleSignIn.authenticationEvents.listen(
      (event) async {
        try {
          switch (event) {
            case GoogleSignInAuthenticationEventSignIn():
              final idToken = event.user.authentication.idToken;
              final credential = GoogleAuthProvider.credential(
                idToken: idToken,
              );
              final userCredential =
                  await _auth.signInWithCredential(credential);

              AppLogger.info(
                'Google Sign-In: успешный вход — ${userCredential.user?.email}',
              );
              if (!completer.isCompleted) {
                completer.complete(userCredential);
              }

            case GoogleSignInAuthenticationEventSignOut():
              // Пользователь вышел — возвращаем null
              if (!completer.isCompleted) {
                completer.complete(null);
              }
          }
        } catch (error, stackTrace) {
          AppLogger.error(
            'Google Sign-In: ошибка при обработке',
            error: error,
            stackTrace: stackTrace,
          );
          if (!completer.isCompleted) {
            completer.completeError(error);
          }
        } finally {
          await subscription.cancel();
        }
      },
      onError: (Object error) {
        // Ошибки стрима (включая GoogleSignInException)
        AppLogger.error('Google Sign-In: ошибка', error: error);
        if (!completer.isCompleted) {
          completer.completeError(error);
        }
        subscription.cancel();
      },
    );

    _googleSignIn.authenticate();

    return completer.future;
  }

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
