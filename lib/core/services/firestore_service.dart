import 'package:cloud_firestore/cloud_firestore.dart';

import '../utils/logger.dart';
import 'collection_names.dart';

/// Обёртка над [FirebaseFirestore].
///
/// Предоставляет удобные методы для работы с документами
/// в Firestore. Сейчас работает только с коллекцией `users`,
/// но можно расширить для любых коллекций.
class FirestoreService {
  /// Экземпляр Firestore.
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;

  // ── Пользователи ─────────────────────────────────────────────

  /// Сохранить (или обновить) данные пользователя в Firestore.
  ///
  /// [uid] — уникальный идентификатор пользователя (из FirebaseAuth).
  /// [data] — словарь с полями, которые нужно сохранить.
  ///
  /// `merge: true` — если документ уже существует, обновляются
  /// только переданные поля (остальные не трогаются).
  Future<void> saveUser(String uid, Map<String, dynamic> data) async {
    try {
      await _firestore
          .collection(CollectionNames.users)
          .doc(uid)
          .set(data, SetOptions(merge: true));

      AppLogger.info('Firestore: пользователь $uid сохранён');
    } catch (error, stackTrace) {
      AppLogger.error(
        'Firestore: ошибка сохранения пользователя $uid',
        error: error,
        stackTrace: stackTrace,
      );
      rethrow;
    }
  }

  /// Получить данные пользователя из Firestore.
  ///
  /// Возвращает `Map<String, dynamic>?` — `null`, если
  /// документа не существует.
  Future<Map<String, dynamic>?> getUser(String uid) async {
    try {
      final DocumentSnapshot<Map<String, dynamic>> doc = await _firestore
          .collection(CollectionNames.users)
          .doc(uid)
          .get();

      if (!doc.exists) {
        AppLogger.warning('Firestore: пользователь $uid не найден');
        return null;
      }

      return doc.data();
    } catch (error, stackTrace) {
      AppLogger.error(
        'Firestore: ошибка получения пользователя $uid',
        error: error,
        stackTrace: stackTrace,
      );
      rethrow;
    }
  }
}
