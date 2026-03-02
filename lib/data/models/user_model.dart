import 'package:equatable/equatable.dart';
import 'package:firebase_auth/firebase_auth.dart';

/// Модель пользователя.
///
/// Используется в BLoC-состояниях и для передачи данных
/// между слоями. Расширяет [Equatable], чтобы BLoC мог
/// корректно сравнивать состояния (== работает по полям).
///
/// Три фабричных конструктора:
/// - [fromJson]  — из Map (Firestore).
/// - [toJson]    — в Map (для сохранения в Firestore).
/// - [fromFirebaseUser] — из объекта [User] (FirebaseAuth).
class UserModel extends Equatable {
  /// Уникальный идентификатор (совпадает с uid в FirebaseAuth).
  final String uid;

  /// Отображаемое имя.
  final String displayName;

  /// Email пользователя.
  final String email;

  /// URL аватара (может быть пустой строкой).
  final String photoUrl;

  const UserModel({
    required this.uid,
    required this.displayName,
    required this.email,
    required this.photoUrl,
  });

  /// Пустой пользователь — используется как дефолтное значение
  /// вместо `null` (удобнее проверять `user == UserModel.empty`).
  static const UserModel empty = UserModel(
    uid: '',
    displayName: '',
    email: '',
    photoUrl: '',
  );

  /// Пользователь пустой?
  bool get isEmpty => this == empty;

  /// Пользователь НЕ пустой?
  bool get isNotEmpty => this != empty;

  // ── Фабрики ──────────────────────────────────────────────────

  /// Создать [UserModel] из Map (обычно из Firestore-документа).
  factory UserModel.fromJson(Map<String, dynamic> json) {
    return UserModel(
      uid: json['uid'] as String? ?? '',
      displayName: json['displayName'] as String? ?? '',
      email: json['email'] as String? ?? '',
      photoUrl: json['photoUrl'] as String? ?? '',
    );
  }

  /// Создать [UserModel] из [User] (FirebaseAuth).
  factory UserModel.fromFirebaseUser(User user) {
    return UserModel(
      uid: user.uid,
      displayName: user.displayName ?? '',
      email: user.email ?? '',
      photoUrl: user.photoURL ?? '',
    );
  }

  /// Конвертировать в Map (для сохранения в Firestore).
  Map<String, dynamic> toJson() {
    return {
      'uid': uid,
      'displayName': displayName,
      'email': email,
      'photoUrl': photoUrl,
    };
  }

  /// Equatable — список полей для сравнения.
  @override
  List<Object?> get props => [uid, displayName, email, photoUrl];
}
