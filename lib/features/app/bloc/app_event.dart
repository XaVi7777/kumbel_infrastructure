import 'package:equatable/equatable.dart';

import '../../../data/models/user_model.dart';

/// События (events) для [AppBloc].
///
/// Event — это «что произошло». BLoC реагирует на события
/// и меняет состояние (state).
abstract class AppEvent extends Equatable {
  const AppEvent();

  @override
  List<Object?> get props => [];
}

/// Изменился статус авторизации (пришёл новый User из стрима).
///
/// Отправляется автоматически при подписке на `authStateChanges`.
class AppAuthStateChanged extends AppEvent {
  /// Новый пользователь (или [UserModel.empty] при выходе).
  final UserModel user;

  const AppAuthStateChanged(this.user);

  @override
  List<Object?> get props => [user];
}

/// Пользователь нажал «Выйти».
class AppSignOutRequested extends AppEvent {
  const AppSignOutRequested();
}
