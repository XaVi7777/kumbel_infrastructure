import 'package:flutter/material.dart';
import 'package:flutter_svg/flutter_svg.dart';

import '../core/constants/app_constants.dart';
import '../core/constants/asset_paths.dart';
import '../l10n/generated/app_localizations.dart';

/// Кнопка «Войти через Google» — стилизована по гайдлайнам Google.
///
/// Содержит SVG-логотип Google слева и текст справа.
/// Принимает [onPressed] и [isLoading] для блокировки при загрузке.
///
/// Стили текста и цвета берутся из [Theme], а не из захардкоженных
/// значений — так кнопка корректно адаптируется к любой теме.
class GoogleSignInButton extends StatelessWidget {
  /// Колбэк при нажатии.
  final VoidCallback? onPressed;

  /// Показывать ли индикатор загрузки.
  final bool isLoading;

  const GoogleSignInButton({
    super.key,
    required this.onPressed,
    this.isLoading = false,
  });

  @override
  Widget build(BuildContext context) {
    // Получаем локализованные строки через сгенерированный класс.
    final loc = AppLocalizations.of(context);

    // Берём цвета и текстовые стили из темы.
    // Раньше здесь был захардкоженный TextStyle с конкретными значениями —
    // это плохо, потому что при смене темы стили не обновятся.
    // Правильно: брать из Theme.of(context).
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;

    return SizedBox(
      width: AppConstants.googleButtonWidth,
      height: AppConstants.googleButtonHeight,
      child: OutlinedButton(
        onPressed: isLoading ? null : onPressed,
        style: OutlinedButton.styleFrom(
          // Фон — поверхность из темы (белый в светлой теме, тёмный в тёмной).
          backgroundColor: colorScheme.surface,
          // Цвет обводки — из темы (outline или divider-подобный).
          side: BorderSide(color: colorScheme.outline),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
        ),
        child: isLoading
            ? const SizedBox(
                width: 20,
                height: 20,
                child: CircularProgressIndicator(strokeWidth: 2),
              )
            : Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  // Логотип Google (SVG).
                  SvgPicture.asset(
                    AssetPaths.googleLogo,
                    width: AppConstants.googleLogoSize,
                    height: AppConstants.googleLogoSize,
                  ),
                  const SizedBox(width: 12),
                  // Текст кнопки — стиль из темы (bodyLarge подходит
                  // по размеру и весу для текста на кнопке).
                  Text(
                    loc.signInWithGoogle,
                    style: textTheme.bodyLarge?.copyWith(
                      fontWeight: FontWeight.w500,
                      color: colorScheme.onSurface,
                    ),
                  ),
                ],
              ),
      ),
    );
  }
}
