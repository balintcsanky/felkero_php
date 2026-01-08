<?php
final class Csrf {
  public static function startSession(): void {
    if (session_status() !== PHP_SESSION_ACTIVE) {
      session_start([
        'cookie_httponly' => true,
        'cookie_samesite' => 'Lax',
        // 'cookie_secure' => true, // élesben HTTPS-nél ON
      ]);
    }
  }

  public static function token(): string {
    self::startSession();
    if (empty($_SESSION['csrf'])) {
      $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
  }

  public static function verify(string $token): bool {
    self::startSession();
    return hash_equals($_SESSION['csrf'] ?? '', $token);
  }
}
