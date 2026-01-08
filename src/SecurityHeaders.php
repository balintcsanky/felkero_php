<?php
final class SecurityHeaders {
  public static function applyNoIndex(): void {
    header('X-Robots-Tag: noindex, nofollow', true);
    header('X-Frame-Options: DENY', true);
    header('X-Content-Type-Options: nosniff', true);
    header('Referrer-Policy: no-referrer', true);
  }
}