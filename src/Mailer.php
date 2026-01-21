<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

final class Mailer {

  private static function baseMailer(): PHPMailer {
    $mail = new PHPMailer(true);
    $mail->isSMTP();
    $mail->Host = getenv('MAIL_HOST') ?: 'mailhog';
    $mail->Port = (int)(getenv('MAIL_PORT') ?: 1025);

    $mail->SMTPAuth = false;
    $mail->SMTPSecure = false;
    $mail->SMTPAutoTLS = false;

    $from = getenv('MAIL_FROM') ?: 'portal@ceg.hu';
    $mail->setFrom($from, 'Felkero Portal');
    $mail->isHTML(true);

    return $mail;
  }

  public static function sendVerifyLink(string $toEmail, string $verifyUrl): void {
    $mail = self::baseMailer();
    $mail->addAddress($toEmail);

    $mail->Subject = 'Email megerosites - Felkero Portal';
    $mail->Body = 'Kattints a megerositeshez: <a href="'.htmlspecialchars($verifyUrl).'">Megerősítés</a>';
    $mail->AltBody = "Megerősítés: $verifyUrl";

    $mail->send();
  }

  public static function sendOtpCode(string $toEmail, string $subject, string $code): void {
    $mail = self::baseMailer();
    $mail->addAddress($toEmail);

    $safeCode = htmlspecialchars($code, ENT_QUOTES, 'UTF-8');

    $mail->Subject = $subject;
    $mail->Body = "<p>Az egyszer használatos kódod: <strong>{$safeCode}</strong></p>"
                . "<p>A kód 10 percig érvényes.</p>";
    $mail->AltBody = "Egyszer használatos kód: {$code}\nÉrvényesség: 10 perc.";

    $mail->send();
  }
}
