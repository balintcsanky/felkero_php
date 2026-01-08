<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

final class Mailer {
  public static function sendVerifyLink(string $toEmail, string $verifyUrl): void {
    $mail = new PHPMailer(true);
    $mail->isSMTP();
    $mail->Host = getenv('MAIL_HOST') ?: 'mailhog';
    $mail->Port = (int)(getenv('MAIL_PORT') ?: 1025);

    $mail->SMTPAuth = false;
    $mail->SMTPSecure = false;
    $mail->SMTPAutoTLS = false;

    $from = getenv('MAIL_FROM') ?: 'portal@ceg.hu';
    $mail->setFrom($from, 'Felkero Portal');
    $mail->addAddress($toEmail);

    $mail->Subject = 'Email megerosites - Felkero Portal';
    $mail->isHTML(true);
    $mail->Body = 'Kattints a megerositeshez: <a href="'.htmlspecialchars($verifyUrl).'">Megerősítés</a>';
    $mail->AltBody = "Megerősítés: $verifyUrl";

    $mail->send();
  }
}
