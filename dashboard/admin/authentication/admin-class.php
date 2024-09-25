<?php
require_once __DIR__.'/../../../database/dbconnection.php';
include_once __DIR__.'/../../../config/settings-configuration.php';
require_once __DIR__.'/../../../src/vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

class ADMIN
{
    private $conn;
    private $settings;
    private $smtp_email;
    private $smtp_password;

    public function __construct() 
    {
        $this->settings = new SystemConfig();
        $this->smtp_email = $this->settings->getSmtpEmail();
        $this->smtp_password = $this->settings->getSmtpPassword();

        $database = new Database();
        $this->conn = $database->dbConnection();
    }

    // Function to send OTP to the user
    public function sendOtp($otp, $email) {
        if ($email == NULL) {
            echo "<script>alert('No email found'); window.location.href = '../../../';</script>";
            exit;
        } else {
            $stmt = $this->runQuery("SELECT * FROM user WHERE email = :email");
            $stmt->execute(array(":email" => $email));
            if ($stmt->rowCount() > 0) {
                echo "<script>alert('Email Already Taken. Please Try Again.'); window.location.href = '../../../';</script>";
                exit;
            } else { 
                $_SESSION['OTP'] = $otp;

                // Prepare email message
                $subject = "OTP VERIFICATION";
                $message = "
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset='UTF-8'>
                    <title>OTP Verification</title>
                    <style>
                        body { font-family: Arial, sans-serif; background-color: #f5f5f5; margin:0; padding:0; }
                        .container { max-width: 600px; margin: 0 auto; padding: 30px; background-color: #ffffff; border-radius: 4px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); }
                        h1 { color: #333333; font-size: 24px; margin-bottom: 20px; }
                        p { color: #666666; font-size: 16px; margin-bottom: 10px; }
                    </style>
                </head>
                <body>
                <div class='container'>
                    <h1>OTP Verification</h1>
                    <p>Hello, $email</p>
                    <p>Your OTP is: $otp</p>
                    <p>If you didn't request an OTP, please ignore this email.</p>
                    <p>Thank you!</p>
                </div>
                </body>
                </html>";

                // Send email
                $this->send_email($email, $message, $subject, $this->smtp_email, $this->smtp_password);
                echo "<script>alert('We sent the OTP to $email.'); window.location.href = '../../../verify-otp.php';</script>";
            }
        }
    }

    // Function to verify OTP and add admin
    public function verifyOTP($username, $email, $password, $tokencode, $otp, $csrf_token){
        if($otp == $_SESSION['OTP']){
            unset($_SESSION['OTP']);

            $this->addAdmin($csrf_token, $username, $email, $password);

            $subject = "VERIFICATION SUCCESS";
            $message = "
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset='UTF-8'>
                <title>OTP Verification Success</title>
                <style>
                    body { font-family: Arial, sans-serif; background-color: #f5f5f5; margin:0; padding:0; }
                    .container { max-width: 600px; margin: 0 auto; padding: 30px; background-color: #ffffff; border-radius: 4px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); }
                    h1 { color: #333333; font-size: 24px; margin-bottom: 20px; }
                    p { color: #666666; font-size: 16px; margin-bottom: 10px; }
                </style>
            </head>
            <body>
                <div class='container'>
                    <h1>Welcome</h1>
                    <p>Hello, <strong>$email</strong></p>
                    <p>Welcome to Jaycee</p>
                    <p>If you did not sign up for an account, you can safely ignore this email.</p>
                </div>
            </body>
            </html>";

            $this->send_email($email, $message, $subject, $this->smtp_email, $this->smtp_password);
            echo "<script>alert('Thank you.'); window.location.href = '../../../';</script>";

            unset($_SESSION['not_verify_username']);
            unset($_SESSION['not_verify_email']);
            unset($_SESSION['not_verify_password']);

        } elseif ($otp == NULL) {
            echo "<script>alert('No OTP Found'); window.location.href = '../../../verify-otp.php';</script>";
            exit;
        } else {
            echo "<script>alert('It appears that the OTP is invalid.'); window.location.href = '../../../verify-otp.php';</script>";
            exit;
        }
    }

    // Function to add admin to the database
    public function addAdmin($csrf_token, $username, $email, $password)
    {
        $stmt = $this->runQuery("SELECT * FROM user WHERE email = :email");
        $stmt->execute(array(":email" => $email));

        if ($stmt->rowCount() > 0) {
            echo "<script>alert('Email already exists.'); window.location.href = '../../../';</script>";
            exit;
        }

        // Validate CSRF token
        if (!isset($csrf_token) || !hash_equals($_SESSION['csrf_token'], $csrf_token)) {
            echo "<script>alert('Invalid CSRF Token.'); window.location.href = '../../../';</script>";
            exit;
        }

        unset($_SESSION['csrf_token']);

        // Hash password using a secure method
        $hash_password = password_hash($password, PASSWORD_DEFAULT);

        // Insert admin into the database
        $stmt = $this->runQuery('INSERT INTO user (username, email, password) VALUES (:username, :email, :password)');
        $exec = $stmt->execute(array(
            ":username" => $username,
            ":email" => $email,
            ":password" => $hash_password
        ));

        if ($exec) {
            echo "<script>alert('Admin Added Successfully'); window.location.href = '../../../';</script>";
            exit;
        } else {
            echo "<script>alert('Error Adding Admin.'); window.location.href = '../../../';</script>";
            exit;
        }
    }

    // Function to handle admin sign-in
    public function adminSignin($email, $password, $csrf_token)
    {
        try {
            // CSRF validation
            if (!isset($csrf_token) || !hash_equals($_SESSION['csrf_token'], $csrf_token)) {
                echo "<script>alert('Invalid CSRF Token.'); window.location.href = '../../../';</script>";
                exit;
            }

            unset($_SESSION['csrf_token']);
            
            // Fetch user details
            $stmt = $this->conn->prepare("SELECT * FROM user WHERE email = :email AND status = 'active'");
            $stmt->execute(array(":email" => $email));
            $userRow = $stmt->fetch(PDO::FETCH_ASSOC);

            // Check if user exists and validate password
            if ($stmt->rowCount() == 1) {
                if ($userRow['status'] == 'active') {
                    if (password_verify($password, $userRow['password'])) {
                        $activity = "Successfully signed in.";
                        $user_id = $userRow['id'];
                        $this->logs($activity, $user_id);

                        $_SESSION['adminSession'] = $user_id;
                        echo "<script>alert('Welcome'); window.location.href = '../';</script>";
                        exit;
                    } else {
                        echo "<script>alert('Incorrect Password'); window.location.href = '../../../';</script>";
                        exit;
                    }
                } else {
                    echo "<script>alert('Email is not verified'); window.location.href = '../../../';</script>";
                    exit;
                }
            } else {
                echo "<script>alert('No Account Found'); window.location.href = '../../../';</script>";
                exit;
            }

        } catch (PDOException $ex) {
            echo $ex->getMessage();
        }
    }

    // Function to log admin activities
    public function logs($activity, $user_id)
    {
        $stmt = $this->conn->prepare("INSERT INTO logs (user_id, activity) VALUES (:user_id, :activity)");
        $stmt->execute(array(":user_id" => $user_id, ":activity" => $activity));
    }

    // Function to check if the user is logged in
    public function isUserLoggedIn()
    {
        return isset($_SESSION['adminSession']);
    }

    // Function to redirect to a specific URL
    public function redirect($url)
    {
        header("Location: $url");
    }

    // Helper function to execute SQL queries
    public function runQuery($sql)
    {
        $stmt = $this->conn->prepare($sql);
        return $stmt;
    }

    // Function to send emails using PHPMailer
    public function send_email($email, $message, $subject, $smtp_email, $smtp_password)
    {
        $mail = new PHPMailer(true);
        try {
            $mail->isSMTP();
            $mail->Host = 'smtp.gmail.com';
            $mail->SMTPAuth = true;
            $mail->Username = $smtp_email;
            $mail->Password = $smtp_password;
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            $mail->Port = 587;

            $mail->setFrom($smtp_email, 'Jaycee');
            $mail->addAddress($email);

            $mail->isHTML(true);
            $mail->Subject = $subject;
            $mail->Body = $message;

            $mail->send();
        } catch (Exception $e) {
            echo "Message could not be sent. Mailer Error: {$mail->ErrorInfo}";
        }
    }

    // Admin sign out function
    public function admin_signout()
    {
        unset($_SESSION['adminSession']);
        if (session_destroy()) {
            echo "<script>alert('Successfully logged out.'); window.location.href = '../../../';</script>";
        }
    }
}
?>
