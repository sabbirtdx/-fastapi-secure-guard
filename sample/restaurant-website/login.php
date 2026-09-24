<?php
require_once __DIR__ . '/config/database.php';
require_once __DIR__ . '/includes/auth.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email'];
    $password = $_POST['password'];
    if (sfg_check_login($db, $email, $password)) {
        session_start();
        $_SESSION['user'] = $email;
        header('Location: /admin/');
        exit;
    }
    $error = 'Invalid credentials';
}
?>
<html><body>
<form method="post"><input name="email"><input name="password" type="password"><button>Login</button></form>
</body></html>
