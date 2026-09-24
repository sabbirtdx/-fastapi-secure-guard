<?php
function sfg_check_login($db, $email, $password) {
    $stmt = $db->prepare("SELECT password_hash FROM staff WHERE email = ?");
    $stmt->bind_param('s', $email);
    $stmt->execute();
    $row = $stmt->fetch_assoc();
    return $row && password_verify($password, $row['password_hash']);
}
function require_admin() {
    session_start();
    if (empty($_SESSION['user'])) { http_response_code(403); exit('Forbidden'); }
}
