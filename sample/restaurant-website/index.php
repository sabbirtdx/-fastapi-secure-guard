<?php
// Bistro 42 — public menu page.
require_once __DIR__ . '/config/database.php';
require_once __DIR__ . '/includes/header.php';

$menus = [
    ['name' => 'Wood-fired Risotto', 'price' => '24'],
    ['name' => 'Grilled Sea Bass', 'price' => '32'],
    ['name' => 'Tagine of the Day', 'price' => '27'],
    ['name' => 'Saffron Lamb', 'price' => '39'],
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title><?= site_title() ?></title>
    <link rel="stylesheet" href="assets/css/main.css">
</head>
<body>
    <h1><?= site_title() ?> — Tonight's Menu</h1>
    <p>Welcome to our restaurant. Order at the table or by phone.</p>
    <ul id="menu">
        <?php foreach ($menus as $item): ?>
            <li><?= htmlspecialchars($item['name']) ?> — <span class="price"><?= htmlspecialchars($item['price']) ?></span></li>
        <?php endforeach; ?>
    </ul>
    <footer><?= site_title() ?> — <?= date('Y') ?></footer>
    <script src="assets/js/app.js"></script>
</body>
</html>
