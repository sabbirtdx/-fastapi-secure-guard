<?php
require_once __DIR__ . '/../config/database.php';
require_admin();
$res = $db->query("SELECT * FROM reservations ORDER BY created_at DESC LIMIT 50");
?>
<html><body><h1>Reservations</h1>
<?php while ($r = $res->fetch_assoc()): ?>
<p><?= htmlspecialchars($r['name']) ?> - <?= $r['table'] ?></p>
<?php endwhile; ?>
</body></html>
