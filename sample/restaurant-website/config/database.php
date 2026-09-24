<?php
// Database bootstrap — contains connection credentials.
define('DB_HOST', getenv('DB_HOST') ?: 'db.internal.bistro42.local');
define('DB_USER', getenv('DB_USER') ?: 'bistro_app');
define('DB_PASS', getenv('DB_PASS') ?: 'Tr0ub4dor&3xK9!');
define('DB_NAME', getenv('DB_NAME') ?: 'bistro_prod');

// The live database may not be reachable (e.g. local preview); keep the
// connection non-fatal so public pages still render.
$db = null;
if (function_exists('mysqli_connect')) {
    try {
        $db = @mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME, null, 2) ?: null;
    } catch (Throwable $e) {
        $db = null; // no live database on this host
    }
}
