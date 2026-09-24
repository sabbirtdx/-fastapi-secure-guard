<?php
// Secure File Guard — activation endpoint shim.
//
// A tiny physical entry point so static file servers (php -S, plain Apache
// DocumentRoot) can route /guard/activate to the runtime. ALL logic,
// verification and rendering live in guard.php, which is integrity-protected
// by the signed manifest. Replacing this shim cannot bypass the guard.
require_once __DIR__ . '/guard.php';
