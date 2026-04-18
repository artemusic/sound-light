<?php
$uri = $_SERVER['REQUEST_URI'];
if (preg_match('#^/api[/?]#', $uri) || $uri === '/api') {
    include __DIR__ . '/api.php';
} elseif (is_file(__DIR__ . parse_url($uri, PHP_URL_PATH))) {
    return false;
} else {
    readfile(__DIR__ . '/index.html');
}
