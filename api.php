<?php
/**
 * Artemusic – Backend PHP
 * Equivalente completo del server.js Node.js
 * Compatibile con hosting shared one.com (PHP 7.4+)
 */

// ══════════════════════════════════════════════
// CONFIGURAZIONE
// ══════════════════════════════════════════════
define('ADMIN_PASSWORD',    '260264');   // admin: calendario + file manager + importo
define('CALENDAR_PASSWORD', '112233');   // tecnici: solo calendario (no modifica, no importo)
define('USER_PASSWORD',     '445566');   // area riservata documenti

define('DOCS_ROOT', __DIR__ . '/documenti');
define('EVENTS_FILE', __DIR__ . '/data/eventi.json');
define('TOKENS_FILE', __DIR__ . '/data/tokens.json');  // token Bearer persistenti

// ══════════════════════════════════════════════
// INIT
// ══════════════════════════════════════════════
// Crea cartelle necessarie
foreach ([DOCS_ROOT, __DIR__ . '/data', DOCS_ROOT . '/Archivio Eventi'] as $dir) {
    if (!is_dir($dir)) mkdir($dir, 0755, true);
}
if (!file_exists(EVENTS_FILE)) file_put_contents(EVENTS_FILE, '[]');
if (!file_exists(TOKENS_FILE)) file_put_contents(TOKENS_FILE, '{}');

// Blocca accesso diretto alla cartella documenti via URL
// (.htaccess gestisce questo, ma doppio controllo)
$requestUri = $_SERVER['REQUEST_URI'] ?? '';
if (preg_match('#/documenti/#i', $requestUri)) {
    http_response_code(403);
    exit('Accesso negato');
}

// Sessione sicura – rileva HTTPS automaticamente
$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
           || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')
           || (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443);
session_set_cookie_params([
    'lifetime' => 86400,      // 24 ore
    'path'     => '/',
    'secure'   => $isHttps,   // true su HTTPS (one.com, Render, ecc.)
    'httponly' => true,
    'samesite' => 'Lax'
]);
session_name('artemusic_sess');
session_start();

// Headers CORS / JSON
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

// ══════════════════════════════════════════════
// ROUTER
// ══════════════════════════════════════════════
$method = $_SERVER['REQUEST_METHOD'];
$path   = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// Supporta sia /api/login (via .htaccess rewrite) che /api.php/login (PATH_INFO) che ?route=/login
// one.com shared hosting: mod_rewrite potrebbe non funzionare, usiamo PATH_INFO
$route = '';
if (!empty($_SERVER['PATH_INFO'])) {
    // Chiamata tipo /api.php/login
    $route = rtrim($_SERVER['PATH_INFO'], '/');
} elseif (!empty($_GET['route'])) {
    // Fallback: /api.php?route=/login
    $route = '/' . ltrim($_GET['route'], '/');
    $route = rtrim($route, '/');
} else {
    // Via .htaccess rewrite: /api/login
    $route = preg_replace('#^/api\.php#', '', $path);
    $route = preg_replace('#^/api#', '', $route);
    $route = rtrim($route, '/');
}
if (empty($route)) $route = '/';

// Body JSON
$rawBody = file_get_contents('php://input');
$body    = json_decode($rawBody, true) ?? [];

// ══════════════════════════════════════════════
// ROUTE DISPATCH
// ══════════════════════════════════════════════

// POST /login
if ($method === 'POST' && $route === '/login') {
    $pw = $body['password'] ?? ($_POST['password'] ?? '');
    $role = null;
    if ($pw === ADMIN_PASSWORD)    $role = 'admin';
    elseif ($pw === CALENDAR_PASSWORD) $role = 'tecnico';
    elseif ($pw === USER_PASSWORD) $role = 'user';

    if (!$role) { http_response_code(401); echo json_encode(['ok'=>false,'message'=>'Password errata']); exit; }

    $_SESSION['role'] = $role;

    // Genera Bearer token persistente
    $token   = bin2hex(random_bytes(24));
    $expires = time() + 86400;
    $tokens  = readTokens();
    cleanExpiredTokens($tokens);
    $tokens[$token] = ['role' => $role, 'expires' => $expires];
    saveTokens($tokens);

    echo json_encode(['ok'=>true,'role'=>$role,'token'=>$token]);
    exit;
}

// POST /logout
if ($method === 'POST' && $route === '/logout') {
    session_destroy();
    echo json_encode(['ok'=>true]);
    exit;
}

// GET /me
if ($method === 'GET' && $route === '/me') {
    $role = getRole();
    if (!$role) { http_response_code(401); echo json_encode(['ok'=>false]); exit; }
    echo json_encode(['ok'=>true,'role'=>$role]);
    exit;
}

// GET /files
if ($method === 'GET' && $route === '/files') {
    requireAuth();
    $role   = getRole();
    $relPath = $_GET['path'] ?? '';
    $folder  = safePath($relPath);
    if (!$folder) { http_response_code(400); echo json_encode(['ok'=>false,'message'=>'Percorso non valido']); exit; }
    if (!is_dir($folder)) { http_response_code(404); echo json_encode(['ok'=>false,'message'=>'Cartella non trovata']); exit; }

    $hidden = ['.keep','keep','index.html','.gitkeep','.DS_Store','Thumbs.db','.htaccess'];
    $isRoot = (relToDocs($folder) === '');
    $hideArchivio = $isRoot && ($role !== 'admin');

    $entries = [];
    foreach (scandir($folder) as $name) {
        if ($name === '.' || $name === '..') continue;
        if (in_array($name, $hidden)) continue;
        if ($name[0] === '.') continue;
        if ($hideArchivio && $name === 'Archivio Eventi') continue;

        $fullPath = $folder . DIRECTORY_SEPARATOR . $name;
        $isDir    = is_dir($fullPath);
        $stat     = stat($fullPath);
        $entries[] = [
            'name'     => $name,
            'isDir'    => $isDir,
            'size'     => $isDir ? 0 : $stat['size'],
            'modified' => date('c', $stat['mtime']),
            'path'     => relToDocs($fullPath)
        ];
    }

    // Ordina: cartelle prima, poi per nome (it)
    usort($entries, function($a, $b) {
        if ($a['isDir'] !== $b['isDir']) return $a['isDir'] ? -1 : 1;
        return strcoll($a['name'], $b['name']);
    });

    echo json_encode(['ok'=>true,'path'=>relToDocs($folder),'entries'=>$entries]);
    exit;
}

// POST /upload
if ($method === 'POST' && $route === '/upload') {
    requireAdmin();
    $relPath = $_POST['path'] ?? '';
    $folder  = safePath($relPath);
    if (!$folder) { http_response_code(400); echo json_encode(['ok'=>false,'message'=>'Percorso non valido']); exit; }
    if (!is_dir($folder)) mkdir($folder, 0755, true);

    if (empty($_FILES['files'])) { http_response_code(400); echo json_encode(['ok'=>false,'message'=>'Nessun file']); exit; }

    // Normalizza struttura $_FILES per upload multiplo
    $files = normalizeFiles($_FILES['files']);
    $uploaded = [];

    foreach ($files as $file) {
        if ($file['error'] !== UPLOAD_ERR_OK) continue;
        $safeName = preg_replace('/[^a-zA-Z0-9._\-àèìòùÀÈÌÒÙ ]/', '_', $file['name']);
        $dest     = $folder . DIRECTORY_SEPARATOR . $safeName;
        if (move_uploaded_file($file['tmp_name'], $dest)) {
            $uploaded[] = ['name'=>$safeName,'size'=>$file['size'],'path'=>relToDocs($dest)];
        }
    }

    echo json_encode(['ok'=>true,'uploaded'=>$uploaded]);
    exit;
}

// POST /mkdir
if ($method === 'POST' && $route === '/mkdir') {
    requireAdmin();
    $name = trim($body['name'] ?? '');
    if (!$name) { http_response_code(400); echo json_encode(['ok'=>false,'message'=>'Nome cartella mancante']); exit; }
    $safeName = preg_replace('/[^a-zA-Z0-9._\-àèìòùÀÈÌÒÙ &]/', '_', $name);
    $relBase  = $body['path'] ?? '';
    $folder   = safePath(($relBase ? $relBase . '/' : '') . $safeName);
    if (!$folder) { http_response_code(400); echo json_encode(['ok'=>false,'message'=>'Percorso non valido']); exit; }
    if (is_dir($folder)) { http_response_code(409); echo json_encode(['ok'=>false,'message'=>'Cartella già esistente']); exit; }
    mkdir($folder, 0755, true);
    echo json_encode(['ok'=>true,'path'=>relToDocs($folder)]);
    exit;
}

// POST /rename
if ($method === 'POST' && $route === '/rename') {
    requireAdmin();
    $newName = trim($body['newName'] ?? '');
    if (!$newName) { http_response_code(400); echo json_encode(['ok'=>false,'message'=>'Nuovo nome mancante']); exit; }
    $src = safePath($body['path'] ?? '');
    if (!$src) { http_response_code(400); echo json_encode(['ok'=>false,'message'=>'Percorso non valido']); exit; }
    $safeName = preg_replace('/[^a-zA-Z0-9._\-àèìòùÀÈÌÒÙ &]/', '_', $newName);
    $dest     = dirname($src) . DIRECTORY_SEPARATOR . $safeName;
    if (strpos(realpath(dirname($src)), DOCS_ROOT) === false) { http_response_code(400); echo json_encode(['ok'=>false,'message'=>'Destinazione non valida']); exit; }
    if (!file_exists($src)) { http_response_code(404); echo json_encode(['ok'=>false,'message'=>'File/cartella non trovata']); exit; }
    if (file_exists($dest)) { http_response_code(409); echo json_encode(['ok'=>false,'message'=>'Esiste già un elemento con quel nome']); exit; }
    rename($src, $dest);
    echo json_encode(['ok'=>true,'path'=>relToDocs($dest)]);
    exit;
}

// DELETE /delete
if ($method === 'DELETE' && $route === '/delete') {
    requireAdmin();
    $target = safePath($_GET['path'] ?? '');
    if (!$target) { http_response_code(400); echo json_encode(['ok'=>false,'message'=>'Percorso non valido']); exit; }
    if (!file_exists($target)) { http_response_code(404); echo json_encode(['ok'=>false,'message'=>'Non trovato']); exit; }
    if (is_dir($target)) {
        deleteDir($target);
    } else {
        unlink($target);
    }
    echo json_encode(['ok'=>true]);
    exit;
}

// GET /download
if ($method === 'GET' && $route === '/download') {
    requireAuth();
    $target = safePath($_GET['path'] ?? '');
    if (!$target || !file_exists($target)) { http_response_code(404); echo json_encode(['ok'=>false,'message'=>'File non trovato']); exit; }

    if (is_dir($target)) {
        // Crea ZIP in memoria e invia
        $zipName = basename($target) . '.zip';
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="' . $zipName . '"');
        header('Content-Transfer-Encoding: binary');
        ob_end_clean();
        $zip = new ZipArchive();
        $tmpZip = sys_get_temp_dir() . '/' . uniqid('art_') . '.zip';
        $zip->open($tmpZip, ZipArchive::CREATE | ZipArchive::OVERWRITE);
        addDirToZip($zip, $target, basename($target));
        $zip->close();
        readfile($tmpZip);
        unlink($tmpZip);
    } else {
        $mime = mime_content_type($target) ?: 'application/octet-stream';
        header('Content-Type: ' . $mime);
        header('Content-Disposition: attachment; filename="' . basename($target) . '"');
        header('Content-Length: ' . filesize($target));
        ob_end_clean();
        readfile($target);
    }
    exit;
}

// POST /share
if ($method === 'POST' && $route === '/share') {
    requireAuth();
    $target = safePath($body['path'] ?? '');
    if (!$target || !file_exists($target)) { http_response_code(404); echo json_encode(['ok'=>false,'message'=>'File non trovato']); exit; }

    $token   = bin2hex(random_bytes(16));
    $expires = time() + 86400;
    $tokens  = readTokens();
    $tokens['share_' . $token] = ['filePath' => $target, 'expires' => $expires, 'type' => 'share'];
    saveTokens($tokens);

    $proto = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host  = $_SERVER['HTTP_HOST'];
    $shareUrl = $proto . '://' . $host . '/api/shared/' . $token;
    echo json_encode(['ok'=>true,'url'=>$shareUrl,'expires'=>date('c', $expires)]);
    exit;
}

// GET /shared/:token
if ($method === 'GET' && preg_match('#^/shared/([a-f0-9]+)$#', $route, $m)) {
    $token  = $m[1];
    $tokens = readTokens();
    $key    = 'share_' . $token;
    if (!isset($tokens[$key]) || $tokens[$key]['expires'] < time()) {
        unset($tokens[$key]); saveTokens($tokens);
        header('Content-Type: text/html; charset=utf-8');
        http_response_code(410);
        echo 'Link scaduto o non valido';
        exit;
    }
    $filePath = $tokens[$key]['filePath'];
    if (!file_exists($filePath)) { http_response_code(404); header('Content-Type: text/html'); echo 'File non trovato'; exit; }

    if (is_dir($filePath)) {
        $zipName = basename($filePath) . '.zip';
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="' . $zipName . '"');
        ob_end_clean();
        $zip    = new ZipArchive();
        $tmpZip = sys_get_temp_dir() . '/' . uniqid('art_') . '.zip';
        $zip->open($tmpZip, ZipArchive::CREATE | ZipArchive::OVERWRITE);
        addDirToZip($zip, $filePath, basename($filePath));
        $zip->close();
        readfile($tmpZip);
        unlink($tmpZip);
    } else {
        $mime = mime_content_type($filePath) ?: 'application/octet-stream';
        header('Content-Type: ' . $mime);
        header('Content-Disposition: attachment; filename="' . basename($filePath) . '"');
        header('Content-Length: ' . filesize($filePath));
        ob_end_clean();
        readfile($filePath);
    }
    exit;
}

// ══════════════════════════════════════════════
// CALENDARIO EVENTI
// ══════════════════════════════════════════════

// GET /eventi
if ($method === 'GET' && $route === '/eventi') {
    requireAuth();
    $role   = getRole();
    $canFin = ($role === 'admin');
    $eventi = readEvents();
    if (!$canFin) {
        $eventi = array_map(function($e) {
            unset($e['importo']);
            return $e;
        }, $eventi);
    }
    echo json_encode(['ok'=>true,'eventi'=>array_values($eventi)]);
    exit;
}

// POST /eventi
if ($method === 'POST' && $route === '/eventi') {
    requireEventManager();
    $role   = getRole();
    $canFin = ($role === 'admin');

    $titolo       = trim($body['titolo']       ?? '');
    $data         = trim($body['data']         ?? '');
    $oraInizio    = trim($body['oraInizio']    ?? '');
    $oraFine      = trim($body['oraFine']      ?? '');
    $luogo        = trim($body['luogo']        ?? '');
    $indirizzo    = trim($body['indirizzo']    ?? '');
    $orarioLavoro = trim($body['orarioLavoro'] ?? '');
    $dipendenti   = trim($body['dipendenti']   ?? '');
    $merce        = trim($body['merce']        ?? '');
    $note         = trim($body['note']         ?? '');
    $colore       = trim($body['colore']       ?? '#e81c2e');
    $importo      = $canFin ? trim($body['importo'] ?? '') : '';

    if (!$titolo || !$data) { http_response_code(400); echo json_encode(['ok'=>false,'message'=>'Titolo e data sono obbligatori']); exit; }

    $id = base_convert(time(), 10, 36) . bin2hex(random_bytes(4));
    $evento = compact('id','titolo','data','oraInizio','oraFine','luogo','indirizzo',
                      'orarioLavoro','dipendenti','merce','note','colore','importo');
    $evento['creatoIl'] = date('c');

    $events = readEvents();
    $events[] = $evento;
    writeEvents($events);

    // Crea cartella in Archivio Eventi
    $archivioPath = DOCS_ROOT . '/Archivio Eventi';
    if (!is_dir($archivioPath)) mkdir($archivioPath, 0755, true);
    $folderName = preg_replace('/[<>:"\/\\|?*]/', '_', $data . ' – ' . $titolo);
    $folderPath = $archivioPath . '/' . $folderName;
    if (!is_dir($folderPath)) mkdir($folderPath, 0755, true);

    echo json_encode(['ok'=>true,'evento'=>$evento]);
    exit;
}

// PUT /eventi/:id
if ($method === 'PUT' && preg_match('#^/eventi/([a-z0-9]+)$#', $route, $m)) {
    requireEventManager();
    $role   = getRole();
    $canFin = ($role === 'admin');
    $id     = $m[1];

    $events = readEvents();
    $idx    = -1;
    foreach ($events as $i => $e) { if ($e['id'] === $id) { $idx = $i; break; } }
    if ($idx === -1) { http_response_code(404); echo json_encode(['ok'=>false,'message'=>'Evento non trovato']); exit; }

    $titolo       = trim($body['titolo']       ?? '');
    $data         = trim($body['data']         ?? '');
    if (!$titolo || !$data) { http_response_code(400); echo json_encode(['ok'=>false,'message'=>'Titolo e data sono obbligatori']); exit; }

    $events[$idx] = array_merge($events[$idx], [
        'titolo'       => $titolo,
        'data'         => $data,
        'oraInizio'    => trim($body['oraInizio']    ?? ''),
        'oraFine'      => trim($body['oraFine']      ?? ''),
        'luogo'        => trim($body['luogo']        ?? ''),
        'indirizzo'    => trim($body['indirizzo']    ?? ''),
        'orarioLavoro' => trim($body['orarioLavoro'] ?? ''),
        'dipendenti'   => trim($body['dipendenti']   ?? ''),
        'merce'        => trim($body['merce']        ?? ''),
        'note'         => trim($body['note']         ?? ''),
        'colore'       => trim($body['colore']       ?? ($events[$idx]['colore'] ?? '#e81c2e')),
        'importo'      => $canFin
                            ? trim($body['importo'] ?? ($events[$idx]['importo'] ?? ''))
                            : ($events[$idx]['importo'] ?? ''),
        'aggiornatoIl' => date('c'),
    ]);
    writeEvents($events);
    echo json_encode(['ok'=>true,'evento'=>$events[$idx]]);
    exit;
}

// DELETE /eventi/:id
if ($method === 'DELETE' && preg_match('#^/eventi/([a-z0-9]+)$#', $route, $m)) {
    requireEventManager();
    $id     = $m[1];
    $events = readEvents();
    $filtered = array_values(array_filter($events, fn($e) => $e['id'] !== $id));
    if (count($filtered) === count($events)) { http_response_code(404); echo json_encode(['ok'=>false,'message'=>'Evento non trovato']); exit; }
    writeEvents($filtered);
    echo json_encode(['ok'=>true]);
    exit;
}

// Route non trovata
http_response_code(404);
echo json_encode(['ok'=>false,'message'=>'Route non trovata']);
exit;

// ══════════════════════════════════════════════
// HELPER FUNCTIONS
// ══════════════════════════════════════════════

function getRole(): ?string {
    // 1. Cookie di sessione (più affidabile su shared hosting)
    if (!empty($_SESSION['role'])) return $_SESSION['role'];

    // 2. Token dal body JSON o POST (fallback per Apache che strippa Authorization)
    global $body;
    $token = '';

    // 2a. Dal body JSON: {"_token":"..."}
    if (!$token && !empty($body['_token'])) $token = $body['_token'];

    // 2b. Da parametro GET: ?_token=...
    if (!$token && !empty($_GET['_token'])) $token = $_GET['_token'];

    // 2c. Dal cookie _art_token
    if (!$token && !empty($_COOKIE['_art_token'])) $token = $_COOKIE['_art_token'];

    // 2d. Header Authorization (funziona solo se Apache non lo strippa)
    if (!$token) {
        $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (!$auth) $auth = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
        if (!$auth) $auth = $_SERVER['HTTP_X_HTTP_AUTHORIZATION'] ?? '';
        if (!$auth && function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            $auth = $headers['Authorization'] ?? '';
        }
        if (str_starts_with($auth, 'Bearer ')) {
            $token = substr($auth, 7);
        }
    }

    if ($token) {
        $tokens = readTokens();
        if (isset($tokens[$token]) && $tokens[$token]['expires'] > time()) {
            return $tokens[$token]['role'];
        }
    }
    return null;
}

function requireAuth(): void {
    if (!getRole()) {
        http_response_code(401);
        echo json_encode(['ok'=>false,'message'=>'Non autenticato']);
        exit;
    }
}

function requireAdmin(): void {
    if (getRole() !== 'admin') {
        http_response_code(403);
        echo json_encode(['ok'=>false,'message'=>'Solo admin']);
        exit;
    }
}

function requireEventManager(): void {
    if (getRole() !== 'admin') {
        http_response_code(403);
        echo json_encode(['ok'=>false,'message'=>'Solo admin']);
        exit;
    }
}

function safePath(string $relPath): ?string {
    $docsRoot = realpath(DOCS_ROOT);
    if (!$docsRoot) return null;
    // Costruisci path assoluto
    $full = $relPath ? $docsRoot . DIRECTORY_SEPARATOR . ltrim($relPath, '/\\') : $docsRoot;
    // Normalizza (risolvi .. ecc.)
    // Non usare realpath perché il path potrebbe non esistere ancora
    $normalized = normalizePath($full);
    // Verifica che sia dentro DOCS_ROOT
    if (strpos($normalized, $docsRoot) !== 0) return null;
    return $normalized;
}

function normalizePath(string $path): string {
    $parts  = preg_split('#[/\\\\]#', $path);
    $result = [];
    foreach ($parts as $part) {
        if ($part === '' || $part === '.') continue;
        if ($part === '..') { array_pop($result); continue; }
        $result[] = $part;
    }
    $normalized = DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, $result);
    // Windows fix
    if (DIRECTORY_SEPARATOR === '\\' && strlen($path) > 2 && $path[1] === ':') {
        $normalized = $result[0] . DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, array_slice($result, 1));
    }
    return $normalized;
}

function relToDocs(string $absPath): string {
    $docsRoot = realpath(DOCS_ROOT) ?: DOCS_ROOT;
    $rel = ltrim(substr($absPath, strlen($docsRoot)), DIRECTORY_SEPARATOR . '/\\');
    return str_replace('\\', '/', $rel);
}

function readEvents(): array {
    if (!file_exists(EVENTS_FILE)) return [];
    $data = json_decode(file_get_contents(EVENTS_FILE), true);
    return is_array($data) ? $data : [];
}

function writeEvents(array $events): void {
    file_put_contents(EVENTS_FILE, json_encode(array_values($events), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}

function readTokens(): array {
    if (!file_exists(TOKENS_FILE)) return [];
    $data = json_decode(file_get_contents(TOKENS_FILE), true);
    return is_array($data) ? $data : [];
}

function saveTokens(array $tokens): void {
    file_put_contents(TOKENS_FILE, json_encode($tokens, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}

function cleanExpiredTokens(array &$tokens): void {
    $now = time();
    foreach ($tokens as $k => $v) {
        if (isset($v['expires']) && $v['expires'] < $now) unset($tokens[$k]);
    }
}

function deleteDir(string $dir): void {
    if (!is_dir($dir)) return;
    $items = scandir($dir);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $path = $dir . DIRECTORY_SEPARATOR . $item;
        is_dir($path) ? deleteDir($path) : unlink($path);
    }
    rmdir($dir);
}

function addDirToZip(ZipArchive $zip, string $dir, string $prefix): void {
    $items = scandir($dir);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $fullPath  = $dir . DIRECTORY_SEPARATOR . $item;
        $entryName = $prefix . '/' . $item;
        if (is_dir($fullPath)) {
            $zip->addEmptyDir($entryName);
            addDirToZip($zip, $fullPath, $entryName);
        } else {
            $zip->addFile($fullPath, $entryName);
        }
    }
}

function normalizeFiles(array $files): array {
    // $_FILES['files'] con upload multiplo ha struttura diversa
    if (!is_array($files['name'])) {
        return [$files];
    }
    $result = [];
    for ($i = 0; $i < count($files['name']); $i++) {
        $result[] = [
            'name'     => $files['name'][$i],
            'tmp_name' => $files['tmp_name'][$i],
            'size'     => $files['size'][$i],
            'error'    => $files['error'][$i],
        ];
    }
    return $result;
}
