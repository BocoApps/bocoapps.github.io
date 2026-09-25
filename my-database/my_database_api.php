<?php
// The image API: a record's pictures under my_database_images/, reached by the
// app over HTTP. One file on every server, with the keys and their roles at
// the top; everything under them is the same everywhere.
//
// Everything under my_database_images has two writers: this script as www-data,
// and the app uploading over SFTP as a user who is only in the www-data *group*.
// The default 022 umask would make every file this script creates group-read-only
// and lock the other writer out, so widen it once for the whole request.
umask(0002);

header('Content-Type: application/json; charset=utf-8');
// No `Access-Control-Allow-Origin: *`. It was here for "some browsers /
// Flutter web", and nothing in this app is a browser: the phone calls this
// file from Dart, which no same-origin policy applies to. With the star, any
// page on any site could make a visitor's browser run every call below —
// delete_post_folder included — against a server whose key that page had got
// hold of once.

// ==================== CONFIG ====================
$imagesRoot = __DIR__ . '/my_database_images';

// ==================================================================
// ==================== API KEYS & ROLES =============================
// ==================================================================
// One line per person or phone: a key and what it may do.
//   admin    — everything
//   uploader — list, add, reorder, and delete only the pictures it added
//   viewer   — list only
//
// Make every key a long random string:
//   php -r "echo bin2hex(random_bytes(24)), PHP_EOL;"
// A key shorter than $MIN_KEY_LENGTH is refused as though it were not here.
// This file once shipped with '8888' as its admin key, and a server set up by
// uploading it as it came had an open door; a name as a key is the same door.
//
// The key the app sends is the "Server API Key" of its MySQL connection.
$API_KEYS = [
    // 'put-a-long-random-string-here' => 'admin',
];
$MIN_KEY_LENGTH = 16;

// The key comes in the X-Api-Key header and nowhere else. It used to be
// accepted as ?key= as well, for builds of the app that sent it that way; a
// query string is written into the access log of every request, and no build
// in use sends one any more.
$provided_key = $_SERVER['HTTP_X_API_KEY'] ?? '';

// Every key is compared, with hash_equals, whatever the answer turns out to
// be: array_key_exists answers faster for a near miss than for a far one, and
// the comparison is against a secret.
$USER_ROLE = null;
if (is_string($provided_key) && strlen($provided_key) >= $MIN_KEY_LENGTH) {
    foreach ($API_KEYS as $key => $role) {
        if (is_string($key) && strlen($key) >= $MIN_KEY_LENGTH
                && hash_equals($key, $provided_key)) {
            $USER_ROLE = $role;
        }
    }
}
if ($USER_ROLE === null) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Invalid or missing API key']);
    exit;
}

// ==================================================================
// ==================== HELPERS ====================
function respond($success, $message = '', $data = []) {
    echo json_encode([
        'success' => $success,
        'message' => $message,
        'data' => $data
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

function sanitize($str) {
    return preg_replace('/[^a-zA-Z0-9_-]/', '_', $str);
}

function ensureDir($path) {
    if (!file_exists($path)) {
        // 0775, not 0755: these folders are also written to over SFTP by a
        // human user who is only in the www-data *group*, so the group needs write.
        mkdir($path, 0775, true);
    }
}

function hasPermission($role, $action) {
    $permissions = [
        'admin' => ['*'],
        'uploader' => [
            'list_images',
            'upload_image',
            'upload_thumb',
            'reorder_images',
            'delete_image',
            'claim_image'
        ],
        'viewer' => ['list_images']
    ];

    if (!isset($permissions[$role])) return false;
    if (in_array('*', $permissions[$role], true)) return true;
    return in_array($action, $permissions[$role], true);
}

// The pictures sit under the web root, because that is what makes them
// reachable by <img src>. So whatever lands in there is served by the web
// server, and a name is the only thing standing between "a photograph was
// uploaded" and "a PHP file was uploaded and then run". `basename` was the
// whole check, which answers a different question.
//
// One extension, at the end, from the list — `shell.php.jpg` has two and is
// refused, because a server that runs it reads the first one. A name starting
// with a dot is refused too: that is .owners.json and .htaccess.
// HEIC is an ISO BMFF file: 'ftyp' at byte 4, then a four-letter brand.
function isHeicFile($path) {
    $fh = @fopen($path, 'rb');
    if (!$fh) return false;
    $head = fread($fh, 32);
    fclose($fh);
    if (!is_string($head) || strlen($head) < 12) return false;
    if (substr($head, 4, 4) !== 'ftyp') return false;
    return (bool) preg_match('/^(heic|heix|heif|mif1|msf1|heim|heis)$/', substr($head, 8, 4));
}

function isImageName($name) {
    if (!is_string($name) || $name === '' || $name[0] === '.') return false;
    if (strpbrk($name, "/\\\0") !== false) return false;
    if (strpos($name, '..') !== false) return false;
    return (bool) preg_match('/^[A-Za-z0-9._-]+\.(jpe?g|png|webp|gif|bmp|heic|heif)$/i', $name)
        && substr_count($name, '.') === 1;
}

// What turns execution off, and where it goes.
//
// **Not in the images root.** The root is not only pictures: "Publish as web
// page" and the page refresh put `<folder>.php` and `<folder>ai.php` in
// `my_database_images/<folder>/`, inside that same tree — so on Apache a
// .htaccess in the root would switch the published page off. It goes into
// each *table's* folder, `<root>/<folder>/<table>/`, which is where every
// picture is written and where no page ever is.
//
// Every line of it has to be one the server accepts, or Apache answers 500
// for every picture in the folder. So `php_flag` only where mod_php is loaded
// — under PHP-FPM it is an unknown command — no `php_admin_flag`, which
// .htaccess may never carry, and the deny in both Apache dialects. What does
// the work on every setup is the deny: a script that cannot be requested
// cannot be run, whichever way PHP is wired in. nginx ignores the file, which
// is why isImageName is not allowed to lean on it.
const GUARD_MARK = '# Written by my_database_api.php.';
// Deny, in both Apache dialects, for one <FilesMatch> pattern.
function denyBlock($pattern) {
    return "<FilesMatch \"$pattern\">\n"
      . "  <IfModule mod_authz_core.c>\n    Require all denied\n  </IfModule>\n"
      . "  <IfModule !mod_authz_core.c>\n    Order allow,deny\n    Deny from all\n  </IfModule>\n"
      . "</FilesMatch>\n";
}
// The dotfile rule is here as well as in the root, and has to be: Hostinger's
// LiteSpeed does not carry a parent's .htaccess into a folder that has one of
// its own — a published page's folder always does — so the root's rule
// stopped at the first table and .owners.json answered 200 below it. The
// table's own file is the nearest one to every record, so it says it too.
define('TABLE_GUARD', GUARD_MARK . "\n"
  . "# Pictures only: nothing in this folder may ever be executed,\n"
  . "# and nothing whose name starts with a dot is served.\n"
  . "<IfModule mod_php.c>\n  php_flag engine off\n</IfModule>\n"
  . "<IfModule mod_php7.c>\n  php_flag engine off\n</IfModule>\n"
  . denyBlock('\.(?i:php[0-9s]?|phtml|phar|htaccess|cgi|pl|py|sh)$')
  . denyBlock('^\.'));

// Writes the table guard, or brings an older one of ours up to date. A
// .htaccess without the mark is the owner's and is left alone. With $create
// false a table with no folder yet is not given one — a listing must not make
// folders.
function guardTableFolder($tablePath, $create = true) {
    if (!$create && !is_dir($tablePath)) return;
    ensureDir($tablePath);
    $file = "$tablePath/.htaccess";
    if (is_file($file)) {
        $current = @file_get_contents($file);
        if ($current === TABLE_GUARD) return;
        if (!is_string($current) || strncmp($current, GUARD_MARK, strlen(GUARD_MARK)) !== 0) return;
    }
    @file_put_contents($file, TABLE_GUARD);
}

// The images root gets one rule of its own, and only this one: nothing whose
// name starts with a dot is served, anywhere under it. That is .owners.json —
// who owns which picture — and every .htaccess. A <FilesMatch> reaches every
// folder below, so it covers the table folders written before this rule
// existed, and it cannot touch a published page, which is never a dotfile.
//
// A build of this file put the whole picture guard here instead, which
// switched the published pages off; a root file carrying the mark is
// therefore rewritten to this one. One without the mark is the owner's, and
// is left alone.
define('ROOT_GUARD', GUARD_MARK . "\n"
  . "# Nothing whose name starts with a dot is served from here down:\n"
  . "# .owners.json says who owns which picture, and .htaccess is this.\n"
  . denyBlock('^\.'));
function guardImagesRoot($root) {
    if (!is_dir($root)) return;
    $file = "$root/.htaccess";
    if (is_file($file)) {
        $current = @file_get_contents($file);
        if ($current === ROOT_GUARD) return;
        if (!is_string($current) || strncmp($current, GUARD_MARK, strlen(GUARD_MARK)) !== 0) return;
    }
    @file_put_contents($file, ROOT_GUARD);
}
guardImagesRoot($imagesRoot);

// ==================== OWNERSHIP HELPERS ====================
//
// An owner is written down as a fingerprint of its key, never the key: the
// .owners.json sits in a folder under the web root, and a key in it is a key
// one misconfigured server away from anybody who asks for the file. It was
// the key itself, so the first picture uploaded with the admin key left the
// admin key in a public folder. A fingerprint answers "is this the same key"
// and nothing else.

function ownerTag($key) {
    return 'k:' . substr(hash('sha256', (string) $key), 0, 32);
}

function isOwner($stored, $key) {
    return is_string($stored) && hash_equals($stored, ownerTag($key));
}

function getOwnersFilePath($basePath) {
    return $basePath . '/.owners.json';
}

// Read, and any owner still written as a key is turned into its fingerprint
// on the way in, so the next save leaves no key behind.
function loadOwners($basePath) {
    $file = getOwnersFilePath($basePath);
    if (!file_exists($file)) return [];
    $data = json_decode(file_get_contents($file), true);
    if (!is_array($data)) return [];
    foreach ($data as $name => $owner) {
        if (!is_string($owner)) { unset($data[$name]); continue; }
        if (strncmp($owner, 'k:', 2) !== 0) $data[$name] = ownerTag($owner);
    }
    return $data;
}

function saveOwners($basePath, $owners) {
    file_put_contents(getOwnersFilePath($basePath), json_encode($owners, JSON_PRETTY_PRINT));
}

function setImageOwner($basePath, $filename, $ownerKey) {
    $owners = loadOwners($basePath);
    $owners[$filename] = ownerTag($ownerKey);
    saveOwners($basePath, $owners);
}

function getImageOwner($basePath, $filename) {
    $owners = loadOwners($basePath);
    return $owners[$filename] ?? null;
}

function removeImageOwner($basePath, $filename) {
    $owners = loadOwners($basePath);
    unset($owners[$filename]);
    saveOwners($basePath, $owners);
}

// Once per server: every .owners.json already there is read and written back,
// which is what turns the keys in it into fingerprints, and the table it sits
// in is given its guard — the file is `<folder>/<table>/<record>/.owners.json`,
// and a table written before the guard had the dotfile rule has none. The
// marker is a dotfile, so it is not served either. It was
// `.owners_fingerprinted` first; the guards came after, so the pass has a new
// name and runs again.
function fingerprintOwnerFiles($root) {
    $marker = "$root/.owners_guarded";
    if (!is_dir($root) || file_exists($marker)) return;
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, RecursiveDirectoryIterator::SKIP_DOTS)
    );
    foreach ($iterator as $file) {
        if ($file->getFilename() === '.owners.json') {
            saveOwners($file->getPath(), loadOwners($file->getPath()));
            $relative = substr($file->getPath(), strlen($root) + 1);
            if (count(explode('/', $relative)) === 3) {
                guardTableFolder(dirname($file->getPath()), false);
            }
        }
    }
    @file_put_contents($marker, date('c') . "\n");
    @unlink("$root/.owners_fingerprinted");
}
fingerprintOwnerFiles($imagesRoot);

// ==================== FOLDER HELPERS ====================

function removeTree($path) {
    if (!is_dir($path)) return;
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $file) {
        $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
    }
    rmdir($path);
}

function recursiveCopy($src, $dst) {
    ensureDir($dst);
    $dir = opendir($src);
    while (($file = readdir($dir)) !== false) {
        if ($file === '.' || $file === '..') continue;
        if (is_dir("$src/$file")) {
            recursiveCopy("$src/$file", "$dst/$file");
        } else {
            copy("$src/$file", "$dst/$file");
        }
    }
    closedir($dir);
}

// The record folder of a request, or a refusal. Every picture action names
// the same three things and checked them the same way, eight times over.
function recordFolder($imagesRoot, $db) {
    $table = sanitize($_GET['table'] ?? '');
    $post = sanitize($_GET['post'] ?? '');
    if ($db === '' || $table === '' || $post === '' || strpos("$db/$table/$post", '..') !== false) {
        respond(false, 'Invalid or missing parameters');
    }
    return ["$imagesRoot/$db/$table/$post", "$imagesRoot/$db/$table"];
}

// ==================== INPUT ====================
$action = $_GET['action'] ?? '';

if ($action === '') {
    respond(false, 'Missing action parameter');
}

// Everything but a listing changes the server, and a change is a POST. A GET
// is what a crawler, a link preview or a CDN warming its cache sends to any
// URL it has seen, and it must never be able to delete a folder. The
// parameters stay in the query string either way, so an app that sends the
// same URL only has to change its method.
if ($action !== 'list_images' && ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    respond(false, 'This action needs POST');
}

if (!hasPermission($USER_ROLE, $action)) {
    respond(false, 'Permission denied');
}

$db = sanitize($_GET['db'] ?? '');

switch ($action) {

    case 'list_images':
        [$basePath, $tablePath] = recordFolder($imagesRoot, $db);
        // A table folder written before its guard learned the dotfile rule is
        // brought up to date by the first look at it. Never created here.
        guardTableFolder($tablePath, false);
        // No ensureDir: listing is a question, and a question that creates a
        // folder per record leaves a tree of empty ones behind on a database
        // nobody ever put a picture in.
        if (!is_dir($basePath)) {
            respond(true, '', ['images' => []]);
        }
        // Numbered pictures first, in their order, then any dropped into the
        // folder by hand, by name. Listing changes nothing: it used to give
        // every unnumbered file a number here, so a GET — repeatable by any
        // crawler or cache that had the URL — renamed files on disk. The
        // number is given when the user actually reorders (reorder_images),
        // which is a write and is asked for.
        $numbered = [];
        $unnumbered = [];
        foreach (array_diff(scandir($basePath), ['.', '..']) as $f) {
            if (!is_file("$basePath/$f") || $f[0] === '.'
                    || preg_match('/_thumb\.jpe?g$/i', $f)) continue;
            if (preg_match('/^\d+_/', $f)) {
                $numbered[] = $f;
            } else {
                $unnumbered[] = $f;
            }
        }
        usort($numbered, 'strnatcasecmp');
        usort($unnumbered, 'strnatcasecmp');
        respond(true, '', ['images' => array_merge($numbered, $unnumbered)]);
        break;

    case 'upload_image':
        [$basePath, $tablePath] = recordFolder($imagesRoot, $db);
        if (empty($_FILES['full']) || empty($_FILES['thumb'])) {
            respond(false, 'Missing full or thumb file');
        }
        $full = $_FILES['full'];
        $thumb = $_FILES['thumb'];
        if ($full['error'] !== 0 || $thumb['error'] !== 0) {
            respond(false, 'File upload error');
        }
        $fullName = basename($full['name']);
        $thumbName = pathinfo($fullName, PATHINFO_FILENAME) . '_thumb.jpg';
        if (!isImageName($fullName) || !isImageName($thumbName)) {
            respond(false, 'Invalid filename');
        }
        // And the bytes have to be a picture as well as the name. HEIC is the
        // exception: getimagesize does not know it on most builds, and the app
        // sends one when the user chose to keep the original.
        $ext = strtolower(pathinfo($fullName, PATHINFO_EXTENSION));
        // getimagesize does not know HEIC. A real one is an ISO BMFF file
        // whose brand says so; anything else with that extension is refused,
        // the same as a jpeg that is not a picture.
        $fullOk = ($ext === 'heic' || $ext === 'heif')
            ? isHeicFile($full['tmp_name'])
            : @getimagesize($full['tmp_name']) !== false;
        if (!$fullOk || @getimagesize($thumb['tmp_name']) === false) {
            respond(false, 'Not an image');
        }
        // An upload under a name already there replaces it, so an uploader
        // may only do that to a picture of its own — otherwise "delete only
        // what you added" is one upload away from "replace anybody's".
        if ($USER_ROLE === 'uploader' && file_exists("$basePath/$fullName")
                && !isOwner(getImageOwner($basePath, $fullName), $provided_key)) {
            respond(false, 'A picture of that name belongs to someone else.');
        }
        guardTableFolder($tablePath);
        ensureDir($basePath);
        if (!move_uploaded_file($full['tmp_name'], "$basePath/$fullName")
                || !move_uploaded_file($thumb['tmp_name'], "$basePath/$thumbName")) {
            respond(false, 'Could not store the upload');
        }
        setImageOwner($basePath, $fullName, $provided_key);
        respond(true, 'Uploaded successfully');
        break;

    case 'delete_image':
        [$basePath] = recordFolder($imagesRoot, $db);
        $file = basename($_GET['file'] ?? '');
        // A picture's name, never .owners.json or .htaccess.
        if (!isImageName($file)) {
            respond(false, 'Invalid file');
        }

        // ==================== STRICT OWNERSHIP CHECK ====================
        if ($USER_ROLE === 'uploader') {
            $owner = getImageOwner($basePath, $file);
            if ($owner === null) {
                respond(false, 'This image has no owner recorded. Only administrators can delete it.');
            }
            if (!isOwner($owner, $provided_key)) {
                respond(false, 'You can only delete images that you uploaded yourself.');
            }
        }
        // Admin can delete everything (no check needed)
        // ================================================================

        $fullPath = "$basePath/$file";
        $thumbPath = "$basePath/" . pathinfo($file, PATHINFO_FILENAME) . '_thumb.jpg';
        if (file_exists($fullPath)) unlink($fullPath);
        if (file_exists($thumbPath)) unlink($thumbPath);
        if (is_dir($basePath)) removeImageOwner($basePath, $file);
        respond(true, 'Image deleted');
        break;

    case 'reorder_images':
        [$basePath] = recordFolder($imagesRoot, $db);
        if (!is_dir($basePath)) respond(false, 'No such record folder');

        $input = json_decode(file_get_contents('php://input'), true);
        $order = $input['order'] ?? [];
        if (empty($order) || !is_array($order)) respond(false, 'No order provided');

        $owners = loadOwners($basePath);

        // ==================== STEP 0: the plan, checked whole ====================
        // Every move is worked out and checked before a single file is
        // touched, so a refusal leaves the folder exactly as it was.
        $plan = [];
        $moving = [];
        foreach (array_values($order) as $i => $oldName) {
            $oldName = basename((string) $oldName);
            if (strpos($oldName, '..') !== false || $oldName === '' || $oldName[0] === '.') continue;
            if (isset($moving[$oldName]) || !is_file("$basePath/$oldName")) continue;

            // The number comes off only when there is one. A file dropped in
            // by hand has none, and `my_photo.jpg` split on its first
            // underscore lost `my_`.
            $uniquePart = preg_match('/^(\d+)_/', $oldName, $num)
                ? substr($oldName, strlen($num[0]))
                : $oldName;
            // Only pictures get a number. The listing shows whatever is in the
            // folder, so a reorder could be handed `x.php` dropped in by hand,
            // and `001_x.php` is still a script — on nginx, where .htaccess
            // does nothing, one the server would run.
            if (!isImageName($uniquePart)) continue;

            $newName = str_pad(count($plan) + 1, 3, '0', STR_PAD_LEFT) . '_' . $uniquePart;
            $plan[] = ['old' => $oldName, 'final' => $newName, 'unique' => $uniquePart];
            $moving[$oldName] = true;
        }
        foreach ($plan as $move) {
            if ($move['final'] === $move['old']) continue;
            // A name that is taken by a picture this order does not mention
            // would be replaced by the rename, silently: rename() overwrites.
            $finalThumb = pathinfo($move['final'], PATHINFO_FILENAME) . '_thumb.jpg';
            if ((file_exists("$basePath/{$move['final']}") && !isset($moving[$move['final']]))
                    || (file_exists("$basePath/$finalThumb") && !isset($moving[$move['final']]))) {
                respond(false, 'The new order would replace a picture it does not mention.');
            }
            // "Delete only what you added" has to hold for a move as well: a
            // picture renamed is a picture changed.
            if ($USER_ROLE === 'uploader' && !isOwner($owners[$move['old']] ?? null, $provided_key)) {
                respond(false, 'You can only move pictures that you uploaded yourself.');
            }
        }

        // ==================== STEP 1: temporary names ====================
        // Everything goes to a temporary name first, so that 001 becoming 002
        // while 002 is still there cannot collide. The picture and its
        // thumbnail move together.
        $tempMap = [];
        foreach ($plan as $i => $move) {
            if ($move['final'] === $move['old']) continue;
            $tempFull = "__tmp_full_{$i}_" . $move['unique'];
            $oldThumb  = pathinfo($move['old'],   PATHINFO_FILENAME) . '_thumb.jpg';
            $newThumb  = pathinfo($move['final'], PATHINFO_FILENAME) . '_thumb.jpg';
            $tempThumb = pathinfo($tempFull,      PATHINFO_FILENAME) . '_thumb.jpg';

            rename("$basePath/{$move['old']}", "$basePath/$tempFull");
            if (file_exists("$basePath/$oldThumb")) {
                rename("$basePath/$oldThumb", "$basePath/$tempThumb");
            }
            $tempMap[$tempFull] = [
                'final'      => $move['final'],
                'tempThumb'  => $tempThumb,
                'finalThumb' => $newThumb,
                'oldName'    => $move['old'],
            ];
        }

        // ==================== STEP 2: temporary -> final ====================
        // Start from the owners there are and move only the names that change.
        // Writing the file from an empty list is what used to lose them.
        $newOwners = $owners;
        foreach ($tempMap as $info) {
            if (isset($owners[$info['oldName']])) unset($newOwners[$info['oldName']]);
        }
        foreach ($tempMap as $tempFull => $info) {
            rename("$basePath/$tempFull", "$basePath/{$info['final']}");
            if (file_exists("$basePath/{$info['tempThumb']}")) {
                rename("$basePath/{$info['tempThumb']}", "$basePath/{$info['finalThumb']}");
            }
            if (isset($owners[$info['oldName']])) {
                $newOwners[$info['final']] = $owners[$info['oldName']];
            }
        }
        saveOwners($basePath, $newOwners);
        respond(true, 'Images reordered');
        break;

    // ==================== CLAIM IMAGE ====================
    // An uploader may take over a picture with NO owner (one copied onto the
    // server by hand, say). An admin may give any picture to anyone.
    case 'claim_image':
        [$basePath] = recordFolder($imagesRoot, $db);
        $file = basename($_GET['file'] ?? '');
        if (!isImageName($file) || !is_file("$basePath/$file")) {
            respond(false, 'Invalid file');
        }
        $owner = getImageOwner($basePath, $file);

        if ($USER_ROLE === 'uploader') {
            if ($owner !== null && !isOwner($owner, $provided_key)) {
                respond(false, 'This image already belongs to someone else.');
            }
            setImageOwner($basePath, $file, $provided_key);
            respond(true, 'You now own this image');
        }

        // An admin names the owner with ?owner=KEY, or takes it itself.
        $targetKey = $_GET['owner'] ?? $provided_key;
        if (!is_string($targetKey) || !array_key_exists($targetKey, $API_KEYS)) {
            respond(false, 'Unknown target owner key');
        }
        setImageOwner($basePath, $file, $targetKey);
        // Not the key itself: the answer is written into logs and caches too.
        respond(true, 'Owner set');
        break;

    // ==================== FOLDER ACTIONS ====================
    // The permission table governs these: 'admin' is ['*'], and 'uploader'
    // carries upload_thumb but none of the folder ones.

    case 'delete_post_folder':
        [$basePath] = recordFolder($imagesRoot, $db);
        removeTree($basePath);
        respond(true, 'Folder deleted');
        break;

    case 'create_table_folder':
        $table = sanitize($_GET['table'] ?? '');
        if ($db === '' || $table === '' || strpos("$db/$table", '..') !== false) {
            respond(false, 'Invalid or missing parameters');
        }
        guardTableFolder("$imagesRoot/$db/$table");
        respond(true, 'Table folder created');
        break;

    case 'delete_table_folder':
        $table = sanitize($_GET['table'] ?? '');
        if ($db === '' || $table === '' || strpos("$db/$table", '..') !== false) {
            respond(false, 'Invalid or missing parameters');
        }
        removeTree("$imagesRoot/$db/$table");
        respond(true, 'Table folder deleted');
        break;

    case 'rename_table_folder':
        $old_table = sanitize($_GET['old_table'] ?? '');
        $new_table = sanitize($_GET['new_table'] ?? '');
        if ($db === '' || $old_table === '' || $new_table === '' || strpos("$db/$old_table/$new_table", '..') !== false) {
            respond(false, 'Invalid or missing parameters');
        }
        $oldPath = "$imagesRoot/$db/$old_table";
        $newPath = "$imagesRoot/$db/$new_table";
        if (!is_dir($oldPath)) {
            respond(false, 'Old folder not found');
        }
        if (is_dir($newPath)) {
            respond(false, 'New folder already exists');
        }
        rename($oldPath, $newPath);
        respond(true, 'Table folder renamed');
        break;

    case 'duplicate_table_folder':
        $table = sanitize($_GET['table'] ?? '');
        $new_table = sanitize($_GET['new_table'] ?? '');
        if ($db === '' || $table === '' || $new_table === '' || strpos("$db/$table/$new_table", '..') !== false) {
            respond(false, 'Invalid or missing parameters');
        }
        $src = "$imagesRoot/$db/$table";
        $dst = "$imagesRoot/$db/$new_table";
        if (!is_dir($src)) {
            respond(false, 'Source folder not found');
        }
        if (is_dir($dst)) {
            respond(false, 'Destination folder already exists');
        }
        recursiveCopy($src, $dst);
        guardTableFolder($dst);
        respond(true, 'Table folder duplicated');
        break;

    case 'upload_thumb':
        [$basePath, $tablePath] = recordFolder($imagesRoot, $db);
        $file = basename($_GET['file'] ?? '');
        // The same checks as upload_image, which this is the other half of:
        // the name it is filed under has to be a picture's, and so do the
        // bytes. It had neither — a thumbnail was only ever `basename`.
        $thumbName = pathinfo($file, PATHINFO_FILENAME) . '_thumb.jpg';
        if (!isImageName($file) || !isImageName($thumbName)) {
            respond(false, 'Invalid filename');
        }
        // Made for a picture that is already there, never for a made-up name.
        if (!is_file("$basePath/$file")) {
            respond(false, 'No such picture');
        }
        // What the app sends this for is a thumbnail that is missing. An
        // uploader may add one of those to any picture, and replace only the
        // thumbnail of a picture of its own.
        if ($USER_ROLE === 'uploader' && file_exists("$basePath/$thumbName")
                && !isOwner(getImageOwner($basePath, $file), $provided_key)) {
            respond(false, 'That thumbnail belongs to someone else.');
        }
        if (empty($_FILES['thumb'])) {
            respond(false, 'Missing thumb file');
        }
        $thumb = $_FILES['thumb'];
        if ($thumb['error'] !== 0) {
            respond(false, 'File upload error');
        }
        if (@getimagesize($thumb['tmp_name']) === false) {
            respond(false, 'Not an image');
        }
        guardTableFolder($tablePath);
        if (!move_uploaded_file($thumb['tmp_name'], "$basePath/$thumbName")) {
            respond(false, 'Could not store the upload');
        }
        respond(true, 'Thumbnail uploaded successfully');
        break;

    default:
        respond(false, 'Unknown action or not allowed for your role');
}
?>
