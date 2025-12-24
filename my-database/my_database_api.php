<?php
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
// Handle pre-flight OPTIONS request (required for some browsers / Flutter web)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit(0);
}
// ==================== CONFIG ====================
$imagesRoot = __DIR__ . '/my_database_images'; // ← folder next to this php file
// ==================================================================
// ==================== API KEY PROTECTION =============================
// ==================================================================
// CHANGE THIS TO A VERY STRONG RANDOM STRING!
// Example: 'a9f3b2e8c7d1f6g5h4j9k8l2m1n0o9p8q7r6s5t4'
// This key must match exactly the "Server API Key" you enter in the app
// when adding/editing a MySQL connection.
$API_KEY = '8888';
// Accept key from GET, POST or request body (works with query string or form field)
$provided_key = $_REQUEST['key'] ?? '';
if ($provided_key !== $API_KEY) {
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
        mkdir($path, 0755, true);
    }
}
// ==================== INPUT ====================
$action = $_GET['action'] ?? '';
$db = sanitize($_GET['db'] ?? ''); // Still sanitize globally, but don't validate yet
switch ($action) {
    case 'list_images':
        $table = sanitize($_GET['table'] ?? '');
        $post = sanitize($_GET['post'] ?? '');
        if ($db === '' || $table === '' || $post === '' || strpos("$db/$table/$post", '..') !== false) {
            respond(false, 'Invalid or missing parameters');
        }
        $basePath = "$imagesRoot/$db/$table/$post";
        ensureDir($basePath);
        if (!is_dir($basePath)) {
            respond(true, '', ['images' => []]);
        }
        $files = array_diff(scandir($basePath), ['.', '..']);
        // Find numbered images and max prefix
        $images = [];
        $maxNum = 0;
        foreach ($files as $f) {
            if (is_file("$basePath/$f") && !preg_match('/_thumb\.jpe?g$/i', $f)) {
                if (preg_match('/^(\d{3})_/', $f, $m)) {
                    $num = intval($m[1]);
                    if ($num > $maxNum) $maxNum = $num;
                    $images[] = $f;
                }
            }
        }
        // Find unnumbered images
        $unnumbered = [];
        foreach ($files as $f) {
            if (is_file("$basePath/$f") && !preg_match('/_thumb\.jpe?g$/i', $f) && !preg_match('/^\d{3}_/', $f)) {
                $unnumbered[] = $f;
            }
        }
        // Sort unnumbered naturally and add prefixes
        usort($unnumbered, 'strnatcasecmp');
        foreach ($unnumbered as $f) {
            $maxNum++;
            $padded = str_pad($maxNum, 3, '0', STR_PAD_LEFT);
            $newName = $padded . '_' . $f;
            rename("$basePath/$f", "$basePath/$newName");
            // Rename matching thumb if it exists
            $thumb = pathinfo($f, PATHINFO_FILENAME) . '_thumb.jpg';
            $newThumb = pathinfo($newName, PATHINFO_FILENAME) . '_thumb.jpg';
            if (file_exists("$basePath/$thumb")) {
                rename("$basePath/$thumb", "$basePath/$newThumb");
            }
            $images[] = $newName;
        }
        // Final sort and respond
        usort($images, 'strnatcasecmp');
        respond(true, '', ['images' => $images]);
        break;
    case 'upload_image':
        $table = sanitize($_GET['table'] ?? '');
        $post = sanitize($_GET['post'] ?? '');
        if ($db === '' || $table === '' || $post === '' || strpos("$db/$table/$post", '..') !== false) {
            respond(false, 'Invalid or missing parameters');
        }
        $basePath = "$imagesRoot/$db/$table/$post";
        ensureDir($basePath);
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
        if (strpos($fullName, '..') !== false || strpos($thumbName, '..') !== false) {
            respond(false, 'Invalid filename');
        }
        move_uploaded_file($full['tmp_name'], "$basePath/$fullName");
        move_uploaded_file($thumb['tmp_name'], "$basePath/$thumbName");
        respond(true, 'Uploaded successfully');
        break;
    case 'delete_image':
        $table = sanitize($_GET['table'] ?? '');
        $post = sanitize($_GET['post'] ?? '');
        if ($db === '' || $table === '' || $post === '' || strpos("$db/$table/$post", '..') !== false) {
            respond(false, 'Invalid or missing parameters');
        }
        $basePath = "$imagesRoot/$db/$table/$post";
        ensureDir($basePath);
        $file = basename($_GET['file'] ?? '');
        if ($file === '' || strpos($file, '..') !== false) {
            respond(false, 'Invalid file');
        }
        $fullPath = "$basePath/$file";
        $thumbPath = "$basePath/" . pathinfo($file, PATHINFO_FILENAME) . '_thumb.jpg';
        if (file_exists($fullPath)) unlink($fullPath);
        if (file_exists($thumbPath)) unlink($thumbPath);
        respond(true, 'Image deleted');
        break;
    case 'delete_post_folder':
        $table = sanitize($_GET['table'] ?? '');
        $post = sanitize($_GET['post'] ?? '');
        if ($db === '' || $table === '' || $post === '' || strpos("$db/$table/$post", '..') !== false) {
            respond(false, 'Invalid or missing parameters');
        }
        $basePath = "$imagesRoot/$db/$table/$post";
        if (is_dir($basePath)) {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($basePath, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($iterator as $file) {
                $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
            }
            rmdir($basePath);
        }
        respond(true, 'Folder deleted');
        break;
    case 'reorder_images':
        $table = sanitize($_GET['table'] ?? '');
        $post = sanitize($_GET['post'] ?? '');
        if ($db === '' || $table === '' || $post === '' || strpos("$db/$table/$post", '..') !== false) {
            respond(false, 'Invalid or missing parameters');
        }
        $basePath = "$imagesRoot/$db/$table/$post";
        ensureDir($basePath);
        $input = json_decode(file_get_contents('php://input'), true);
        $order = $input['order'] ?? [];
        if (empty($order)) {
            respond(false, 'No order provided');
        }
        foreach ($order as $i => $oldFullName) {
            $oldFullName = basename($oldFullName);
            if (strpos($oldFullName, '..') !== false) continue;
            $oldFullPath = "$basePath/$oldFullName";
            if (!file_exists($oldFullPath)) continue;
            $parts = explode('_', $oldFullName, 2);
            if (count($parts) !== 2) continue;
            $uniquePart = $parts[1];
            $padded = str_pad($i + 1, 3, '0', STR_PAD_LEFT);
            $newFullName = $padded . '_' . $uniquePart;
            $newFullPath = "$basePath/$newFullName";
            if ($oldFullPath !== $newFullPath) {
                rename($oldFullPath, $newFullPath);
            }
            $oldThumbName = pathinfo($oldFullName, PATHINFO_FILENAME) . '_thumb.jpg';
            $oldThumbPath = "$basePath/$oldThumbName";
            if (file_exists($oldThumbPath)) {
                $newThumbName = $padded . '_' . pathinfo($uniquePart, PATHINFO_FILENAME) . '_thumb.jpg';
                rename($oldThumbPath, "$basePath/$newThumbName");
            }
        }
        respond(true, 'Images reordered');
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
        function recursiveCopy($src, $dst) {
            $dir = opendir($src);
            @mkdir($dst, 0755);
            while (($file = readdir($dir)) !== false) {
                if (($file != '.') && ($file != '..')) {
                    if (is_dir($src . '/' . $file)) {
                        recursiveCopy($src . '/' . $file, $dst . '/' . $file);
                    } else {
                        copy($src . '/' . $file, $dst . '/' . $file);
                    }
                }
            }
            closedir($dir);
        }
        recursiveCopy($src, $dst);
        respond(true, 'Table folder duplicated');
        break;
    case 'delete_table_folder':
        $table = sanitize($_GET['table'] ?? '');
        if ($db === '' || $table === '' || strpos("$db/$table", '..') !== false) {
            respond(false, 'Invalid or missing parameters');
        }
        $path = "$imagesRoot/$db/$table";
        if (is_dir($path)) {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($iterator as $file) {
                $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
            }
            rmdir($path);
        }
        respond(true, 'Table folder deleted');
        break;
    case 'create_table_folder':
        $table = sanitize($_GET['table'] ?? '');
        if ($db === '' || $table === '' || strpos("$db/$table", '..') !== false) {
            respond(false, 'Invalid or missing parameters');
        }
        $path = "$imagesRoot/$db/$table";
        ensureDir($path);
        respond(true, 'Table folder created');
        break;
    case 'upload_thumb':
        $table = sanitize($_GET['table'] ?? '');
        $post = sanitize($_GET['post'] ?? '');
        $file = basename($_GET['file'] ?? '');
        if ($db === '' || $table === '' || $post === '' || $file === '' || strpos("$db/$table/$post/$file", '..') !== false) {
            respond(false, 'Invalid or missing parameters');
        }
        $basePath = "$imagesRoot/$db/$table/$post";
        ensureDir($basePath);
        if (empty($_FILES['thumb'])) {
            respond(false, 'Missing thumb file');
        }
        $thumb = $_FILES['thumb'];
        if ($thumb['error'] !== 0) {
            respond(false, 'File upload error');
        }
        $thumbName = pathinfo($file, PATHINFO_FILENAME) . '_thumb.jpg';
        if (strpos($thumbName, '..') !== false) {
            respond(false, 'Invalid filename');
        }
        move_uploaded_file($thumb['tmp_name'], "$basePath/$thumbName");
        respond(true, 'Thumbnail uploaded successfully');
        break;
    default:
        respond(false, 'Unknown action');
}
?>
