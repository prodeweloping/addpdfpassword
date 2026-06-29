<?php
session_start();

// Generate CSRF token if not exists
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Helper to delete files and directory
function cleanup($files, $dir = null) {
    foreach ((array)$files as $file) {
        if (file_exists($file)) {
            @unlink($file);
        }
    }
    if ($dir && is_dir($dir)) {
        @rmdir($dir);
    }
}

// Handle POST request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF check
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Invalid CSRF token.']);
        exit;
    }

    // File upload check
    if (!isset($_FILES['pdf_file']) || $_FILES['pdf_file']['error'] !== UPLOAD_ERR_OK) {
        $errorMsg = 'File upload error.';
        if (isset($_FILES['pdf_file']['error'])) {
            switch ($_FILES['pdf_file']['error']) {
                case UPLOAD_ERR_INI_SIZE:
                case UPLOAD_ERR_FORM_SIZE:
                    $errorMsg = 'File exceeds maximum size (100MB).';
                    break;
                case UPLOAD_ERR_PARTIAL:
                    $errorMsg = 'File only partially uploaded.';
                    break;
                case UPLOAD_ERR_NO_FILE:
                    $errorMsg = 'No file uploaded.';
                    break;
                default:
                    $errorMsg = 'Unknown upload error.';
            }
        }
        header('Content-Type: application/json');
        echo json_encode(['error' => $errorMsg]);
        exit;
    }

    // Validate MIME type
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $_FILES['pdf_file']['tmp_name']);
    finfo_close($finfo);
    if ($mimeType !== 'application/pdf') {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Invalid file type. Only PDF files are allowed.']);
        exit;
    }

    // Validate size (extra check)
    if ($_FILES['pdf_file']['size'] > 100 * 1024 * 1024) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'File exceeds maximum size (100MB).']);
        exit;
    }

    // Password validation
    $password = $_POST['password'] ?? '';
    $confirm  = $_POST['confirm_password'] ?? '';
    if (empty($password) || strlen($password) < 4) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Password must be at least 4 characters.']);
        exit;
    }
    if ($password !== $confirm) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Passwords do not match.']);
        exit;
    }

    // Check qpdf availability
    $qpdfPath = trim(shell_exec('command -v qpdf'));
    if (empty($qpdfPath)) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'qpdf is not installed on the server. Please contact administrator.']);
        exit;
    }

    // Create temporary directory with random name
    $tempDir = sys_get_temp_dir() . '/pdf_protect_' . bin2hex(random_bytes(8));
    if (!mkdir($tempDir, 0700, true)) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Could not create temporary directory.']);
        exit;
    }

    $inputFile  = $tempDir . '/input.pdf';
    $outputFile = $tempDir . '/protected.pdf';

    // Move uploaded file
    if (!move_uploaded_file($_FILES['pdf_file']['tmp_name'], $inputFile)) {
        cleanup([$inputFile, $outputFile], $tempDir);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Failed to move uploaded file.']);
        exit;
    }

    // Build qpdf command (both passwords identical, 256-bit AES)
    $escapedPass = escapeshellarg($password);
    $escapedIn   = escapeshellarg($inputFile);
    $escapedOut  = escapeshellarg($outputFile);
    $command = "qpdf --encrypt $escapedPass $escapedPass 256 -- $escapedIn $escapedOut 2>&1";

    exec($command, $output, $returnCode);

    // Check success
    if ($returnCode !== 0 || !file_exists($outputFile) || filesize($outputFile) === 0) {
        cleanup([$inputFile, $outputFile], $tempDir);
        $errorMsg = 'Encryption failed. qpdf error: ' . implode("\n", $output);
        header('Content-Type: application/json');
        echo json_encode(['error' => $errorMsg]);
        exit;
    }

    // Delete input file (no longer needed)
    @unlink($inputFile);

    // Register shutdown to delete output file and temp dir after sending
    register_shutdown_function(function() use ($outputFile, $tempDir) {
        cleanup([$outputFile], $tempDir);
    });

    // Clear any output buffers to prevent corruption of the PDF
    while (ob_get_level()) {
        ob_end_clean();
    }

    // Send the protected PDF for download
    header('Content-Type: application/pdf');
    header('Content-Disposition: attachment; filename="protected.pdf"');
    header('Content-Length: ' . filesize($outputFile));
    header('Cache-Control: private, max-age=0, must-revalidate');
    header('Pragma: public');
    readfile($outputFile);
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PDF Password Protect</title>
    <style>
        /* CSS Variables for Light/Dark modes */
        :root {
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --text: #0f172a;
            --border: #e2e8f0;
            --primary: #2563eb;
            --primary-hover: #1d4ed8;
            --primary-light: #dbeafe;
            --shadow: 0 10px 25px rgba(0,0,0,0.08);
            --radius: 16px;
            --drop-border: #94a3b8;
            --drop-bg: #f1f5f9;
            --input-bg: #f8fafc;
            --input-border: #cbd5e1;
            --toast-bg: #1e293b;
            --toast-text: #f1f5f9;
            --spinner-color: #2563eb;
            --strength-weak: #ef4444;
            --strength-medium: #f59e0b;
            --strength-strong: #22c55e;
            --transition: 0.3s ease;
        }
        [data-theme="dark"] {
            --bg: #0f172a;
            --card-bg: #1e293b;
            --text: #f1f5f9;
            --border: #334155;
            --primary: #3b82f6;
            --primary-hover: #60a5fa;
            --primary-light: #1e3a5f;
            --shadow: 0 10px 25px rgba(0,0,0,0.4);
            --drop-border: #475569;
            --drop-bg: #1e293b;
            --input-bg: #334155;
            --input-border: #475569;
            --toast-bg: #e2e8f0;
            --toast-text: #0f172a;
            --spinner-color: #3b82f6;
        }

        /* Reset & base */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            transition: background var(--transition), color var(--transition);
        }
        .app-container {
            width: 100%;
            max-width: 640px;
            margin: 0 auto;
        }

        /* Card */
        .card {
            background: var(--card-bg);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            padding: 40px 32px;
            transition: background var(--transition), box-shadow var(--transition);
        }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 28px;
        }
        .card-header h1 {
            font-size: 1.8rem;
            font-weight: 700;
            letter-spacing: -0.02em;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .card-header h1 svg {
            width: 32px;
            height: 32px;
            fill: currentColor;
        }
        .theme-toggle {
            background: none;
            border: none;
            color: var(--text);
            cursor: pointer;
            padding: 8px;
            border-radius: 50%;
            width: 44px;
            height: 44px;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: background 0.2s;
            font-size: 1.4rem;
        }
        .theme-toggle:hover {
            background: var(--drop-bg);
        }

        /* Drop zone */
        .drop-zone {
            border: 2px dashed var(--drop-border);
            border-radius: 12px;
            padding: 48px 20px;
            text-align: center;
            cursor: pointer;
            background: var(--drop-bg);
            transition: border-color 0.3s, background 0.3s, transform 0.2s;
            position: relative;
        }
        .drop-zone.dragover {
            border-color: var(--primary);
            background: var(--primary-light);
            transform: scale(1.01);
        }
        .drop-zone .icon {
            font-size: 3.2rem;
            line-height: 1;
            margin-bottom: 12px;
            display: block;
            color: var(--primary);
        }
        .drop-zone .text {
            font-size: 1.1rem;
            font-weight: 500;
            margin-bottom: 6px;
        }
        .drop-zone .subtext {
            font-size: 0.9rem;
            color: var(--drop-border);
        }
        .drop-zone input[type="file"] {
            position: absolute;
            inset: 0;
            opacity: 0;
            cursor: pointer;
        }
        .file-name {
            margin-top: 14px;
            font-size: 0.95rem;
            font-weight: 500;
            color: var(--primary);
            display: none;
        }
        .file-name.show {
            display: block;
        }

        /* Form fields */
        .form-group {
            margin-top: 24px;
        }
        .form-group label {
            display: block;
            font-weight: 600;
            margin-bottom: 6px;
            font-size: 0.95rem;
        }
        .password-wrapper {
            position: relative;
        }
        .password-wrapper input {
            width: 100%;
            padding: 12px 44px 12px 14px;
            border: 1px solid var(--input-border);
            border-radius: 10px;
            background: var(--input-bg);
            color: var(--text);
            font-size: 1rem;
            transition: border-color 0.2s, box-shadow 0.2s;
            outline: none;
        }
        .password-wrapper input:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15);
        }
        .toggle-password {
            position: absolute;
            right: 12px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            cursor: pointer;
            color: var(--drop-border);
            padding: 4px;
            font-size: 1.2rem;
            line-height: 1;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .toggle-password:hover {
            color: var(--text);
        }

        /* Strength meter */
        .strength-meter {
            margin-top: 10px;
            height: 6px;
            background: var(--input-border);
            border-radius: 6px;
            overflow: hidden;
            transition: background 0.3s;
        }
        .strength-meter .bar {
            height: 100%;
            width: 0%;
            border-radius: 6px;
            transition: width 0.4s ease, background 0.3s;
            background: var(--strength-weak);
        }
        .strength-label {
            font-size: 0.8rem;
            margin-top: 4px;
            color: var(--drop-border);
            font-weight: 500;
        }

        /* Submit */
        .submit-btn {
            width: 100%;
            margin-top: 28px;
            padding: 14px;
            background: var(--primary);
            color: #fff;
            border: none;
            border-radius: 10px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s, transform 0.1s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }
        .submit-btn:hover:not(:disabled) {
            background: var(--primary-hover);
        }
        .submit-btn:active:not(:disabled) {
            transform: scale(0.98);
        }
        .submit-btn:disabled {
            opacity: 0.7;
            cursor: not-allowed;
        }

        /* Spinner (inline) */
        .spinner {
            display: none;
            width: 22px;
            height: 22px;
            border: 3px solid rgba(255,255,255,0.3);
            border-top-color: #fff;
            border-radius: 50%;
            animation: spin 0.7s linear infinite;
        }
        .submit-btn.loading .spinner {
            display: inline-block;
        }
        .submit-btn.loading .btn-text {
            display: none;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        /* Toast container */
        .toast-container {
            position: fixed;
            bottom: 30px;
            left: 50%;
            transform: translateX(-50%);
            z-index: 9999;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 10px;
            width: 90%;
            max-width: 460px;
            pointer-events: none;
        }
        .toast {
            padding: 14px 24px;
            border-radius: 12px;
            background: var(--toast-bg);
            color: var(--toast-text);
            box-shadow: 0 8px 20px rgba(0,0,0,0.2);
            font-weight: 500;
            font-size: 0.95rem;
            width: 100%;
            text-align: center;
            pointer-events: auto;
            animation: slideUp 0.4s ease forwards;
            transition: opacity 0.3s, transform 0.3s;
        }
        .toast.success {
            border-left: 6px solid #22c55e;
        }
        .toast.error {
            border-left: 6px solid #ef4444;
        }
        .toast.hide {
            opacity: 0;
            transform: translateY(20px);
            pointer-events: none;
        }
        @keyframes slideUp {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* Responsive */
        @media (max-width: 520px) {
            .card { padding: 24px 18px; }
            .card-header h1 { font-size: 1.4rem; }
            .drop-zone { padding: 32px 16px; }
            .drop-zone .icon { font-size: 2.6rem; }
        }
    </style>
</head>
<body>
    <div class="app-container">
        <div class="card">
            <!-- Header -->
            <div class="card-header">
                <h1>
                    <svg viewBox="0 0 24 24" width="32" height="32"><path d="M20 2H8c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-8.5 7.5c0 .83-.67 1.5-1.5 1.5H9v2H7.5V7H10c.83 0 1.5.67 1.5 1.5v1zm5 2c0 .83-.67 1.5-1.5 1.5h-2.5V7H15c.83 0 1.5.67 1.5 1.5v3zm-7.5-3H9v1.5H9.5V9.5zm5 3H15v1.5h-1.5V12.5zM6 18c0 .55.45 1 1 1h13v2H7c-1.66 0-3-1.34-3-3V4h2v14z"/></svg>
                    PDF Protect
                </h1>
                <button class="theme-toggle" id="themeToggle" aria-label="Toggle dark/light mode" title="Toggle theme">
                    <span id="themeIcon">🌙</span>
                </button>
            </div>

            <!-- Form -->
            <form id="uploadForm" enctype="multipart/form-data" method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">

                <!-- Drop Zone -->
                <div class="drop-zone" id="dropZone">
                    <span class="icon">📄</span>
                    <div class="text">Drag &amp; drop your PDF here</div>
                    <div class="subtext">or click to browse</div>
                    <input type="file" name="pdf_file" id="fileInput" accept=".pdf,application/pdf" required>
                </div>
                <div class="file-name" id="fileName"></div>

                <!-- Password -->
                <div class="form-group">
                    <label for="password">Password</label>
                    <div class="password-wrapper">
                        <input type="password" id="password" name="password" placeholder="Enter password" required minlength="4" autocomplete="new-password">
                        <button type="button" class="toggle-password" data-target="password" aria-label="Toggle password visibility">👁️</button>
                    </div>
                </div>

                <!-- Confirm Password -->
                <div class="form-group">
                    <label for="confirm_password">Confirm Password</label>
                    <div class="password-wrapper">
                        <input type="password" id="confirm_password" name="confirm_password" placeholder="Confirm password" required minlength="4" autocomplete="new-password">
                        <button type="button" class="toggle-password" data-target="confirm_password" aria-label="Toggle password visibility">👁️</button>
                    </div>
                </div>

                <!-- Strength Meter -->
                <div class="form-group">
                    <div class="strength-meter">
                        <div class="bar" id="strengthBar"></div>
                    </div>
                    <div class="strength-label" id="strengthLabel">Password strength</div>
                </div>

                <!-- Submit -->
                <button type="submit" class="submit-btn" id="submitBtn">
                    <span class="btn-text">🔒 Protect PDF</span>
                    <span class="spinner"></span>
                </button>
            </form>
        </div>
    </div>

    <!-- Toast Container -->
    <div class="toast-container" id="toastContainer"></div>

    <script>
        (function() {
            'use strict';

            // DOM refs
            const form = document.getElementById('uploadForm');
            const fileInput = document.getElementById('fileInput');
            const dropZone = document.getElementById('dropZone');
            const fileName = document.getElementById('fileName');
            const passwordInput = document.getElementById('password');
            const confirmInput = document.getElementById('confirm_password');
            const strengthBar = document.getElementById('strengthBar');
            const strengthLabel = document.getElementById('strengthLabel');
            const submitBtn = document.getElementById('submitBtn');
            const toastContainer = document.getElementById('toastContainer');
            const themeToggle = document.getElementById('themeToggle');
            const themeIcon = document.getElementById('themeIcon');

            // ─── Theme ──────────────────────────────────────────────
            let currentTheme = localStorage.getItem('theme') || 'light';
            applyTheme(currentTheme);

            themeToggle.addEventListener('click', () => {
                const next = currentTheme === 'light' ? 'dark' : 'light';
                applyTheme(next);
                localStorage.setItem('theme', next);
            });

            function applyTheme(theme) {
                currentTheme = theme;
                document.documentElement.setAttribute('data-theme', theme);
                themeIcon.textContent = theme === 'light' ? '🌙' : '☀️';
            }

            // ─── File drag & drop ──────────────────────────────────
            let selectedFile = null;

            dropZone.addEventListener('dragover', (e) => {
                e.preventDefault();
                dropZone.classList.add('dragover');
            });
            dropZone.addEventListener('dragleave', (e) => {
                e.preventDefault();
                dropZone.classList.remove('dragover');
            });
            dropZone.addEventListener('drop', (e) => {
                e.preventDefault();
                dropZone.classList.remove('dragover');
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    handleFile(files[0]);
                }
            });

            fileInput.addEventListener('change', () => {
                if (fileInput.files.length > 0) {
                    handleFile(fileInput.files[0]);
                }
            });

            function handleFile(file) {
                // Validate type
                if (file.type !== 'application/pdf' && !file.name.toLowerCase().endsWith('.pdf')) {
                    showToast('Please select a valid PDF file.', 'error');
                    fileInput.value = '';
                    fileName.classList.remove('show');
                    selectedFile = null;
                    return;
                }
                if (file.size > 100 * 1024 * 1024) {
                    showToast('File size exceeds 100MB limit.', 'error');
                    fileInput.value = '';
                    fileName.classList.remove('show');
                    selectedFile = null;
                    return;
                }
                selectedFile = file;
                fileName.textContent = `📎 ${file.name}`;
                fileName.classList.add('show');
            }

            // ─── Password toggle ──────────────────────────────────
            document.querySelectorAll('.toggle-password').forEach(btn => {
                btn.addEventListener('click', function() {
                    const targetId = this.dataset.target;
                    const input = document.getElementById(targetId);
                    if (!input) return;
                    const isPassword = input.type === 'password';
                    input.type = isPassword ? 'text' : 'password';
                    this.textContent = isPassword ? '🙈' : '👁️';
                });
            });

            // ─── Password strength meter ──────────────────────────
            passwordInput.addEventListener('input', updateStrength);
            function updateStrength() {
                const pwd = passwordInput.value;
                let score = 0;
                if (pwd.length >= 4) score += 1;
                if (pwd.length >= 8) score += 1;
                if (/[a-z]/.test(pwd) && /[A-Z]/.test(pwd)) score += 1;
                if (/\d/.test(pwd)) score += 1;
                if (/[^a-zA-Z0-9]/.test(pwd)) score += 1;

                let width = 0;
                let color = '#ef4444';
                let label = 'Weak';
                if (pwd.length === 0) {
                    width = 0;
                    label = 'Password strength';
                } else if (score <= 1) {
                    width = 20;
                    color = '#ef4444';
                    label = 'Weak';
                } else if (score <= 2) {
                    width = 40;
                    color = '#f59e0b';
                    label = 'Fair';
                } else if (score <= 3) {
                    width = 60;
                    color = '#f59e0b';
                    label = 'Good';
                } else if (score <= 4) {
                    width = 80;
                    color = '#22c55e';
                    label = 'Strong';
                } else {
                    width = 100;
                    color = '#22c55e';
                    label = 'Very Strong';
                }
                strengthBar.style.width = width + '%';
                strengthBar.style.background = color;
                strengthLabel.textContent = label;
            }

            // ─── Form submission (AJAX) ───────────────────────────
            form.addEventListener('submit', async (e) => {
                e.preventDefault();

                // Basic validation
                if (!selectedFile) {
                    showToast('Please select a PDF file.', 'error');
                    return;
                }
                const pwd = passwordInput.value;
                const confirm = confirmInput.value;
                if (pwd.length < 4) {
                    showToast('Password must be at least 4 characters.', 'error');
                    return;
                }
                if (pwd !== confirm) {
                    showToast('Passwords do not match.', 'error');
                    return;
                }

                // Prepare FormData
                const formData = new FormData(form);
                // If fileInput was cleared somehow, re-add
                if (fileInput.files.length === 0 && selectedFile) {
                    const dataTransfer = new DataTransfer();
                    dataTransfer.items.add(selectedFile);
                    fileInput.files = dataTransfer.files;
                }

                // Disable button, show loader
                submitBtn.disabled = true;
                submitBtn.classList.add('loading');

                try {
                    const response = await fetch('index.php', {
                        method: 'POST',
                        body: formData
                    });

                    const contentType = response.headers.get('content-type') || '';
                    if (contentType.includes('application/pdf')) {
                        // Success: download the PDF
                        const blob = await response.blob();
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = 'protected.pdf';
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                        URL.revokeObjectURL(url);
                        showToast('PDF protected successfully! Download started.', 'success');
                        // Reset form
                        form.reset();
                        fileName.classList.remove('show');
                        selectedFile = null;
                        fileInput.value = '';
                        strengthBar.style.width = '0%';
                        strengthLabel.textContent = 'Password strength';
                    } else {
                        // JSON error
                        const text = await response.text();
                        let errorMsg = 'An error occurred.';
                        try {
                            const json = JSON.parse(text);
                            if (json.error) errorMsg = json.error;
                        } catch (_) {
                            errorMsg = text || 'Unknown error.';
                        }
                        showToast(errorMsg, 'error');
                    }
                } catch (err) {
                    showToast('Network error. Please try again.', 'error');
                    console.error(err);
                } finally {
                    submitBtn.disabled = false;
                    submitBtn.classList.remove('loading');
                }
            });

            // ─── Toast system ──────────────────────────────────────
            function showToast(message, type = 'success') {
                const toast = document.createElement('div');
                toast.className = `toast ${type}`;
                toast.textContent = message;
                toastContainer.appendChild(toast);

                // Auto-hide after 5 seconds
                setTimeout(() => {
                    toast.classList.add('hide');
                    setTimeout(() => {
                        if (toast.parentNode) toast.remove();
                    }, 400);
                }, 5000);
            }

            // ─── Keyboard accessibility ────────────────────────────
            // Drop zone click triggers file input (already via label/input)
            // Password toggle buttons are accessible via Enter/Space (button elements)
            // Theme toggle is a button.

            // ─── Init ──────────────────────────────────────────────
            updateStrength();
        })();
    </script>
</body>
</html>
