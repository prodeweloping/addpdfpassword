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
    <title>PDF Password Protect - ProToolss</title>
    <!-- Favicon -->
    <link rel="icon" type="image/png" href="https://i.ibb.co/FkJPMZ8r/Chat-GPT-Image-Jun-18-2026-07-58-22-AM.png">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <style>
        /* ========== RESET & BASE ========== */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f8fafc;
            color: #0f172a;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            padding-top: 75px; /* space for fixed navbar */
        }

        /* ========== NAVBAR (from user) ========== */
        .new-nav {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            z-index: 999;
            background: rgba(255,255,255,0.98);
            backdrop-filter: blur(4px);
            box-shadow: 0 4px 20px rgba(0,0,0,.05);
            padding: 12px 25px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .logo {
            font-size: 32px;
            font-weight: 800;
        }
        .logo-blue {
            color: #007BFF;
        }
        .logo-orange {
            color: #FF6F00;
        }

        .home-btn {
            background: none;
            border: none;
            cursor: pointer;
            display: flex;
            flex-direction: column;
            align-items: center;
            text-decoration: none;
        }
        .home-btn .lines {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }
        .home-btn .lines span {
            width: 24px;
            height: 3px;
            background: #1e293b;
            border-radius: 10px;
        }
        .home-btn .label {
            font-size: 10px;
            font-weight: 700;
            color: #1e293b;
            margin-top: 3px;
            text-transform: uppercase;
        }

        /* ========== MAIN CONTENT ========== */
        main {
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 30px 20px;
        }

        .app-container {
            width: 100%;
            max-width: 640px;
            margin: 0 auto;
        }

        /* ========== CARD (PDF TOOL) ========== */
        .card {
            background: #ffffff;
            border-radius: 16px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.08);
            padding: 40px 32px;
            transition: box-shadow 0.3s ease;
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
            color: #0f172a;
        }
        .card-header h1 i {
            color: #2563eb;
        }

        /* ========== DROP ZONE ========== */
        .drop-zone {
            border: 2px dashed #94a3b8;
            border-radius: 12px;
            padding: 48px 20px;
            text-align: center;
            cursor: pointer;
            background: #f1f5f9;
            transition: border-color 0.3s, background 0.3s, transform 0.2s;
            position: relative;
        }
        .drop-zone.dragover {
            border-color: #2563eb;
            background: #dbeafe;
            transform: scale(1.01);
        }
        .drop-zone .icon {
            font-size: 3.2rem;
            line-height: 1;
            margin-bottom: 12px;
            display: block;
            color: #2563eb;
        }
        .drop-zone .text {
            font-size: 1.1rem;
            font-weight: 500;
            margin-bottom: 6px;
        }
        .drop-zone .subtext {
            font-size: 0.9rem;
            color: #94a3b8;
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
            color: #2563eb;
            display: none;
        }
        .file-name.show {
            display: block;
        }

        /* ========== FORM FIELDS ========== */
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
            border: 1px solid #cbd5e1;
            border-radius: 10px;
            background: #f8fafc;
            color: #0f172a;
            font-size: 1rem;
            transition: border-color 0.2s, box-shadow 0.2s;
            outline: none;
        }
        .password-wrapper input:focus {
            border-color: #2563eb;
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
            color: #94a3b8;
            padding: 4px;
            font-size: 1.2rem;
            line-height: 1;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .toggle-password:hover {
            color: #0f172a;
        }

        /* ========== STRENGTH METER ========== */
        .strength-meter {
            margin-top: 10px;
            height: 6px;
            background: #cbd5e1;
            border-radius: 6px;
            overflow: hidden;
        }
        .strength-meter .bar {
            height: 100%;
            width: 0%;
            border-radius: 6px;
            transition: width 0.4s ease, background 0.3s;
            background: #ef4444;
        }
        .strength-label {
            font-size: 0.8rem;
            margin-top: 4px;
            color: #94a3b8;
            font-weight: 500;
        }

        /* ========== SUBMIT BUTTON ========== */
        .submit-btn {
            width: 100%;
            margin-top: 28px;
            padding: 14px;
            background: #2563eb;
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
            background: #1d4ed8;
        }
        .submit-btn:active:not(:disabled) {
            transform: scale(0.98);
        }
        .submit-btn:disabled {
            opacity: 0.7;
            cursor: not-allowed;
        }

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

        /* ========== TOAST ========== */
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
            background: #1e293b;
            color: #f1f5f9;
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

        /* ========== FOOTER (from user) ========== */
        footer {
            background: #0b1426;
            color: white;
            height: 70px;
            display: flex;
            justify-content: center;
            align-items: center;
            margin-top: auto;
        }
        .design-footer {
            color: #94a3b8;
        }
        .highlight {
            color: #facc15;
            font-weight: 700;
            text-decoration: underline;
        }
        .highlight:hover {
            color: #fde047;
        }

        @media (max-width: 768px) {
            footer {
                position: fixed;
                left: 0;
                right: 0;
                bottom: 0;
                height: 60px;
            }
            body {
                padding-bottom: 70px; /* space for fixed footer on mobile */
            }
        }

        /* ========== RESPONSIVE ========== */
        @media (max-width: 520px) {
            .card { padding: 24px 18px; }
            .card-header h1 { font-size: 1.4rem; }
            .drop-zone { padding: 32px 16px; }
            .drop-zone .icon { font-size: 2.6rem; }
            .logo { font-size: 26px; }
        }
    </style>
</head>
<body>

    <!-- ========== NAVBAR ========== -->
    <nav class="new-nav">
        <div class="logo">
            <span class="logo-blue">Pro</span>
            <span class="logo-orange">Toolss</span>
        </div>
        <button id="homeBtn" class="home-btn" aria-label="Home">
            <div class="lines">
                <span></span>
                <span></span>
                <span></span>
            </div>
            <span class="label">Home</span>
        </button>
    </nav>

    <!-- ========== MAIN CONTENT ========== -->
    <main>
        <div class="app-container">
            <div class="card">
                <div class="card-header">
                    <h1>
                        <i class="fas fa-file-pdf" style="color: #2563eb;"></i>
                        PDF Protect
                    </h1>
                    <!-- removed theme toggle -->
                </div>

                <!-- Form -->
                <form id="uploadForm" enctype="multipart/form-data" method="POST">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">

                    <!-- Drop Zone -->
                    <div class="drop-zone" id="dropZone">
                        <span class="icon"><i class="fas fa-cloud-upload-alt"></i></span>
                        <div class="text">Drag &amp; drop your PDF here</div>
                        <div class="subtext">or click to browse</div>
                        <input type="file" name="pdf_file" id="fileInput" accept=".pdf,application/pdf" required>
                    </div>
                    <div class="file-name" id="fileName"></div>

                    <!-- Password -->
                    <div class="form-group">
                        <label for="password"><i class="fas fa-lock"></i> Password</label>
                        <div class="password-wrapper">
                            <input type="password" id="password" name="password" placeholder="Enter password" required minlength="4" autocomplete="new-password">
                            <button type="button" class="toggle-password" data-target="password" aria-label="Toggle password visibility">
                                <i class="fas fa-eye"></i>
                            </button>
                        </div>
                    </div>

                    <!-- Confirm Password -->
                    <div class="form-group">
                        <label for="confirm_password"><i class="fas fa-check-circle"></i> Confirm Password</label>
                        <div class="password-wrapper">
                            <input type="password" id="confirm_password" name="confirm_password" placeholder="Confirm password" required minlength="4" autocomplete="new-password">
                            <button type="button" class="toggle-password" data-target="confirm_password" aria-label="Toggle password visibility">
                                <i class="fas fa-eye"></i>
                            </button>
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
                        <span class="btn-text"><i class="fas fa-shield-alt"></i> Protect PDF</span>
                        <span class="spinner"></span>
                    </button>
                </form>
            </div>
        </div>
    </main>

    <!-- ========== FOOTER ========== -->
    <footer>
        <div class="design-footer">
            Design by
            <a href="https://www.protoolss.online" target="_blank" class="highlight">
                Pro Toolss
            </a>
        </div>
    </footer>

    <!-- Toast Container -->
    <div class="toast-container" id="toastContainer"></div>

    <!-- ========== JAVASCRIPT ========== -->
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
            const homeBtn = document.getElementById('homeBtn');

            // Home button
            homeBtn.addEventListener('click', function() {
                window.location.href = 'https://www.protoolss.online';
            });

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
                fileName.textContent = '📎 ' + file.name;
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
                    const icon = this.querySelector('i');
                    if (icon) {
                        icon.className = isPassword ? 'fas fa-eye-slash' : 'fas fa-eye';
                    }
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
                // Ensure file is attached even if dropped
                if (fileInput.files.length === 0 && selectedFile) {
                    const dataTransfer = new DataTransfer();
                    dataTransfer.items.add(selectedFile);
                    fileInput.files = dataTransfer.files;
                }

                submitBtn.disabled = true;
                submitBtn.classList.add('loading');

                try {
                    const response = await fetch('index.php', {
                        method: 'POST',
                        body: formData
                    });

                    const contentType = response.headers.get('content-type') || '';
                    if (contentType.includes('application/pdf')) {
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
                setTimeout(() => {
                    toast.classList.add('hide');
                    setTimeout(() => {
                        if (toast.parentNode) toast.remove();
                    }, 400);
                }, 5000);
            }

            // ─── Init ──────────────────────────────────────────────
            updateStrength();
        })();
    </script>
</body>
</html>
