// SecureShare API Configuration
// Loaded from config.js or defaults to window.API_BASE_URL
const API_BASE_URL = (window.API_BASE_URL || "").replace(/\/+$/, "");

// DOM Elements
const fileInput = document.getElementById("fileInput");
const dropArea = document.getElementById("dropArea");
const fileInfo = document.getElementById("fileInfo");
const fileName = document.getElementById("fileName");
const fileSize = document.getElementById("fileSize");
const removeFileBtn = document.getElementById("removeFileBtn");
const generateBtn = document.getElementById("generateBtn");
const passwordEnabled = document.getElementById("passwordEnabled");
const sharePassword = document.getElementById("sharePassword");
const result = document.getElementById("result");
const shareLink = document.getElementById("shareLink");
const copyBtn = document.getElementById("copyBtn");
const openBtn = document.getElementById("openBtn");
const linkDetails = document.getElementById("linkDetails");
const statusAlert = document.getElementById("statusAlert");
const progressContainer = document.getElementById("progressContainer");
const progressBar = document.getElementById("progressBar");
const progressPercent = document.getElementById("progressPercent");
const progressStatus = document.getElementById("progressStatus");

let selectedFile = null;

// Helper: Format bytes to human readable string
function formatBytes(bytes) {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

// Helper: Show inline alert
function showAlert(message, type = "error") {
    if (!statusAlert) return;
    statusAlert.textContent = message;
    statusAlert.className = `alert-box alert-${type}`;
    statusAlert.hidden = false;
    statusAlert.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function clearAlert() {
    if (statusAlert) {
        statusAlert.hidden = true;
        statusAlert.textContent = "";
    }
}

// Helper: Update selected file
function setSelectedFile(file) {
    clearAlert();
    const MAX_FILE_SIZE = 16 * 1024 * 1024; // 16 MB

    if (!file) {
        selectedFile = null;
        if (fileInfo) fileInfo.hidden = true;
        if (dropArea) dropArea.hidden = false;
        return;
    }

    if (file.size > MAX_FILE_SIZE) {
        showAlert(`File "${file.name}" (${formatBytes(file.size)}) exceeds the 16 MB maximum size limit.`, "error");
        fileInput.value = "";
        return;
    }

    selectedFile = file;
    if (fileName) fileName.textContent = file.name;
    if (fileSize) fileSize.textContent = formatBytes(file.size);
    if (fileInfo) fileInfo.hidden = false;
    if (dropArea) dropArea.hidden = true;
    if (result) result.hidden = true;
}

// File Input change
fileInput.addEventListener("change", function () {
    if (fileInput.files && fileInput.files[0]) {
        setSelectedFile(fileInput.files[0]);
    }
});

// Remove file button
if (removeFileBtn) {
    removeFileBtn.addEventListener("click", function (e) {
        e.preventDefault();
        e.stopPropagation();
        fileInput.value = "";
        setSelectedFile(null);
    });
}

// Drag & Drop handlers
if (dropArea) {
    ["dragenter", "dragover"].forEach(eventName => {
        dropArea.addEventListener(eventName, function (e) {
            e.preventDefault();
            e.stopPropagation();
            dropArea.classList.add("dragover");
        }, false);
    });

    ["dragleave", "drop"].forEach(eventName => {
        dropArea.addEventListener(eventName, function (e) {
            e.preventDefault();
            e.stopPropagation();
            dropArea.classList.remove("dragover");
        }, false);
    });

    dropArea.addEventListener("drop", function (e) {
        const dt = e.dataTransfer;
        if (dt && dt.files && dt.files[0]) {
            fileInput.files = dt.files;
            setSelectedFile(dt.files[0]);
        }
    }, false);
}

// Toggle password input visibility
passwordEnabled.addEventListener("change", function () {
    sharePassword.hidden = !passwordEnabled.checked;
    if (passwordEnabled.checked) {
        sharePassword.focus();
    } else {
        sharePassword.value = "";
    }
});
sharePassword.hidden = !passwordEnabled.checked;

// Upload file directly to S3 via Presigned PUT with live progress tracking
function uploadToS3(uploadUrl, file) {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open("PUT", uploadUrl, true);
        xhr.setRequestHeader("Content-Type", file.type || "application/octet-stream");

        if (progressContainer) progressContainer.hidden = false;

        xhr.upload.onprogress = function (e) {
            if (e.lengthComputable) {
                const percent = Math.round((e.loaded / e.total) * 100);
                if (progressBar) progressBar.style.width = percent + "%";
                if (progressPercent) progressPercent.textContent = percent + "%";
                if (progressStatus) progressStatus.textContent = `Uploading directly to S3: ${percent}%...`;
            }
        };

        xhr.onload = function () {
            if (xhr.status >= 200 && xhr.status < 300) {
                if (progressStatus) progressStatus.textContent = "Upload complete! Finalizing...";
                resolve();
            } else {
                reject(new Error(`S3 upload failed with status ${xhr.status}: ${xhr.statusText}`));
            }
        };

        xhr.onerror = function () {
            reject(new Error("Network error during direct S3 upload. Check CORS or network connection."));
        };

        xhr.send(file);
    });
}

// Generate secure sharing link
generateBtn.addEventListener("click", async function () {
    clearAlert();

    if (!selectedFile) {
        showAlert("Please select a file to upload first.", "error");
        return;
    }

    if (passwordEnabled.checked && !sharePassword.value.trim()) {
        showAlert("Please enter a password or uncheck 'Require password for access'.", "error");
        sharePassword.focus();
        return;
    }

    const expirySelect = document.getElementById("expiry");
    const downloadsSelect = document.getElementById("downloads");

    const expiry = expirySelect.options[expirySelect.selectedIndex].text.trim();
    const downloadChoice = downloadsSelect.options[downloadsSelect.selectedIndex].text.trim();

    let maxDownloads;
    if (/unlimited|no limit/i.test(downloadChoice)) {
        maxDownloads = "unlimited";
    } else {
        const match = downloadChoice.match(/\d+/);
        if (!match) {
            showAlert("Please select a valid download limit.", "error");
            return;
        }
        maxDownloads = match[0];
    }

    // UI Loading state
    generateBtn.disabled = true;
    generateBtn.textContent = "Preparing upload...";
    if (result) result.hidden = true;

    try {
        let actualLink = null;
        let returnedFilename = selectedFile.name;

        if (API_BASE_URL) {
            // =========================================================
            // AWS CLOUD UPLOAD FLOW (Presigned S3 Direct Upload)
            // =========================================================
            if (progressStatus) progressStatus.textContent = "Initializing secure cloud storage...";
            if (progressPercent) progressPercent.textContent = "0%";
            if (progressBar) progressBar.style.width = "0%";

            const initPayload = {
                filename: selectedFile.name,
                file_size: selectedFile.size,
                content_type: selectedFile.type || "application/octet-stream",
                expiry: expiry,
                max_downloads: maxDownloads,
                password: passwordEnabled.checked ? sharePassword.value.trim() : ""
            };

            const response = await fetch(`${API_BASE_URL}/api/share`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(initPayload)
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                throw new Error(data.error || data.message || "Upload initialization failed on AWS.");
            }

            if (!data.upload_url) {
                throw new Error("AWS backend did not provide a presigned S3 upload URL.");
            }

            // Upload binary directly to private S3 bucket
            await uploadToS3(data.upload_url, selectedFile);

            actualLink = data.share_url || data.share_link || data.url;
            returnedFilename = data.filename || selectedFile.name;

        } else {
            // =========================================================
            // LOCAL FALLBACK UPLOAD (Local Flask backend)
            // =========================================================
            generateBtn.textContent = "Uploading to local server...";

            const formData = new FormData();
            formData.append("file", selectedFile);
            formData.append("expiry", expiry);
            formData.append("max_downloads", maxDownloads);
            formData.append("password", passwordEnabled.checked ? sharePassword.value.trim() : "");

            const response = await fetch("/api/share", {
                method: "POST",
                body: formData
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                throw new Error(data.error || data.message || "Local upload failed.");
            }

            actualLink = data.share_url || data.share_link || data.url;
            returnedFilename = data.filename || selectedFile.name;
        }

        if (!actualLink) {
            throw new Error("Sharing link was not returned by the server.");
        }

        // Display results
        shareLink.value = actualLink;
        linkDetails.textContent = `File: ${returnedFilename} | Expires in: ${expiry} | Maximum downloads: ${maxDownloads === "unlimited" ? "Unlimited" : maxDownloads}`;

        if (result) result.hidden = false;
        showAlert("Document uploaded successfully! Your secure sharing link is ready.", "success");

    } catch (error) {
        console.error("Upload error:", error);
        showAlert(`Upload error: ${error.message}`, "error");
    } finally {
        if (progressContainer) progressContainer.hidden = true;
        generateBtn.disabled = false;
        generateBtn.textContent = "Generate Secure Link";
    }
});

// Copy link button
if (copyBtn) {
    copyBtn.addEventListener("click", async function () {
        if (!shareLink.value) {
            showAlert("No sharing link available to copy.", "error");
            return;
        }

        try {
            await navigator.clipboard.writeText(shareLink.value);
            copyBtn.textContent = "Copied! ✓";
            setTimeout(() => {
                copyBtn.textContent = "Copy";
            }, 2000);
        } catch (err) {
            shareLink.select();
            document.execCommand("copy");
            copyBtn.textContent = "Copied! ✓";
            setTimeout(() => {
                copyBtn.textContent = "Copy";
            }, 2000);
        }
    });
}

// Open link in new tab button
if (openBtn) {
    openBtn.addEventListener("click", function () {
        if (shareLink && shareLink.value) {
            window.open(shareLink.value, "_blank");
        }
    });
}
