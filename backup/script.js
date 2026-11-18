
// SecureShare API Configuration
const API_BASE_URL = window.API_BASE_URL || "";

const fileInput = document.getElementById("fileInput");
const fileInfo = document.getElementById("fileInfo");
const generateBtn = document.getElementById("generateBtn");
const passwordEnabled = document.getElementById("passwordEnabled");
const sharePassword = document.getElementById("sharePassword");
const result = document.getElementById("result");
const shareLink = document.getElementById("shareLink");
const copyBtn = document.getElementById("copyBtn");

let selectedFile = null;

// Display selected file
fileInput.addEventListener("change", function () {
    selectedFile = fileInput.files[0];

    if (selectedFile) {
        fileInfo.textContent =
            `Selected: ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(2)} KB)`;

        result.hidden = true;
    }
});

// Show or hide password field
passwordEnabled.addEventListener("change", function () {
    sharePassword.hidden = !passwordEnabled.checked;
});

sharePassword.hidden = !passwordEnabled.checked;

// Generate secure sharing link
generateBtn.addEventListener("click", async function () {

    if (!selectedFile) {
        alert("Please select a file first!");
        return;
    }

    if (passwordEnabled.checked && !sharePassword.value.trim()) {
        alert("Please enter a sharing password!");
        return;
    }

    const expirySelect = document.getElementById("expiry");
    const downloadsSelect = document.getElementById("downloads");

    const expiry =
        expirySelect.options[expirySelect.selectedIndex].text.trim();

    const downloadChoice =
        downloadsSelect.options[downloadsSelect.selectedIndex].text.trim();

    let maxDownloads;

    if (/unlimited|no limit/i.test(downloadChoice)) {
        maxDownloads = "unlimited";
    } else {
        const match = downloadChoice.match(/\d+/);

        if (!match) {
            alert("Please select a valid download limit.");
            return;
        }

        maxDownloads = match[0];
    }

    const MAX_FILE_SIZE = 16 * 1024 * 1024;

    if (selectedFile.size > MAX_FILE_SIZE) {
        alert("Selected file exceeds the 16 MB maximum size limit.");
        return;
    }

    generateBtn.disabled = true;

    try {
        let response;
        let data;

        if (!API_BASE_URL) {

            // LOCAL UPLOAD THROUGH FLASK
            generateBtn.textContent = "Uploading file...";

            const formData = new FormData();

            formData.append("file", selectedFile);
            formData.append("expiry", expiry);
            formData.append("max_downloads", maxDownloads);
            formData.append(
                "password",
                passwordEnabled.checked
                    ? sharePassword.value.trim()
                    : ""
            );

            response = await fetch("/api/share", {
                method: "POST",
                body: formData
            });

            data = await response.json();

        } else {

            // AWS CLOUD UPLOAD USING PRESIGNED URL
            generateBtn.textContent = "Initializing upload...";

            const initPayload = {
                filename: selectedFile.name,
                file_size: selectedFile.size,
                content_type: selectedFile.type || "application/octet-stream",
                expiry: expiry,
                max_downloads: maxDownloads,
                password: passwordEnabled.checked
                    ? sharePassword.value.trim()
                    : ""
            };

            response = await fetch(`${API_BASE_URL}/api/share`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(initPayload)
            });

            data = await response.json();

            if (response.ok && data.success && data.upload_url) {

                generateBtn.textContent = "Uploading to S3...";

                const uploadResponse = await fetch(data.upload_url, {
                    method: "PUT",
                    headers: {
                        "Content-Type": selectedFile.type ||
                            "application/octet-stream"
                    },
                    body: selectedFile
                });

                if (!uploadResponse.ok) {
                    throw new Error("S3 upload failed.");
                }
            }
        }

        if (!response.ok || !data.success) {
            throw new Error(
                data.error || data.message || "Upload failed"
            );
        }

        const actualLink =
            data.share_url || data.share_link || data.url;

        if (!actualLink) {
            throw new Error("Sharing link was not returned.");
        }

        shareLink.value = actualLink;

        document.getElementById("linkDetails").textContent =
            `File: ${data.filename || selectedFile.name} | ` +
            `Expires in: ${expiry} | ` +
            `Maximum downloads: ${maxDownloads}`;

        result.hidden = false;

        alert("File uploaded successfully!");

    } catch (error) {

        console.error("Upload error:", error);
        alert("Upload failed: " + error.message);

    } finally {

        generateBtn.disabled = false;
        generateBtn.textContent = "Generate Secure Link";

    }
});

// Copy sharing link
copyBtn.addEventListener("click", async function () {

    if (!shareLink.value) {
        alert("No sharing link available!");
        return;
    }

    try {
        await navigator.clipboard.writeText(shareLink.value);

        copyBtn.textContent = "Copied!";

        setTimeout(function () {
            copyBtn.textContent = "Copy Link";
        }, 2000);

    } catch (error) {
        shareLink.select();
        alert("Copy the selected link manually.");
    }

});
