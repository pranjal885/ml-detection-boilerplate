// CloudVault Main Interactive Logic

document.addEventListener('DOMContentLoaded', () => {
    // 1. Auto-dismiss alerts/toasts after 4 seconds
    const flashAlerts = document.querySelectorAll('.alert-dismissible');
    flashAlerts.forEach(alert => {
        setTimeout(() => {
            // Using Bootstrap's JS API to fade out alerts
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            if (bsAlert) {
                bsAlert.close();
            }
        }, 4000);
    });

    // 2. Drag & Drop File Upload Handler
    const uploadZone = document.getElementById('uploadZone');
    const fileInput = document.getElementById('fileInput');
    const uploadForm = document.getElementById('uploadForm');

    if (uploadZone && fileInput && uploadForm) {
        // Trigger click event on file input when box is clicked
        uploadZone.addEventListener('click', () => {
            fileInput.click();
        });

        // Automatically submit the form on file selection
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                showUploadIndicator();
                uploadForm.submit();
            }
        });

        // Prevent default drag & drop behaviors
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            uploadZone.addEventListener(eventName, preventDefaults, false);
            document.body.addEventListener(eventName, preventDefaults, false);
        });

        // Highlight upload zone when dragging over
        ['dragenter', 'dragover'].forEach(eventName => {
            uploadZone.addEventListener(eventName, () => {
                uploadZone.classList.add('dragover');
            }, false);
        });

        // Remove highlights when dragging away
        ['dragleave', 'drop'].forEach(eventName => {
            uploadZone.addEventListener(eventName, () => {
                uploadZone.classList.remove('dragover');
            }, false);
        });

        // Handle file drop
        uploadZone.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const droppedFiles = dt.files;

            if (droppedFiles.length > 0) {
                fileInput.files = droppedFiles;
                showUploadIndicator();
                uploadForm.submit();
            }
        }, false);
    }

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    function showUploadIndicator() {
        const textElement = uploadZone.querySelector('p');
        const iconElement = uploadZone.querySelector('.upload-icon');
        
        if (textElement && iconElement) {
            iconElement.innerHTML = '🔄';
            iconElement.classList.add('fa-spin'); // fallback spin class
            textElement.innerText = "Processing upload, please wait...";
            uploadZone.style.pointerEvents = 'none';
            uploadZone.style.opacity = '0.75';
        }
    }
});
