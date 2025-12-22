// Main JavaScript functionality for the homepage

document.addEventListener('DOMContentLoaded', function() {
    // File upload handling
    const uploadZone = document.getElementById('uploadZone');
    const fileInput = document.getElementById('fileInput');
    const fileInfo = document.getElementById('fileInfo');
    const fileName = document.getElementById('fileName');
    const analyzeBtn = document.getElementById('analyzeBtn');

    // Drag and drop functionality
    if (uploadZone) {
        uploadZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadZone.classList.add('drag-over');
        });

        uploadZone.addEventListener('dragleave', () => {
            uploadZone.classList.remove('drag-over');
        });

        uploadZone.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadZone.classList.remove('drag-over');
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                handleFile(files[0]);
            }
        });

        // Click to upload
        uploadZone.addEventListener('click', () => {
            fileInput.click();
        });
    }

    // File input change
    if (fileInput) {
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                handleFile(e.target.files[0]);
            }
        });
    }

    function handleFile(file) {
        const allowedTypes = ['.eml', '.msg', '.txt'];
        const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
        
        if (allowedTypes.includes(fileExtension)) {
            // Check file size (10MB limit)
            if (file.size > 10 * 1024 * 1024) {
                alert('File size exceeds 10MB limit. Please select a smaller file.');
                return;
            }
            
            fileName.textContent = file.name;
            fileInfo.classList.remove('d-none');
            analyzeBtn.disabled = false;
            
            // Add file size info
            const fileSize = formatFileSize(file.size);
            fileName.innerHTML = `${file.name} <small class="text-muted">(${fileSize})</small>`;
        } else {
            alert('Please select a valid email file (.eml, .msg, or .txt)');
            fileInput.value = '';
        }
    }

    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function clearFile() {
        fileInput.value = '';
        fileInfo.classList.add('d-none');
        analyzeBtn.disabled = true;
    }

    // Make clearFile available globally
    window.clearFile = clearFile;

    // Form submission validation
    const uploadForm = document.getElementById('uploadForm');
    if (uploadForm) {
        uploadForm.addEventListener('submit', (e) => {
            if (!fileInput.files.length) {
                e.preventDefault();
                alert('Please select a file to analyze.');
            }
        });
    }

    // Text form validation
    const textForm = document.querySelector('#textForm form');
    if (textForm) {
        textForm.addEventListener('submit', (e) => {
            const emailText = document.getElementById('emailText').value.trim();
            if (!emailText) {
                e.preventDefault();
                alert('Please paste email source code in the text area.');
            }
        });
    }

    // Auto-dismiss flash messages
    const flashMessages = document.querySelectorAll('.alert');
    flashMessages.forEach(alert => {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });

    // Smooth scrolling for navigation links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Add loading state to buttons
    const buttons = document.querySelectorAll('button[type="submit"]');
    buttons.forEach(button => {
        button.addEventListener('click', function() {
            // Add a small delay to show loading state
            this.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Analyzing...';
            this.disabled = true;
            
            // Re-enable after form submission (fallback)
            setTimeout(() => {
                if (this.disabled) {
                    this.disabled = false;
                    this.innerHTML = this.innerHTML.replace('Analyzing...', 'Analyze Email');
                }
            }, 10000);
        });
    });

    // Feature cards animation on scroll
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('fade-in');
            }
        });
    }, observerOptions);

    document.querySelectorAll('.feature-card').forEach(card => {
        observer.observe(card);
    });

    // Accordion enhancement
    const accordionButtons = document.querySelectorAll('.accordion-button');
    accordionButtons.forEach(button => {
        button.addEventListener('click', function() {
            // Add a subtle animation when opening/closing
            const content = this.parentElement.nextElementSibling;
            if (content) {
                content.style.transition = 'all 0.3s ease';
            }
        });
    });
});