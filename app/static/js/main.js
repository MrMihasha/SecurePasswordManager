// Auto-dismiss alerts after 5 seconds
document.addEventListener('DOMContentLoaded', function() {
    const alerts = document.querySelectorAll('.alert:not(.alert-info):not(.alert-warning)');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });
});

// Confirm delete actions
document.addEventListener('DOMContentLoaded', function() {
    const deleteLinks = document.querySelectorAll('a[href*="/delete/"]');
    deleteLinks.forEach(function(link) {
        if (!link.closest('form')) {
            link.addEventListener('click', function(e) {
                // Only confirm on direct delete links, not on delete confirmation page
                if (!window.location.pathname.includes('/delete/')) {
                    const confirmed = confirm('Are you sure you want to delete this password?');
                    if (!confirmed) {
                        e.preventDefault();
                    }
                }
            });
        }
    });
});

// Add loading state to forms on submit
document.addEventListener('DOMContentLoaded', function() {
    const forms = document.querySelectorAll('form');
    forms.forEach(function(form) {
        form.addEventListener('submit', function(e) {
            const submitBtn = form.querySelector('button[type="submit"], input[type="submit"]');
            if (submitBtn && !submitBtn.classList.contains('btn-loading')) {
                submitBtn.classList.add('btn-loading');
                submitBtn.disabled = true;
            }
        });
    });
});

// Tooltip initialization (if using Bootstrap tooltips)
document.addEventListener('DOMContentLoaded', function() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
});

// Search form enhancement
document.addEventListener('DOMContentLoaded', function() {
    const searchForm = document.querySelector('form[action*="search"]');
    if (searchForm) {
        const searchInput = searchForm.querySelector('input[name="q"]');
        if (searchInput) {
            searchInput.addEventListener('input', function() {
                if (this.value.length > 0) {
                    searchForm.querySelector('button[type="submit"]').classList.add('btn-primary');
                    searchForm.querySelector('button[type="submit"]').classList.remove('btn-outline-primary');
                } else {
                    searchForm.querySelector('button[type="submit"]').classList.remove('btn-primary');
                    searchForm.querySelector('button[type="submit"]').classList.add('btn-outline-primary');
                }
            });
        }
    }
});

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl/Cmd + K to focus search
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        const searchInput = document.querySelector('input[name="q"]');
        if (searchInput) {
            searchInput.focus();
        }
    }
    
    // Escape to close modals/cancel
    if (e.key === 'Escape') {
        const cancelBtn = document.querySelector('a.btn-outline-secondary, button.btn-secondary');
        if (cancelBtn) {
            cancelBtn.click();
        }
    }
});

// Copy to clipboard utility
function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
        return navigator.clipboard.writeText(text);
    } else {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        try {
            document.execCommand('copy');
        } catch (err) {
            console.error('Failed to copy:', err);
        }
        document.body.removeChild(textArea);
    }
}

// Session timeout warning (25 minutes)
let sessionWarningTimeout;
let sessionLogoutTimeout;

function resetSessionTimers() {
    clearTimeout(sessionWarningTimeout);
    clearTimeout(sessionLogoutTimeout);
    
    // Warn after 25 minutes
    sessionWarningTimeout = setTimeout(function() {
        alert('Your session will expire in 5 minutes due to inactivity. Please save your work.');
    }, 25 * 60 * 1000);
    
    // Logout after 30 minutes
    sessionLogoutTimeout = setTimeout(function() {
        alert('Your session has expired. Please log in again.');
        window.location.href = '/logout';
    }, 30 * 60 * 1000);
}

// Reset timers on user activity
if (document.querySelector('body').classList.contains('authenticated')) {
    resetSessionTimers();
    document.addEventListener('click', resetSessionTimers);
    document.addEventListener('keypress', resetSessionTimers);
}
