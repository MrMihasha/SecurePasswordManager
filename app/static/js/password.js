// Password visibility toggle
document.addEventListener('DOMContentLoaded', function() {
    const toggleBtn = document.getElementById('togglePassword');
    if (toggleBtn) {
        toggleBtn.addEventListener('click', function() {
            const passwordField = document.getElementById('passwordField');
            const icon = document.getElementById('toggleIcon');
            
            if (passwordField.type === 'password') {
                passwordField.type = 'text';
                icon.classList.remove('bi-eye');
                icon.classList.add('bi-eye-slash');
            } else {
                passwordField.type = 'password';
                icon.classList.remove('bi-eye-slash');
                icon.classList.add('bi-eye');
            }
        });
    }
});

// Password generator
document.addEventListener('DOMContentLoaded', function() {
    const generateBtn = document.getElementById('generatePassword');
    if (generateBtn) {
        generateBtn.addEventListener('click', function() {
            const password = generateSecurePassword();
            const passwordField = document.getElementById('passwordField');
            passwordField.value = password;
            passwordField.type = 'text'; // Show generated password
            
            // Update toggle icon
            const icon = document.getElementById('toggleIcon');
            if (icon) {
                icon.classList.remove('bi-eye');
                icon.classList.add('bi-eye-slash');
            }
            
            // Visual feedback
            passwordField.classList.add('border-success');
            setTimeout(() => {
                passwordField.classList.remove('border-success');
            }, 1000);
            
            // Show strength indicator if it exists
            updatePasswordStrength(password);
        });
    }
});

// Generate secure password
function generateSecurePassword(length = 16) {
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    const allChars = lowercase + uppercase + numbers + symbols;
    let password = '';
    
    // Ensure at least one of each type
    password += lowercase[Math.floor(Math.random() * lowercase.length)];
    password += uppercase[Math.floor(Math.random() * uppercase.length)];
    password += numbers[Math.floor(Math.random() * numbers.length)];
    password += symbols[Math.floor(Math.random() * symbols.length)];
    
    // Fill the rest randomly
    for (let i = password.length; i < length; i++) {
        password += allChars[Math.floor(Math.random() * allChars.length)];
    }
    
    // Shuffle the password
    return password.split('').sort(() => Math.random() - 0.5).join('');
}

// Password strength checker
function checkPasswordStrength(password) {
    let strength = 0;
    
    if (password.length >= 8) strength++;
    if (password.length >= 12) strength++;
    if (password.length >= 16) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^a-zA-Z0-9]/.test(password)) strength++;
    
    if (strength <= 3) return 'weak';
    if (strength <= 5) return 'medium';
    return 'strong';
}

// Update password strength indicator
function updatePasswordStrength(password) {
    const strengthBar = document.querySelector('.password-strength-bar');
    if (strengthBar) {
        const strength = checkPasswordStrength(password);
        strengthBar.className = 'password-strength-bar ' + strength;
    }
}

// Real-time password strength monitoring
document.addEventListener('DOMContentLoaded', function() {
    const passwordField = document.getElementById('passwordField');
    if (passwordField) {
        // Create strength indicator if it doesn't exist
        if (!document.querySelector('.password-strength')) {
            const strengthDiv = document.createElement('div');
            strengthDiv.className = 'password-strength';
            strengthDiv.innerHTML = '<div class="password-strength-bar"></div>';
            passwordField.parentElement.parentElement.appendChild(strengthDiv);
        }
        
        passwordField.addEventListener('input', function() {
            updatePasswordStrength(this.value);
        });
    }
});

// Password confirmation matching
document.addEventListener('DOMContentLoaded', function() {
    const password1 = document.getElementById('password');
    const password2 = document.getElementById('password2');
    
    if (password1 && password2) {
        function checkPasswordMatch() {
            if (password2.value.length > 0) {
                if (password1.value === password2.value) {
                    password2.classList.remove('is-invalid');
                    password2.classList.add('is-valid');
                } else {
                    password2.classList.remove('is-valid');
                    password2.classList.add('is-invalid');
                }
            } else {
                password2.classList.remove('is-valid', 'is-invalid');
            }
        }
        
        password1.addEventListener('input', checkPasswordMatch);
        password2.addEventListener('input', checkPasswordMatch);
    }
});

// Copy password to clipboard with feedback
function copyPassword(fieldId) {
    const field = document.getElementById(fieldId);
    if (field) {
        // Use the Clipboard API
        navigator.clipboard.writeText(field.value).then(function() {
            // Show success feedback
            const copyBtn = event.target.closest('button');
            const originalHTML = copyBtn.innerHTML;
            copyBtn.innerHTML = '<i class="bi bi-check"></i> Copied!';
            copyBtn.classList.add('btn-success');
            copyBtn.classList.remove('btn-outline-primary', 'btn-outline-secondary');
            
            setTimeout(function() {
                copyBtn.innerHTML = originalHTML;
                copyBtn.classList.remove('btn-success');
                copyBtn.classList.add('btn-outline-primary');
            }, 2000);
        }).catch(function(err) {
            console.error('Failed to copy:', err);
            alert('Failed to copy to clipboard');
        });
    }
}

// Prevent form submission on Enter in password generator
document.addEventListener('DOMContentLoaded', function() {
    const passwordField = document.getElementById('passwordField');
    if (passwordField) {
        passwordField.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' && e.target.value.length === 0) {
                e.preventDefault();
                document.getElementById('generatePassword')?.click();
            }
        });
    }
});
