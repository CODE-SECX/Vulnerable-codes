// Form submission without CSRF token
function createVulnerableForm() {
    const form = document.createElement('form');
    form.method = 'post';
    form.action = '/api/update-profile';
    
    const nameInput = document.createElement('input');
    nameInput.name = 'username';
    nameInput.value = 'newUsername';
    
    form.appendChild(nameInput);
    document.body.appendChild(form);
    form.submit();
}  