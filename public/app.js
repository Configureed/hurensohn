const tokenInput = document.getElementById('token-input');
const loginBtn = document.getElementById('login-btn');
const loginError = document.getElementById('login-error');
const loginSection = document.getElementById('login-section');
const serverSection = document.getElementById('server-section');
const welcomeText = document.getElementById('welcome-text');
const sourceServerSelect = document.getElementById('source-server');
const targetServerSelect = document.getElementById('target-server');
const cloneBtn = document.getElementById('clone-btn');
const cloneStatus = document.getElementById('clone-status');

let servers = [];

loginBtn.addEventListener('click', async () => {
    const token = tokenInput.value.trim();
    if (!token) {
        loginError.textContent = 'Please enter a token';
        return;
    }

    loginError.textContent = '';
    loginBtn.textContent = 'Logging in...';
    loginBtn.disabled = true;

    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ token })
        });

        const data = await response.json();

        if (data.success) {
            servers = data.servers;
            welcomeText.textContent = `Welcome, ${data.username}!`;
            
            // Populate server dropdowns
            sourceServerSelect.innerHTML = '';
            targetServerSelect.innerHTML = '';
            servers.forEach(server => {
                const option1 = document.createElement('option');
                option1.value = server.id;
                option1.textContent = server.name;
                sourceServerSelect.appendChild(option1);

                const option2 = document.createElement('option');
                option2.value = server.id;
                option2.textContent = server.name;
                targetServerSelect.appendChild(option2);
            });

            loginSection.style.display = 'none';
            serverSection.style.display = 'block';
        } else {
            loginError.textContent = data.error || 'Login failed';
        }
    } catch (error) {
        loginError.textContent = 'An error occurred during login';
        console.error(error);
    }

    loginBtn.textContent = 'Login';
    loginBtn.disabled = false;
});

cloneBtn.addEventListener('click', async () => {
    const sourceServerId = sourceServerSelect.value;
    const targetServerId = targetServerSelect.value;

    if (!sourceServerId || !targetServerId) {
        cloneStatus.textContent = 'Please select both servers';
        cloneStatus.style.color = '#e74c3c';
        return;
    }

    if (sourceServerId === targetServerId) {
        cloneStatus.textContent = 'Source and target servers must be different';
        cloneStatus.style.color = '#e74c3c';
        return;
    }

    cloneStatus.textContent = 'Cloning in progress...';
    cloneStatus.style.color = '#667eea';
    cloneBtn.textContent = 'Cloning...';
    cloneBtn.disabled = true;

    try {
        const response = await fetch('/api/clone', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ sourceServerId, targetServerId })
        });

        const data = await response.json();

        if (data.success) {
            cloneStatus.textContent = 'Cloning started! Check the server console for progress.';
            cloneStatus.style.color = '#27ae60';
        } else {
            cloneStatus.textContent = data.error || 'Cloning failed';
            cloneStatus.style.color = '#e74c3c';
        }
    } catch (error) {
        cloneStatus.textContent = 'An error occurred during cloning';
        cloneStatus.style.color = '#e74c3c';
        console.error(error);
    }

    cloneBtn.textContent = 'Clone Server';
    cloneBtn.disabled = false;
});
