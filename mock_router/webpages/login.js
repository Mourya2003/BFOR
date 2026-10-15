```javascript
const form = document.getElementById("loginForm");
const message = document.getElementById("message");
const button = document.getElementById("loginButton");

form.addEventListener("submit", async (event) => {
    event.preventDefault();

    message.textContent = "";
    button.disabled = true;
    button.textContent = "Checking...";

    try {
        const formData = new FormData(form);

        const response = await fetch("/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams(formData)
        });

        const result = await response.json();

        if (result.success) {
            window.location.href = "/dashboard";
        } else {
            message.textContent =
                result.message || "Login failed. Try again.";
        }
    } catch (error) {
        message.textContent =
            "Could not contact the server. Please try again.";
    } finally {
        button.disabled = false;
        button.textContent = "Login";
    }
});
```