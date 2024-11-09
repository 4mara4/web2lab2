function toggleXSSProtection() {
    fetch('/toggle-xss')
        .then(response => response.json())
        .then(data => {
            alert("XSS Protection is now " + (data.protectionEnabled ? "enabled" : "disabled"));
            location.reload(); // Osvežava stranicu da ažurira status
        });
}
