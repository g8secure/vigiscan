document.addEventListener('DOMContentLoaded', () => {
    const links = document.querySelectorAll('.sidebar-nav .nav-link');
    links.forEach(link => {
        link.addEventListener('click', () => {
            links.forEach(item => item.classList.remove('active'));
            link.classList.add('active');
        });
    });

    const langSelect = document.getElementById('languageSelect');
    if (langSelect) {
        langSelect.addEventListener('change', () => {
            fetch('/api/save_language', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ language: langSelect.value })
            })
            .then(res => res.json())
            .then(() => {
                window.location.reload();
            })
            .catch(() => {
                console.warn('Unable to save language preference.');
            });
        });
    }

    const dropdowns = document.querySelectorAll('.topbar-dropdown');
    dropdowns.forEach(dropdown => {
        const toggle = dropdown.querySelector('.topbar-dropdown-toggle');
        if (!toggle) return;

        toggle.addEventListener('click', event => {
            event.stopPropagation();
            const isOpen = dropdown.classList.contains('open');
            document.querySelectorAll('.topbar-dropdown.open').forEach(openDropdown => {
                openDropdown.classList.remove('open');
                openDropdown.querySelector('.topbar-dropdown-toggle').setAttribute('aria-expanded', 'false');
            });
            if (!isOpen) {
                dropdown.classList.add('open');
                toggle.setAttribute('aria-expanded', 'true');
            }
        });
    });

    document.addEventListener('click', () => {
        document.querySelectorAll('.topbar-dropdown.open').forEach(openDropdown => {
            openDropdown.classList.remove('open');
            openDropdown.querySelector('.topbar-dropdown-toggle').setAttribute('aria-expanded', 'false');
        });
    });

    document.addEventListener('keydown', event => {
        if (event.key === 'Escape') {
            document.querySelectorAll('.topbar-dropdown.open').forEach(openDropdown => {
                openDropdown.classList.remove('open');
                openDropdown.querySelector('.topbar-dropdown-toggle').setAttribute('aria-expanded', 'false');
            });
        }
    });
});
