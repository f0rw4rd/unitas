// Injected by the built in web server (unitas <folder> -H), which writes the
// scan next to the page as data.json. Everything it needs already exists in the
// regular scripts, so this only fetches the file and hands it over -- an
// earlier version kept its own copy of validateAndDisplayData plus timer driven
// "fixups", which silently drifted from the real implementation.
document.addEventListener('DOMContentLoaded', function () {
    const debugRequested = new URLSearchParams(window.location.search).get('debug') === '1';
    let debugContainer = null;

    if (debugRequested) {
        debugContainer = document.createElement('div');
        debugContainer.id = 'debug-output';
        debugContainer.className = 'debug-output';
        document.body.appendChild(debugContainer);

        const debugToggle = document.createElement('button');
        debugToggle.textContent = 'Show Debug Info';
        debugToggle.className = 'debug-toggle';
        debugToggle.addEventListener('click', function () {
            const shown = debugContainer.classList.toggle('visible');
            debugToggle.textContent = shown ? 'Hide Debug Info' : 'Show Debug Info';
        });
        document.body.appendChild(debugToggle);
    }

    function logDebug(message) {
        console.log(message);
        if (!debugContainer) return;
        const line = document.createElement('div');
        line.textContent = message;
        debugContainer.appendChild(line);
        debugContainer.scrollTop = debugContainer.scrollHeight;
    }

    logDebug('Loading data.json');
    showLoading();

    fetch('data.json')
        .then(response => {
            if (!response.ok) {
                throw new Error(`data.json responded with ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            logDebug(`Loaded ${data.hosts ? data.hosts.length : 0} hosts`);
            window.scanData = data;
            validateAndDisplayData(data);
        })
        .catch(error => {
            logDebug(`Error loading data: ${error.message}`);
            console.error('Error loading data:', error);
            showError(`Could not load the scan data: ${error.message}`);
            hideLoading();
        });
});
