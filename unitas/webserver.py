import http
import logging
import os
import shutil
import socketserver
import tempfile
import threading
import time
import webbrowser


def start_http_server(json_content, port=8000):
    """Start an HTTP server to serve the HTML viewer and JSON data."""
    # Create a temporary directory to serve files from
    temp_dir = tempfile.mkdtemp()
    try:
        # Find the HTML file
        html_file = None
        # Try to find the packaged HTML file
        try:
            import pkg_resources

            html_file = pkg_resources.resource_filename("unitas.resources", "view.html")
        except (ImportError, pkg_resources.DistributionNotFound):
            # Fall back to looking in the script directory
            script_dir = os.path.dirname(os.path.abspath(__file__))
            potential_html = os.path.join(script_dir, "resources", "view.html")
            if os.path.exists(potential_html):
                html_file = potential_html

        if not html_file or not os.path.exists(html_file):
            logging.error("Could not find the HTML viewer file (view.html)")
            return False

        # Copy the HTML file to the temp directory
        shutil.copy(html_file, os.path.join(temp_dir, "index.html"))

        # Write the JSON data to the temp directory
        with open(os.path.join(temp_dir, "data.json"), "w", encoding="utf-8") as f:
            f.write(json_content)

        # Create a minimal JavaScript file to auto-load the data
        auto_loader_js = """
        document.addEventListener('DOMContentLoaded', function() {
            // Auto-load the JSON data
            fetch('data.json')
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Network response was not ok');
                    }
                    return response.json();
                })
                .then(data => {
                    // Access the internal handleFile function
                    // Simulate file selection
                    scanData = data;
                    
                    // Hide the initial screen and show data view directly
                    document.getElementById('initial-screen').classList.add('hidden');
                    document.getElementById('data-view').classList.remove('hidden');
                    document.getElementById('error-message').classList.add('hidden');
                    
                    // Call the validation and display functions
                    validateAndDisplayData(data);
                })
                .catch(error => {
                    console.error('Error loading data:', error);
                    const errorMsg = document.getElementById('error-message');
                    if (errorMsg) {
                        errorMsg.textContent = "Error loading data automatically. Please try uploading manually.";
                        errorMsg.classList.remove('hidden');
                    }
                });
        });
        """

        with open(os.path.join(temp_dir, "auto-loader.js"), "w", encoding="utf-8") as f:
            f.write(auto_loader_js)

        # Modify the index.html to include the auto-loader script
        with open(os.path.join(temp_dir, "index.html"), "r", encoding="utf-8") as f:
            html_content = f.read()

        # Add the auto-loader script right before the closing </head> tag
        html_content = html_content.replace(
            "</head>", '<script src="auto-loader.js"></script></head>'
        )

        with open(os.path.join(temp_dir, "index.html"), "w", encoding="utf-8") as f:
            f.write(html_content)

        # Save the current directory
        original_dir = os.getcwd()

        # Change to the temp directory
        os.chdir(temp_dir)

        # Create a custom HTTP handler to add CORS headers
        class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
            def end_headers(self):
                self.send_header("Access-Control-Allow-Origin", "*")
                super().end_headers()

        # Create a simple HTTP server
        httpd = socketserver.TCPServer(("", port), CustomHTTPRequestHandler)

        # Start server in a new thread
        server_thread = threading.Thread(target=httpd.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        logging.info(f"Started HTTP server at http://localhost:{port}")
        logging.info("The web interface is now available")
        logging.info("Press Ctrl+C to stop the server")

        # Open web browser
        webbrowser.open(f"http://localhost:{port}/index.html")

        # Keep the main thread running until interrupted
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logging.info("\nStopping HTTP server")

        # Shutdown the server
        httpd.shutdown()
        server_thread.join()

        # Return to the original directory
        os.chdir(original_dir)

        return True

    except Exception as e:
        logging.error(f"Error starting HTTP server: {e}")
        return False
    finally:
        # Clean up the temporary directory
        shutil.rmtree(temp_dir)
