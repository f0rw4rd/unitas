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
        # Find the resources directory
        resources_dir = None
        # Try to find the packaged resources directory
        try:
            import pkg_resources

            resources_dir = pkg_resources.resource_filename("unitas", "resources")
        except (ImportError, pkg_resources.DistributionNotFound):
            # Fall back to looking in the script directory
            script_dir = os.path.dirname(os.path.abspath(__file__))
            potential_resources = os.path.join(script_dir, "resources")
            if os.path.exists(potential_resources):
                resources_dir = potential_resources

        if not resources_dir or not os.path.exists(resources_dir):
            logging.error("Could not find the resources directory")
            return False

        # Create directory structure in temp dir
        os.makedirs(os.path.join(temp_dir, "static", "css"), exist_ok=True)
        os.makedirs(os.path.join(temp_dir, "static", "js"), exist_ok=True)

        # Copy index.html
        index_html_path = os.path.join(resources_dir, "index.html")
        if not os.path.exists(index_html_path):
            logging.error(f"Could not find index.html at {index_html_path}")
            return False
        shutil.copy(index_html_path, os.path.join(temp_dir, "index.html"))

        # Copy CSS files
        css_dir = os.path.join(resources_dir, "static", "css")
        if os.path.exists(css_dir):
            for file in os.listdir(css_dir):
                if file.endswith(".css"):
                    shutil.copy(
                        os.path.join(css_dir, file),
                        os.path.join(temp_dir, "static", "css", file),
                    )

        # Copy JS files
        js_dir = os.path.join(resources_dir, "static", "js")
        if os.path.exists(js_dir):
            for file in os.listdir(js_dir):
                if file.endswith(".js"):
                    shutil.copy(
                        os.path.join(js_dir, file),
                        os.path.join(temp_dir, "static", "js", file),
                    )

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
                    // Store data globally
                    window.scanData = data;
                    
                    // Call validation function from dataHandlers.js
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

        with open(
            os.path.join(temp_dir, "static", "js", "auto-loader.js"),
            "w",
            encoding="utf-8",
        ) as f:
            f.write(auto_loader_js)

        # Modify the index.html to include the auto-loader script
        with open(os.path.join(temp_dir, "index.html"), "r", encoding="utf-8") as f:
            html_content = f.read()

        # Add the auto-loader script right before the closing </body> tag
        html_content = html_content.replace(
            "</body>", '<script src="static/js/auto-loader.js"></script></body>'
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
