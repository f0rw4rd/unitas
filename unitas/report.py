"""Single file HTML report.

The viewer normally needs a directory of assets and a web server. For handing
results to someone else -- or archiving them with the engagement -- everything
is inlined into one .html that opens from the filesystem with no network and no
server.
"""

import json
import logging
import os
import re
from typing import List, Optional


def find_resources_dir() -> Optional[str]:
    """Locate the packaged viewer resources."""
    try:
        from importlib.resources import files

        resources_dir = str(files("unitas") / "resources")
        if os.path.exists(resources_dir):
            return resources_dir
    except Exception as e:  # pylint: disable=broad-except
        logging.debug(f"Could not resolve packaged resources: {e}")

    # Fall back to looking next to this file
    script_dir = os.path.dirname(os.path.abspath(__file__))
    potential_resources = os.path.join(script_dir, "resources")
    if os.path.exists(potential_resources):
        return potential_resources

    return None


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _script_sources(html: str) -> List[str]:
    """The local script sources of the page, in load order."""
    sources = []
    for src in re.findall(r'<script[^>]+src="([^"]+)"', html):
        if src.startswith("http://") or src.startswith("https://"):
            logging.warning(f"Skipping external script {src}, it cannot be inlined")
            continue
        sources.append(src)
    return sources


def _guard_closing_tag(content: str) -> str:
    """Keep an embedded "</script>" from ending the inline script early."""
    return content.replace("</script>", "<\\/script>")


def build_single_file_report(json_content: str, resources_dir: str = None) -> str:
    """Return the viewer and the scan data as one self contained HTML document."""
    resources_dir = resources_dir or find_resources_dir()
    if not resources_dir:
        raise FileNotFoundError("Could not find the viewer resources directory")

    index_path = os.path.join(resources_dir, "index.html")
    if not os.path.exists(index_path):
        raise FileNotFoundError(f"Could not find index.html at {index_path}")

    html = _read(index_path)

    # Inline the stylesheets
    for href in re.findall(r'<link[^>]+rel="stylesheet"[^>]+href="([^"]+)"', html):
        css_path = os.path.join(resources_dir, href)
        if not os.path.exists(css_path):
            logging.warning(f"Stylesheet {href} not found, skipping")
            continue
        link = re.search(
            r'<link[^>]+href="' + re.escape(href) + r'"[^>]*>', html
        ).group(0)
        html = html.replace(link, f"<style>\n{_read(css_path)}\n</style>")

    # Inline the scripts, in the order the page loads them
    for src in _script_sources(html):
        js_path = os.path.join(resources_dir, src)
        tag = re.search(
            r'<script[^>]+src="' + re.escape(src) + r'"[^>]*></script>', html
        )
        if not tag:
            continue
        if not os.path.exists(js_path):
            logging.warning(f"Script {src} not found, skipping")
            html = html.replace(tag.group(0), "")
            continue
        html = html.replace(
            tag.group(0),
            f"<script>\n{_guard_closing_tag(_read(js_path))}\n</script>",
        )

    # Drop whatever external scripts are left, an offline report cannot use them
    html = re.sub(r'<script[^>]+src="https?://[^"]+"[^>]*></script>', "", html)

    # The data itself plus the call the web server's auto loader would make
    data = json.loads(json_content)
    bootstrap = (
        "<script>\n"
        "window.scanData = " + _guard_closing_tag(json.dumps(data)) + ";\n"
        "document.addEventListener('DOMContentLoaded', function () {\n"
        "    validateAndDisplayData(window.scanData);\n"
        "});\n"
        "</script>\n"
    )

    return html.replace("</body>", bootstrap + "</body>")


def write_single_file_report(json_content: str, output_file: str) -> str:
    """Write the report and return the path it was written to."""
    report = build_single_file_report(json_content)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(report)
    return output_file
