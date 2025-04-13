from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
import pandas as pd
from werkzeug.utils import secure_filename
import re
import base64
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from googleapiclient.errors import HttpError
from werkzeug.middleware.proxy_fix import ProxyFix
from urllib.parse import urlparse

# Google OAuth Libraries
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

# Allow OAuthlib to work in development (HTTP) without forcing HTTPS
# Set this early, before any Flow object might be instantiated
# Remove this or set to '0' in production!
# os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' # Ensure this is commented out/removed for production

app = Flask(__name__)

# Apply ProxyFix to handle proxy headers (e.g., X-Forwarded-Proto for HTTPS)
# Adjust x_for=1, x_proto=1, x_host=1, x_prefix=1 based on your proxy setup if needed.
# Common defaults are usually sufficient for platforms like Render.
# Simplifying to trust only X-Forwarded-Proto
# Restoring more comprehensive proxy header trust
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

app.config['UPLOAD_FOLDER'] = 'uploads'
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24))
# --- Debug Secret Key ---
# print(f"DEBUG: Using Flask Secret Key: {app.secret_key}") # Removed
# --- End Debug ---

# Production Session Cookie Settings
app.config.update(
    SESSION_COOKIE_SECURE=True,    # Send cookie only over HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # Prevent client-side JS access
    SESSION_COOKIE_SAMESITE='Lax' # Recommended setting for cross-site request handling
)

# --- OAuth 2.0 Configuration ---
# !! Store these as Environment Variables !!
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")

# --- Temporary Debug Print --- #
# print(f"DEBUG: Read GOOGLE_CLIENT_ID = {GOOGLE_CLIENT_ID}") # Removed
# print(f"DEBUG: Read GOOGLE_CLIENT_SECRET = {GOOGLE_CLIENT_SECRET[:5]}...{GOOGLE_CLIENT_SECRET[-5:] if GOOGLE_CLIENT_SECRET else None}") # Removed
# --- End Temporary Debug Print --- #

if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    print("ERROR: GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables must be set.")
    # You might want to exit or handle this more gracefully in production
    # exit(1)

# Use the production URL env var if available (for deployment), otherwise default to local
PROD_URL = os.environ.get("PRODUCTION_URL")
if PROD_URL:
    REDIRECT_URI = f"{PROD_URL}/oauth2callback"
else:
    REDIRECT_URI = 'http://127.0.0.1:5000/oauth2callback'

# print(f"DEBUG: Using Redirect URI: {REDIRECT_URI}") # Removed

# --- Add print to check PROD_URL at startup ---
print(f"DEBUG: PROD_URL environment variable = {PROD_URL}")
# -------------------------------------------

# Set insecure transport for local development only (when PRODUCTION_URL is not set)
if not PROD_URL:
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    print("INFO: Running in local development mode with OAUTHLIB_INSECURE_TRANSPORT enabled.")
else:
    # Configure SERVER_NAME for production to help url_for generate correct URLs
    try:
        parsed_url = urlparse(PROD_URL)
        # Ensure scheme is included if not present in PRODUCTION_URL
        # Although Render URLs usually include https
        if parsed_url.netloc: # Check if parsing was successful
             app.config['SERVER_NAME'] = parsed_url.netloc # e.g., frostsend.onrender.com
             app.config['PREFERRED_URL_SCHEME'] = parsed_url.scheme or 'https' # Default to https
             app.config['SESSION_COOKIE_DOMAIN'] = parsed_url.netloc # Set cookie domain
             app.config['APPLICATION_ROOT'] = '/' # <<< Add this line
             print(f"INFO: Configured SERVER_NAME='{app.config.get('SERVER_NAME')}', PREFERRED_URL_SCHEME='{app.config.get('PREFERRED_URL_SCHEME')}', SESSION_COOKIE_DOMAIN='{app.config.get('SESSION_COOKIE_DOMAIN')}', APPLICATION_ROOT='{app.config.get('APPLICATION_ROOT')}'")
        else:
             print(f"WARNING: Could not parse PRODUCTION_URL ('{PROD_URL}') correctly to set SERVER_NAME.")
    except Exception as e:
        print(f"ERROR: Exception while setting SERVER_NAME from PRODUCTION_URL: {e}")

# Scopes define the permissions your app requests
SCOPES = [
    'https://www.googleapis.com/auth/gmail.send', # To send emails
    'https://www.googleapis.com/auth/userinfo.email', # To get user's email address (optional, for display)
    'openid' # Standard scope
]

# File path to store client secrets (downloaded from Google Cloud Console)
# We are reading from env vars, but the flow object needs this structure
CLIENT_SECRETS_DICT = {
    "web": {
        "client_id": GOOGLE_CLIENT_ID,
        "project_id": "coldemailerpro", # Added project ID
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uris": [REDIRECT_URI]
        # "javascript_origins": ["http://localhost:5000"] # Optional
    }
}

# --- Helper Functions --- #

def get_user_email(credentials):
    try:
        user_info_service = googleapiclient.discovery.build(
            'oauth2', 'v2',
            credentials=credentials)
        user_info = user_info_service.userinfo().get().execute()
        return user_info.get('email')
    except HttpError as error:
        print(f'An error occurred getting user info: {error}')
        return None
    except Exception as e:
        print(f"An unexpected error occurred getting user info: {e}")
        return None

def find_placeholders(text):
    return re.findall(r'{{(.*?)}}', text)

# --- Routes --- #

@app.route('/')
def index():
    user_email = None
    if 'credentials' in session:
        user_email = session.get('user_email')

    # Retrieve stored templates from session
    saved_subject = session.get('saved_subject', '')
    saved_body = session.get('saved_body', '')

    return render_template('index.html', 
                           user_email=user_email, 
                           saved_subject=saved_subject, 
                           saved_body=saved_body)

@app.route('/authorize')
def authorize():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
         flash("OAuth Client ID/Secret not configured on the server.", "error")
         return redirect(url_for('index'))

    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        CLIENT_SECRETS_DICT, scopes=SCOPES)

    # The URI created here must exactly match one of the authorized redirect URIs
    # for the OAuth 2.0 client, which you configured in the Cloud Console.
    flow.redirect_uri = REDIRECT_URI
    # --- Debug Redirect URI ---
    # print(f"DEBUG: Authorize using Redirect URI: {flow.redirect_uri}") # Removed
    # --- End Debug ---

    authorization_url, state = flow.authorization_url(
        # Enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type='offline',
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes='true',
        # Indicate that the server needs consent from the user.
        prompt='consent')

    # Store the state so the callback can verify the auth server response.
    session['state'] = state
    # --- Debug State --- #
    # print(f"DEBUG: Stored state in session: {state}") # Removed
    # --- End Debug ---

    return redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
    # print("--- DEBUG: Entered /oauth2callback ---") # Removed
    # print(f"--- DEBUG: Request URL: {request.url} ---") # Removed

    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
         # print("--- DEBUG: OAuth Client ID/Secret not configured ---") # Removed
         flash("OAuth Client ID/Secret not configured on the server.", "error")
         return redirect(url_for('index'))

    # Specify the state when creating the flow in the callback so that it can
    # verified in the authorization server response.
    state = session.get('state') # Use .get to avoid KeyError if state is missing
    # print(f"--- DEBUG: State from session: {state} ---") # Removed
    if not state:
        # print("--- DEBUG: State missing from session! ---") # Removed
        flash("OAuth state missing from session. Please try connecting again.", "error")
        # Explicitly redirect to root URL in production
        return redirect(PROD_URL or url_for('index'))

    try:
        # print("--- DEBUG: Creating Flow object... ---") # Removed
        flow = google_auth_oauthlib.flow.Flow.from_client_config(
            CLIENT_SECRETS_DICT, scopes=SCOPES, state=state)
        flow.redirect_uri = REDIRECT_URI
        # print("--- DEBUG: Flow object created. ---") # Removed
    except Exception as e:
         # print(f"--- DEBUG: Error creating Flow object: {e} ---") # Removed
         flash(f"Error initializing OAuth flow: {e}", "error")
         return redirect(url_for('index'))

    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = request.url
    # print(f"--- DEBUG: Authorization Response URL: {authorization_response} ---") # Removed

    # Google recommends using https for production
    # Adjusting URL for OAUTHLIB_INSECURE_TRANSPORT if needed
    needs_https_adjustment = (not os.environ.get("OAUTHLIB_INSECURE_TRANSPORT") and 
                              not authorization_response.startswith("https://"))
    if needs_https_adjustment:
         # print("--- DEBUG: Adjusting auth response URL to HTTPS ---") # Removed
         authorization_response = "https" + authorization_response[4:]
         # print(f"--- DEBUG: Adjusted URL: {authorization_response} ---") # Removed

    try:
        # print("--- DEBUG: Preparing to call flow.fetch_token... ---") # Removed
        # print(f"--- DEBUG: Using auth response URL: {authorization_response} ---") # Removed
        # Explicitly import potential error types
        from oauthlib.oauth2 import MismatchingStateError, InvalidGrantError

        flow.fetch_token(authorization_response=authorization_response)
        # print("--- DEBUG: flow.fetch_token successful. ---") # Removed
    except MismatchingStateError as e:
        # Specific error for state mismatch
        # print(f"--- DEBUG: FATAL ERROR - MismatchingStateError during flow.fetch_token: {e} ---") # Removed
        flash(f"OAuth state mismatch error. This can happen if the session is invalid or the request was tampered with. Please try connecting again. Details: {e}", "error")
        # print(f"Request URL was: {request.url}") # Removed
        # print(f"Expected Redirect URI: {REDIRECT_URI}") # Removed
        # print(f"State from session: {state}") # Removed
        # Explicitly redirect to root URL in production
        return redirect(PROD_URL or url_for('index'))
    except InvalidGrantError as e:
        # Specific error for invalid code or other grant issues
        # print(f"--- DEBUG: FATAL ERROR - InvalidGrantError during flow.fetch_token: {e} ---") # Removed
        flash(f"OAuth invalid grant error. The authorization code might be invalid or expired. Please try connecting again. Details: {e}", "error")
        # print(f"Request URL was: {request.url}") # Removed
        # Explicitly redirect to root URL in production
        return redirect(PROD_URL or url_for('index'))
    except Exception as e:
        # General exception catch
        # print(f"--- DEBUG: Generic Exception during flow.fetch_token: {type(e).__name__}: {e} ---") # Removed
        flash(f"Error fetching OAuth token: {e}. Ensure Redirect URI matches and session is stable.", "error")
        # print(f"OAuth fetch_token error details: {e}") # Removed
        # print(f"Request URL was: {request.url}") # Removed
        # print(f"Expected Redirect URI: {REDIRECT_URI}") # Removed
        # print(f"State used: {state}") # Removed
        # Explicitly redirect to root URL in production
        return redirect(PROD_URL or url_for('index'))

    # Store credentials in the session.
    # print("--- DEBUG: Storing credentials in session... ---") # Removed
    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes}

    # Get user email to display
    # print("--- DEBUG: Credentials stored. Getting user email... ---") # Removed
    session['user_email'] = get_user_email(credentials)
    # print(f"--- DEBUG: User email obtained: {session.get('user_email')} ---") # Removed

    flash(f"Successfully connected account: {session['user_email']}", "info")
    # print("--- DEBUG: Redirecting to index... ---") # Removed
    # Force redirect to root URL in production even on success
    return redirect(PROD_URL or url_for('index'))

@app.route('/clear')
def clear_credentials():
    if 'credentials' in session:
        del session['credentials']
        if 'user_email' in session:
             del session['user_email']
        # Also clear saved templates
        if 'saved_subject' in session:
            del session['saved_subject']
        if 'saved_body' in session:
            del session['saved_body']
        flash("Account disconnected.", "info")
    return redirect(url_for('index'))

# --- Email Sending Logic (Using Gmail API) --- #

def create_message(sender, to, subject, message_text):
    message = MIMEText(message_text, 'plain') # Assume plain text for now
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    # Encode message in base64url format
    raw = base64.urlsafe_b64encode(message.as_bytes())
    return {'raw': raw.decode()}

def create_message_with_attachment(sender, to, subject, message_text, file_path, filename):
    message = MIMEMultipart()
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject

    msg = MIMEText(message_text, 'plain')
    message.attach(msg)

    # Guess content type
    # content_type, encoding = mimetypes.guess_type(file_path)
    # if content_type is None or encoding is not None:
    #     content_type = 'application/octet-stream' # Default if guess fails
    # main_type, sub_type = content_type.split('/', 1)

    # For simplicity, using a generic type. For production, use mimetypes.
    main_type = 'application'
    sub_type = 'octet-stream'

    try:
        with open(file_path, 'rb') as fp:
            msg = MIMEBase(main_type, sub_type)
            msg.set_payload(fp.read())

        encoders.encode_base64(msg)
        msg.add_header('Content-Disposition', 'attachment', filename=filename)
        message.attach(msg)

        raw = base64.urlsafe_b64encode(message.as_bytes())
        return {'raw': raw.decode()}

    except FileNotFoundError:
        print(f"Error: Attachment file not found at {file_path}")
        return None
    except Exception as e:
        print(f"Error attaching file: {e}")
        return None


@app.route('/send_emails', methods=['POST'])
def send_emails():
    # --- Check Authentication --- #
    if 'credentials' not in session:
        flash("Please connect your Google Account first using the button above.", "warning")
        return redirect(url_for('index'))

    creds_dict = session['credentials']
    try:
        credentials = google.oauth2.credentials.Credentials(**creds_dict)
        # Optional: Could add logic here to check if token needs refreshing
        # credentials.refresh(Request()) # Requires google.auth.transport.requests
    except Exception as e:
        flash(f"Error loading credentials: {e}. Please try reconnecting your account.", "error")
        # Clear potentially corrupted credentials
        if 'credentials' in session: del session['credentials']
        if 'user_email' in session: del session['user_email']
        return redirect(url_for('index'))

    sender_email = session.get('user_email', 'me') # Use authenticated user's email
    if not sender_email:
         flash(f"Could not determine sender email from credentials. Please reconnect.", "error")
         if 'credentials' in session: del session['credentials'] # Clear potentially corrupted credentials
         return redirect(url_for('index'))

    # --- Get form data ---
    subject_template = request.form['subject']
    body_template = request.form['body']
    # Store templates in session *before* potential redirects
    session['saved_subject'] = subject_template
    session['saved_body'] = body_template
    data_sheet_file = request.files['data_sheet']
    attachment_file = request.files.get('attachment')

    # --- Basic Validation ---
    if not subject_template or not body_template or not data_sheet_file:
        flash('Missing required template fields or data sheet.', 'error')
        return redirect(url_for('index'))

    if data_sheet_file.filename == '':
        flash('No data sheet selected.', 'error')
        return redirect(url_for('index'))

    # --- Secure and save uploaded files ---
    data_filename = secure_filename(data_sheet_file.filename)
    data_filepath = os.path.join(app.config['UPLOAD_FOLDER'], data_filename)
    data_sheet_file.save(data_filepath)

    attachment_path = None
    attachment_filename = None
    if attachment_file and attachment_file.filename != '':
        attachment_filename = secure_filename(attachment_file.filename)
        attachment_path = os.path.join(app.config['UPLOAD_FOLDER'], attachment_filename)
        attachment_file.save(attachment_path)

    # --- Read Data Sheet ---
    try:
        if data_filename.endswith('.csv'):
            df = pd.read_csv(data_filepath)
        elif data_filename.endswith(('.xls', '.xlsx')):
            df = pd.read_excel(data_filepath)
        else:
            flash('Unsupported data sheet format. Please use CSV or Excel.', 'error')
            os.remove(data_filepath)
            if attachment_path: os.remove(attachment_path)
            return redirect(url_for('index'))
    except Exception as e:
        flash(f'Error reading data sheet: {e}', 'error')
        os.remove(data_filepath)
        if attachment_path: os.remove(attachment_path)
        return redirect(url_for('index'))

    # --- Validate Sheet Columns ---
    if 'Email' not in df.columns:
        flash('Data sheet must contain an \'Email\' column for recipient addresses.', 'error')
        os.remove(data_filepath)
        if attachment_path: os.remove(attachment_path)
        return redirect(url_for('index'))

    required_vars = set(find_placeholders(subject_template)) | set(find_placeholders(body_template))
    missing_cols = required_vars - set(df.columns)
    if missing_cols:
        flash(f'Data sheet is missing required columns for placeholders: {", ".join(missing_cols)}', 'error')
        os.remove(data_filepath)
        if attachment_path: os.remove(attachment_path)
        return redirect(url_for('index'))

    # --- Process and Send Emails via Gmail API ---
    success_count = 0
    error_count = 0
    error_details = []

    try:
        # Build the Gmail service object
        service = googleapiclient.discovery.build('gmail', 'v1', credentials=credentials)

        for index, row in df.iterrows():
            recipient_email = row['Email']
            if not recipient_email or pd.isna(recipient_email):
                print(f"Skipping row {index+2}: Empty recipient email.")
                error_count += 1
                error_details.append(f"Row {index+2}: Missing recipient email.")
                continue

            # Replace placeholders
            current_subject = subject_template
            current_body = body_template
            try:
                for col in required_vars:
                    value = str(row[col])
                    current_subject = current_subject.replace(f'{{{{{col}}}}}', value)
                    current_body = current_body.replace(f'{{{{{col}}}}}', value)

                # Create message
                if attachment_path:
                    message_body = create_message_with_attachment(
                        sender_email, recipient_email, current_subject, current_body, attachment_path, attachment_filename
                    )
                    if not message_body:
                         error_count += 1
                         error_details.append(f"Recipient {recipient_email}: Failed to create message with attachment.")
                         continue # Skip if attachment failed
                else:
                    message_body = create_message(
                        sender_email, recipient_email, current_subject, current_body
                    )

                # Send email using Gmail API
                try:
                    # Use 'me' to refer to the authenticated user
                    sent_message = service.users().messages().send(userId='me', body=message_body).execute()
                    success_count += 1
                except HttpError as error:
                    print(f"An API error occurred sending to {recipient_email}: {error}")
                    error_msg = f"API Send error - {error}" # Default error message
                    try:
                        # Attempt to parse the error content for specific details
                        error_details_json = json.loads(error.content.decode('utf-8'))
                        if error_details_json.get('error') and error_details_json['error'].get('errors'):
                            first_error = error_details_json['error']['errors'][0]
                            if first_error.get('reason') == 'invalidArgument' and 'Invalid To header' in first_error.get('message', ''):
                                error_msg = f"Invalid Email Address Format."
                            else:
                                # Use the message from the API error if available, otherwise default
                                error_msg = first_error.get('message', error_msg)
                    except (json.JSONDecodeError, IndexError, KeyError, AttributeError) as parse_error:
                         print(f"Could not parse specific error details from HttpError: {parse_error}")
                         # Stick with the default error message
                    
                    error_details.append(f"Recipient {recipient_email} (Row {index+2}): {error_msg}")
                    error_count += 1
                except Exception as e:
                     print(f"Unexpected error sending email to {recipient_email}: {e}")
                     error_details.append(f"Recipient {recipient_email}: Unexpected send error - {e}")
                     error_count += 1

            except KeyError as e:
                 print(f"Skipping row {index+2} for {recipient_email}: Missing data for placeholder {e}")
                 error_count += 1
                 error_details.append(f"Recipient {recipient_email} (Row {index+2}): Missing data for {e}")
            except Exception as e:
                print(f"Generic error processing email for {recipient_email}: {e}")
                error_count += 1
                error_details.append(f"Recipient {recipient_email}: Processing error - {e}")

    except HttpError as error:
         flash(f"An error occurred communicating with the Gmail API: {error}. Please try reconnecting your account.", "error")
         # Consider clearing credentials here
         if 'credentials' in session: del session['credentials']
         if 'user_email' in session: del session['user_email']
         # Clean up files before redirecting
         try:
             os.remove(data_filepath)
             if attachment_path:
                 os.remove(attachment_path)
         except OSError as e:
             print(f"Error deleting uploaded files after API error: {e}")
         return redirect(url_for('index'))
    except Exception as e:
         flash(f"An unexpected error occurred: {e}.", "error")
         # Clean up files before redirecting
         try:
             os.remove(data_filepath)
             if attachment_path:
                 os.remove(attachment_path)
         except OSError as e:
             print(f"Error deleting uploaded files after unexpected error: {e}")
         return redirect(url_for('index'))

    # --- Clean up uploaded files ---
    try:
        os.remove(data_filepath)
        if attachment_path:
            os.remove(attachment_path)
    except OSError as e:
        print(f"Error deleting uploaded files: {e}")

    # --- Provide Feedback ---
    flash(f'Email sending process completed. Success: {success_count}, Errors: {error_count}.', 'info')
    if error_details:
         flash('Error Details: ' + "; ".join(error_details[:10]) + ('...' if len(error_details) > 10 else ''), 'warning')

    # Redirect happens last, session now contains the templates
    return redirect(url_for('index'))


if __name__ == '__main__':
    # This allows OAuthlib to work in development (HTTP) without forcing HTTPS
    # Remove this or set to '0' in production!
    # os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' # Moved to top level

    # --- End Debug ---

    # print("--- Runtime Check ---") # Removed
    # print(f"GOOGLE_CLIENT_ID: {os.environ.get('GOOGLE_CLIENT_ID')}") # Removed
    # print(f"GOOGLE_CLIENT_SECRET: {os.environ.get('GOOGLE_CLIENT_SECRET')[:5]}...{os.environ.get('GOOGLE_CLIENT_SECRET')[-5:] if os.environ.get('GOOGLE_CLIENT_SECRET') else None}") # Removed
    # print(f"FLASK_SECRET_KEY: {os.environ.get('FLASK_SECRET_KEY')}") # Removed
    # print("---------------------") # Removed

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    # Consider using a more production-ready server than Flask's default dev server
    # For session management, ensure the secret key is properly set and kept secret
    app.run(debug=True, port=5000) # Running on port 5000 