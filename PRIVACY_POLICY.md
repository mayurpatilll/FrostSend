# Privacy Policy for FrostSend

**Last Updated:** April 13, 2025

This Privacy Policy describes how FrostSend ("we," "us," or "our") handles information when you use our web application (the "Service").

## Information We Access

When you connect your Google Account to FrostSend, we request access to the following information via Google OAuth 2.0:

*   **Your Google Email Address:** We access your primary Google Account email address solely to display it within the application interface, confirming which account is connected.
*   **Permission to Send Email:** We request permission (`https://www.googleapis.com/auth/gmail.send`) to send emails on your behalf using the Google Gmail API.

## How We Use Information

*   **Sending Emails:** The core function of FrostSend is to send emails that you compose using the provided templates and recipient data. The permission to send email is used exclusively for this purpose when you initiate the "Start Sending Emails" action.
*   **Personalization:** Data from the spreadsheet you upload is used only to replace the corresponding placeholders (e.g., `{{CompanyName}}`) in your email subject and body templates before sending.
*   **Display:** Your email address is displayed within the app to confirm your connection.

## Data Storage and Handling

*   **OAuth Credentials:** When you authenticate via Google, secure OAuth tokens (access and refresh tokens) are stored temporarily in your browser's session storage. These are necessary to maintain your connection and authorize email sending actions. These tokens are cleared when you explicitly click "Disconnect" or when your session expires.
*   **Email Templates:** The subject and body text you enter into the template fields are stored temporarily in your browser's session storage to persist them if the page is reloaded during use. This data is cleared when you explicitly click "Disconnect" or when your session expires.
*   **Uploaded Files (Data Sheet & Attachment):** Files you upload (recipient data sheet, optional attachment) are temporarily stored on the server solely for the duration required to process your email sending request. These files are deleted from the server immediately after the sending process for the corresponding batch completes (whether successful or with errors).
*   **No Long-Term Storage:** FrostSend **does not** store the content of your emails, your recipient lists, your uploaded files, or your Google password long-term on any server or database.

## Google API Services User Data Policy

FrostSend's use and transfer to any other app of information received from Google APIs will adhere to the [Google API Services User Data Policy](https://developers.google.com/terms/api-services-user-data-policy), including the Limited Use requirements.

## Security

We use standard security measures like HTTPS and secure session handling. However, no internet transmission is completely secure.

## Changes to This Policy

We may update this Privacy Policy. We will notify you of any changes by posting the new Privacy Policy on this page.

## Contact Us

If you have any questions about this Privacy Policy, please contact us at: wallmaporg@gmail.com 