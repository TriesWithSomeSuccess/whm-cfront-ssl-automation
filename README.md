WHM/Cloudfront SSL Management Automation
This project automates the management of SSL certificates for domains hosted on a WHM/cPanel server, including issuing, renewing, and switching DNS settings between CloudFront and EC2 IPs using AWS Route53. The project is written in Python and utilizes AWS SDK (boto3), Paramiko for SSH, and the WHM API.
This is one of those things that should probably be solved in one of a dozen better ways. That said... it works. Cron it and be sure to check your email daily. I'll add better error reporting in the future. I wouldn't set it and forget it. DNS propagation can be slow at times and if it times out you're liable to have a flubbed setup on that particular domain. I'll also address that at some point.

Features
Automatically check SSL certificates for expiration on CloudFront domains.
Switch DNS records between EC2 and CloudFront using AWS Route53.
Automate the deletion and renewal of SSL certificates using WHM AutoSSL.
Send email notifications for expiring certificates or errors.
Configurable via a JSON file for easy deployment.
Prerequisites
Ensure you have the following installed on your system:

Python 3.6 or higher
pip (Python package installer)
AWS credentials with appropriate access to Route53 and CloudFront.
WHM access credentials and API token for cPanel/WHM server.
Installation
Clone the repository:

bash
Copy code
git clone https://github.com/yourusername/ssl-management-automation.git
cd ssl-management-automation
Install dependencies: Run the following command to install required packages:

bash
Copy code
pip install -r requirements.txt
Dependencies include:

boto3
paramiko
cryptography
requests
Create the configuration file: You need to create a config.json file with your specific credentials and settings. Below is an example:

json
Copy code
{
  "aws": {
    "access_key": "YOUR_AWS_ACCESS_KEY",
    "secret_key": "YOUR_AWS_SECRET_KEY"
  },
  "whm": {
    "api_token": "YOUR_WHM_API_TOKEN",
    "server": "https://yourwhmserver.com:2087"
    "ip": "WHM IP / DOMAIN NON-CLOUDFRONT IP"	
  },
  "ssh": {
    "host": "YOUR_SSH_HOST",
    "username": "YOUR_SSH_USERNAME",
    "private_key_path": "/path/to/your/private/key.pem"
  },
  "email": {
    "enabled": true,
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 465,
    "address": "your-email@gmail.com",
    "password": "your-email-app-password",
    "recipient": "recipient-email@gmail.com"
  }
}
Configure AWS CLI or credentials: Ensure your AWS credentials are correctly set up for boto3 to access AWS services such as Route53 and CloudFront. This can be done through environment variables or an AWS credentials file. For more details, visit the AWS Boto3 documentation.

Usage
Running the script: You can run the script to check for expiring SSL certificates and automatically renew them by executing:

bash
Copy code
python ssl_management.py
The script will:

List all CloudFront domains.
Check for SSL certificates expiring within a given number of days (default: 27).
Automatically switch DNS records from CloudFront to EC2 IP for renewal.
Renew SSL certificates using WHM AutoSSL.
Switch DNS back to CloudFront after renewal.
Send email notifications if enabled.
Example Cron Job: To automate this process, you can add it to your crontab so it runs periodically:

bash
Copy code
crontab -e
Add the following line to run the script daily at 2 AM:

bash
Copy code
0 2 * * * /usr/bin/python3 /path/to/ssl_management.py
Configuration
You can configure the following parameters in the config.json file:

AWS Credentials: For accessing Route53 and CloudFront services.
WHM API: For managing SSL certificates via the WHM API.
SSH Details: For connecting to your EC2 instance.
Email Settings: Enable or disable email notifications for SSL events.
Configurable Email Notifications
Set email.enabled to true or false to control email notifications.
Email notifications will be sent when an SSL certificate is expiring or if there's an error during the SSL renewal process.
Logging
The script uses Python's logging module to log important information and errors. You can modify the logging behavior by adjusting the logging.basicConfig in the script.

Security Considerations
Sensitive data: Ensure that your config.json file is added to .gitignore to prevent committing sensitive credentials to version control.
SSH keys: Use an SSH key pair for securely connecting to the EC2 instance.
Email passwords: Use app-specific passwords or environment variables to secure email credentials.
Contributing
Contributions are welcome! If you have improvements or bug fixes, please follow these steps:

Fork the repository.
Create a new branch (git checkout -b feature/my-feature).
Commit your changes (git commit -am 'Add my feature').
Push to the branch (git push origin feature/my-feature).
Open a pull request.
License
This project is licensed under the MIT License. See the LICENSE file for details.

Contact
For any questions or issues, feel free to open an issue on GitHub or contact the maintainer at your-email@example.com.

