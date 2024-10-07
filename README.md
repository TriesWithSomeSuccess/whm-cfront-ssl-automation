
# **WHM / Cloudfront SSL Management Automation**
This project automates the management of SSL certificates for domains hosted on a WHM/cPanel server, including issuing, renewing, and switching DNS settings between CloudFront and EC2 IPs using AWS Route53. The project is written in Python and utilizes AWS SDK (boto3), Paramiko for SSH, and the WHM API.

Why does it exist? If you are hosting wordpress sites on WHM  and using AutoSSL some weirdness happens when you attempt to create and use Cloudfront distributions with them. Everything is fine until your local whm certificates expire. Autossl attempts to renew them and fails because it can't pass it's usual
checks due to the domain being fronted by Cloudfront. Cloudfront then errors out the next time it tries to pull from the origin because it expects a valid SSL certificate.

Aren't there better ways to configure everything initially so that this isn't an issue? For sure. And if you're the only cook in the kitchen I would probably suggest not relying on SSL at all on your origin. Make it http only and then configure origin access to use http. Much simpler setup. One AWS issued SSL to deal with. Very nice.

I am not the only cook in my kitchen. The other cooks require an SSL on the origin for other software to function. I decided it was easiest to hack this together and call it a day.

You can cron this but I would babysit it... run it from the command line and watch the output.  DNS propagation rates fluctuate. Error checking and reporting is lacking right now. It will fail sometimes. I may fix it up.

## **Features**
- Automatically check SSL certificates for expiration on CloudFront domains.
- Switch DNS records between EC2 and CloudFront using AWS Route53.
- Automate the deletion and renewal of SSL certificates using WHM AutoSSL.
- Send email notifications for expiring certificates or errors.
- Configurable via a JSON file for easy deployment.

## **Prerequisites**
Ensure you have the following installed on your system:

- Python 3.6 or higher
- `pip` (Python package installer)
- AWS credentials with appropriate access to Route53 and CloudFront.
- WHM access credentials and API token for cPanel/WHM server.

## **Installation**

### Clone the repository:
```bash
git clone https://github.com/TriesWithSomeSuccess/whm-cfront-ssl-automation.git
cd whm-cfront-ssl-automation
```

### Install dependencies:
Run the following command to install the required packages:
```bash
pip install -r requirements.txt
```

Dependencies include:
- `boto3`
- `paramiko`
- `cryptography`
- `requests`

### Create the configuration file:
You need to create a `config.json` file with your specific credentials and settings. Below is an example:

```json
{
  "aws": {
    "access_key": "YOUR_AWS_ACCESS_KEY",
    "secret_key": "YOUR_AWS_SECRET_KEY"
  },
  "whm": {
    "api_token": "YOUR_WHM_API_TOKEN",
    "server": "https://yourwhmserver.com:2087"
    "ip": "WHM_IP"
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
```

### Configure AWS CLI or credentials:
Ensure your AWS credentials are correctly set up for `boto3` to access AWS services such as Route53 and CloudFront. This can be done through environment variables or an AWS credentials file. For more details, visit the [AWS Boto3 documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html).

## **Usage**

### Running the script:
You can run the script to check for expiring SSL certificates and automatically renew them by executing:

```bash
python ssl_management.py
```

The script will:
- List all CloudFront domains.
- Check for SSL certificates expiring within a given number of days (default: 27).
- Automatically switch DNS records from CloudFront to EC2 IP for renewal.
- Renew SSL certificates using WHM AutoSSL.
- Switch DNS back to CloudFront after renewal.
- Send email notifications if enabled.

### Example Cron Job:
To automate this process, you can add it to your `crontab` so it runs periodically:

```bash
crontab -e
```

Add the following line to run the script daily at 2 AM:
```bash
0 2 * * * /usr/bin/python3 /path/to/ssl_management.py
```

## **Configuration**

You can configure the following parameters in the `config.json` file:
- **AWS Credentials**: For accessing Route53 and CloudFront services.
- **WHM API**: For managing SSL certificates via the WHM API.
- **SSH Details**: For connecting to your EC2 instance.
- **Email Settings**: Enable or disable email notifications for SSL events.

### Configurable Email Notifications
Set `email.enabled` to `true` or `false` to control email notifications.  
Email notifications will be sent when an SSL certificate is expiring or if there's an error during the SSL renewal process.

## **Logging**

The script uses Python's `logging` module to log important information and errors. You can modify the logging behavior by adjusting the `logging.basicConfig` in the script.

## **Contact**

For any questions or issues, feel free to open an issue on GitHub or contact the maintainer at suboptimal@serpcollective.com.
