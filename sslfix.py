import json
import logging
import smtplib
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.mime.text import MIMEText

import boto3
import certifi  # This provides the CA bundle path
import paramiko
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend


# Load configuration from the config.json file
def load_config():
    with open("config.json", "r") as file:
        return json.load(file)


config = load_config()

# AWS and WHM credentials from config file
AWS_ACCESS_KEY = config["aws"]["access_key"]
AWS_SECRET_KEY = config["aws"]["secret_key"]
WHM_API_TOKEN = config["whm"]["api_token"]
WHM_SERVER = config["whm"]["server"]
WHM_SERVER_IP = config["whm"]["ip"]

# SSH details for connecting to EC2 from config file
SSH_HOST = config["ssh"]["host"]
SSH_USERNAME = config["ssh"]["username"]
SSH_PRIVATE_KEY_PATH = config["ssh"]["private_key_path"]

# Email settings from config file
EMAIL_NOTIFICATIONS_ENABLED = config["email"]["enabled"]
SMTP_SERVER = config["email"]["smtp_server"]
SMTP_PORT = config["email"]["smtp_port"]
EMAIL_ADDRESS = config["email"]["address"]
EMAIL_PASSWORD = config["email"]["password"]
EMAIL_RECIPIENT = config["email"]["recipient"]

# Route53 and CloudFront clients
route53_client = boto3.client(
    "route53", aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY
)
cloudfront_client = boto3.client(
    "cloudfront", aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY
)


# SSH setup
def ssh_command(command):
    """Executes SSH command using Paramiko."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(SSH_HOST, username=SSH_USERNAME, key_filename=SSH_PRIVATE_KEY_PATH)
        stdin, stdout, stderr = ssh.exec_command(command)
        stdout_output = stdout.read().decode("utf-8").strip()
        stderr_output = stderr.read().decode("utf-8").strip()

        if stdout_output:
            logging.info(f"SSH stdout for {command}: {stdout_output}")
        if stderr_output:
            logging.error(f"SSH stderr for {command}: {stderr_output}")

        return stdout_output, stderr_output
    except Exception as e:
        logging.error(f"SSH command failed: {e}")
        return None, None
    finally:
        ssh.close()


def send_email(subject, message):
    """Sends an email alert if enabled."""
    if not EMAIL_NOTIFICATIONS_ENABLED:
        return
    try:
        msg = MIMEText(message)
        msg["Subject"] = subject
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = EMAIL_RECIPIENT

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, EMAIL_RECIPIENT, msg.as_string())
        print("Email notification sent.")
    except Exception as e:
        print(f"Failed to send email: {e}")


def list_cloudfront_domains():
    """Lists CloudFront domains and filters by those using CloudFront."""
    all_domains = requests.get(
        f"{WHM_SERVER}/json-api/listaccts?api.version=1",
        headers={"Authorization": f"whm root:{WHM_API_TOKEN}"},
    ).json()
    domains = [
        acct["domain"] for acct in all_domains["data"]["acct"] if acct["suspended"] == 0
    ]

    cloudfront_domains = []
    global non_cloudfront_domains
    non_cloudfront_domains = []

    for domain in domains:
        try:
            response = requests.head(f"http://{domain}", timeout=5)
            if "CloudFront" in response.headers.get(
                "Server", ""
            ) or "CloudFront" in response.headers.get("Via", ""):
                cloudfront_domains.append(domain)
            else:
                non_cloudfront_domains.append(domain)

        except Exception as e:
            print(f"Failed to check {domain}: {e}")

    return cloudfront_domains


def get_ssl_certificate_info(domain):
    """Fetches SSL certificate info for a given domain using WHM API."""
    url = f"{WHM_SERVER}/json-api/fetchsslinfo?api.version=1&domain={domain}"
    headers = {"Authorization": f"whm root:{WHM_API_TOKEN}"}

    response = requests.get(
        url, headers=headers, verify=certifi.where()
    )  # Using certifi for SSL verification
    if response.status_code == 200:
        content = response.json()
        if "data" in content and "crt" in content["data"]:

            crt_string = content["data"]["crt"]
            cert_bytes = crt_string.encode("ascii")

            cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())

            domain = content["data"]["domain"]
            issuer = cert.issuer.rfc4514_string()
            expiry_date = cert.not_valid_after

            return {"domain": domain, "issuer": issuer, "expiry_date": expiry_date}
        else:
            logging.error(
                f"SSL info not found for {domain}. Available keys: {list(content.keys())}"
            )
            if "data" in content:
                logging.error(
                    f"Available keys in 'data': {list(content['data'].keys())}"
                )
    else:
        logging.error(
            f"Failed to fetch SSL info for {domain}. Status Code: {response.status_code}"
        )
        logging.error(f"Response: {response.content}")

    return None


logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def get_expiring_ssl_certificates(days, cloudfront_domains):
    """Fetches SSL certificates expiring within a specified number of days for CloudFront domains."""
    expiring_certs = []

    def check_domain(domain):
        logging.info(f"Checking SSL info for domain: {domain}")
        ssl_info = get_ssl_certificate_info(domain)

        if ssl_info:
            expiry_date = ssl_info["expiry_date"]
            expiry_date = expiry_date.replace(tzinfo=timezone.utc)
            days_until_expiry = (expiry_date - datetime.now(timezone.utc)).days

            if days_until_expiry <= days:
                logging.info(f"Domain {domain} is expiring within {days} days.")
                expiring_certs.append(ssl_info)
            else:
                logging.info(f"Domain {domain} is not expiring within {days} days.")

    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(check_domain, cloudfront_domains)

    logging.info(
        f"Finished checking all domains. Total expiring certificates: {len(expiring_certs)}"
    )
    return expiring_certs


def switch_route53_alias(domain, switch_to_ip):
    """Switches the Route53 DNS record between IP and CloudFront alias."""
    hosted_zone_id = get_hosted_zone_id(domain)
    if not hosted_zone_id:
        print(f"Hosted zone not found for {domain}")
        return

    if switch_to_ip:
        change_to_ip(domain, hosted_zone_id, WHM_SERVER_IP)
    else:
        change_to_cloudfront_alias(domain, hosted_zone_id)


def get_hosted_zone_id(domain):
    """Fetches the hosted zone ID for a given domain."""
    hosted_zone_id = None
    next_marker = None

    while True:
        if next_marker:
            response = route53_client.list_hosted_zones(Marker=next_marker)
        else:
            response = route53_client.list_hosted_zones()

        for zone in response["HostedZones"]:
            if zone["Name"].startswith(domain + "."):
                hosted_zone_id = zone["Id"].split("/")[-1]
                return hosted_zone_id

        if response["IsTruncated"]:
            next_marker = response["NextMarker"]
        else:
            break

    return None


def change_to_ip(domain, hosted_zone_id, ip_address):
    """Changes Route53 A record to point to a specific IP address."""
    change_batch = {
        "Changes": [
            {
                "Action": "UPSERT",
                "ResourceRecordSet": {
                    "Name": domain,
                    "Type": "A",
                    "TTL": 300,
                    "ResourceRecords": [{"Value": ip_address}],
                },
            }
        ]
    }
    route53_client.change_resource_record_sets(
        HostedZoneId=hosted_zone_id, ChangeBatch=change_batch
    )
    print(f"Switched {domain} to IP {ip_address}")


def change_to_cloudfront_alias(domain, hosted_zone_id):
    """Changes Route53 A record to point back to CloudFront alias."""
    distribution_id = get_distribution_id(domain)
    if distribution_id:
        distribution = cloudfront_client.get_distribution(Id=distribution_id)
        dns_name = distribution["Distribution"]["DomainName"]
        alias_target = {
            "DNSName": dns_name,
            "HostedZoneId": "Z2FDTNDATAQYW2",
            "EvaluateTargetHealth": False,
        }
        change_batch = {
            "Changes": [
                {
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": domain,
                        "Type": "A",
                        "AliasTarget": alias_target,
                    },
                }
            ]
        }
        route53_client.change_resource_record_sets(
            HostedZoneId=hosted_zone_id, ChangeBatch=change_batch
        )
        print(f"Switched {domain} back to CloudFront alias.")


def get_account_username_from_domain(domain, whm_host, api_token):
    """
    Fetches the account username associated with the specified domain from the WHM API.

    Args:
        domain (str): The domain for which to retrieve the account username.
        whm_host (str): The WHM host (server address).
        api_token (str): The WHM API token for authentication.

    Returns:
        str: The account username associated with the domain, or None if not found.
    """
    try:
        # Construct the request URI
        request_uri = (
            f"{whm_host}/json-api/accountsummary?api.version=1&domain={domain}"
        )

        # Set up the headers, including WHM API authentication
        headers = {"Authorization": f"whm root:{api_token}"}

        # Send the GET request
        response = requests.get(
            request_uri, headers=headers, verify=False
        )  # Disable SSL verification if needed

        # Check if the response was successful
        if response.status_code == 200:
            content = response.text
            json_data = json.loads(content)

            # Check if the 'data' and 'acct' properties exist
            if "data" in json_data and "acct" in json_data["data"]:
                for account in json_data["data"]["acct"]:
                    if "user" in account:
                        return account["user"]  # Return the account username
        else:
            print(
                f"Failed to get account summary for domain {domain}. Status Code: {response.status_code}, Response: {response.text}"
            )

    except Exception as e:
        print(f"Error while fetching account username for domain {domain}: {e}")

    return None


def update_ssl_for_domain(domain):
    """Performs the entire SSL update process for a given domain."""
    print(f"Starting SSL update process for {domain}")

    # Switch to IP and initiate SSL update
    try:
        switch_route53_alias(domain, True)  # Switch to IP
        user = get_account_username_from_domain(domain, WHM_SERVER, WHM_API_TOKEN)
        time.sleep(300)  # Wait for DNS propagation

        # Perform SSL deletion
        stdout, stderr = ssh_command(f"sudo whmapi1 delete_ssl_vhost host='{domain}'")
        if stderr or (stdout and "Failed to remove SSL vhost" in stdout):
            logging.warning(f"SSL deletion failed for {domain}: {stderr or stdout}")
            # Proceed with AutoSSL check even if deletion failed
        else:
            logging.info(f"SSL deleted successfully for {domain}")

        time.sleep(20)

        # Perform AutoSSL check regardless of deletion success
        stdout, stderr = ssh_command(f"sudo uapi --user={user} SSL start_autossl_check")
        if stderr:
            raise Exception(
                f"Failed to start AutoSSL check for {user} - {domain}: {stderr}"
            )

        print(f"AutoSSL check started for {user} - {domain}")

    except Exception as e:
        print(f"Error occurred while updating SSL for {domain}: {e}")
        send_email(
            f"SSL Update Failed for {domain}",
            f"An error occurred while updating SSL for {domain}. Error: {e}",
        )

    finally:
        # Always attempt to switch back to CloudFront regardless of success/failure
        try:
            switch_route53_alias(domain, False)  # Switch back to CloudFront
            print(f"Switched {domain} back to CloudFront alias.")
        except Exception as e:
            print(f"Failed to switch {domain} back to CloudFront: {e}")
            send_email(
                f"Failed to Switch Back to CloudFront for {domain}",
                f"An error occurred while switching {domain} back to CloudFront. Error: {e}",
            )


def get_distribution_id(domain):
    """Fetches the CloudFront distribution ID for a given domain."""
    distributions = cloudfront_client.list_distributions()["DistributionList"]["Items"]
    for dist in distributions:
        if domain in dist["Aliases"]["Items"]:
            return dist["Id"]
    return None


def nonCloudfront():
    message = ""
    for domain in non_cloudfront_domains:
        message += f"Not on Cloudfront: {domain}\n"

    message = message.rstrip("\n")
    send_email("Non Cloudfront Domain List", f"Domains not on cloudfront:\n{message}")


def main():
    cloudfront_domains = list_cloudfront_domains()
    nonCloudfront()
    print(f"Found {len(cloudfront_domains)} CloudFront domains.")

    expiring_certificates = get_expiring_ssl_certificates(27, cloudfront_domains)
    for cert in expiring_certificates:
        print(f"Domain: {cert['domain']}, Expiry Date: {cert['expiry_date']}")

    if not expiring_certificates:
        print("No SSL certificates expiring soon.")
        return

    print(f"Found {len(expiring_certificates)} expiring certificates. Updating...")

    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(
            update_ssl_for_domain, [cert["domain"] for cert in expiring_certificates]
        )


if __name__ == "__main__":
    main()
