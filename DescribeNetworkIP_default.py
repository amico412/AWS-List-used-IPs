# Import needed modules for the script to run
import boto3
from botocore.exceptions import ClientError
import botocore
import csv

# Environment Variables
csv_filename = "CUSTOMERNAME_used_ips.csv"
shared_role = "AWSControlTowerExecution"

# List accounts in the Organization
def GetAccountIds():
    client = boto3.client('organizations')
    
    # Creating an empty array to store accounts in org
    AccountID = []
    response = client.list_accounts()

    for account in response['Accounts']:
        # Find status and only add if active since deleted accounts could show as suspended
        if account['Status'] == 'ACTIVE':
            # Append the id field from the dict 
            AccountID.append(account['Id'])
            try:
                # Running a try block to make sure the Token field is empty. Some api calls do not return everything in one pass
                while response['NextToken'] is not None:
                    response = client.list_accounts(NextToken = response['NextToken'])
                    for account in response['Accounts']:
                        if account['Status'] == 'ACTIVE':
                            AccountID.append(account['Id'])
            except KeyError:
                continue
    return AccountID

# Get email associated with child account
def GetAccountEmail(account_id):
    client = boto3.client('organizations')

    response = client.describe_account(
        AccountId=account_id)
    account_email = response['Account']['Email']
    return account_email

 # Assume role from the master into the child account and pass credentials to a parameter
def assume_role(role_arn):
    sts_client = boto3.client('sts')
    try:
        assumedRoleObject = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='GetUsedIP'
        )
        return assumedRoleObject['Credentials']

    except botocore.exceptions.ClientError as error:
        pass
        print('Could not assume role into child account: ')
        print(error)

def list_used_ip(credentials,account_email,filename):
    client = boto3.client('ec2', 
                        aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken'],
                        )
    
    ec2_regions = [region['RegionName'] for region in client.describe_regions()['Regions']]
    
    for region in ec2_regions:
        ec2 = boto3.resource('ec2',
                            aws_access_key_id=credentials['AccessKeyId'],
                            aws_secret_access_key=credentials['SecretAccessKey'],
                            aws_session_token=credentials['SessionToken'],
                            region_name=region)

        for eni in ec2.network_interfaces.all():
            attachment_info = 'No attachment'
            if eni.attachment:
                if 'InstanceId' in eni.attachment:
                    attachment_info = eni.attachment['InstanceId']
                else:
                    attachment_info = eni.description
            
            # Set Name tag for subnet id
            describe_network = boto3.client('ec2',
                        aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken'],
                        region_name=region)

           # filter off the subnet id from the network interface
            subnet_filter = [{'Name': 'subnet-id', 'Values': [eni.subnet_id]}]
            subnet = describe_network.describe_subnets(Filters=subnet_filter)

            # Set the friendly name for the subnet
            try:
                # If subnet has a Name tag then update subnet_name value
                for subnet_tags in subnet['Subnets'][0]['Tags']:
                    if subnet_tags['Key'] == 'Name':
                        subnet_name = subnet_tags['Value']

            # If no name tag then catch the Key Error and set the name to the subnet id
            except KeyError:
                subnet_name = eni.subnet_id

            # filter off the vpc id from the network interface
            vpc_filter = [{'Name': 'vpc-id', 'Values': [eni.vpc_id]}]
            vpc = describe_network.describe_vpcs(Filters=vpc_filter)

            # Set the friendly name for the vpc
            try:
                # If vpc has a Name tag then update the vpc_name value
                for vpc_tags in vpc['Vpcs'][0]['Tags']:
                    if vpc_tags['Key'] == 'Name':
                        vpc_name = vpc_tags['Value']

            # if no name tag then catch KeyError and set the name to the vpc id
            except KeyError:
                vpc_name = eni.vpc_id

            rows = [ [eni.private_ip_address,attachment_info,eni.subnet.cidr_block,account_email,region,subnet_name,vpc_name,eni.vpc.cidr_block]]

            with open(filename, 'a') as csvfile:
                # Write row
                csvwriter = csv.writer(csvfile)
                csvwriter.writerows(rows)

def main():
    # Create csv file
    # field names 
    fields = ['IP address', 'Description', 'Subnet CIDR', 'Account Email','Region','Subnet Name','VPC Name','VPC CIDR']
    # Name of csv file
    filename = csv_filename
    with open(filename, 'w') as csvfile:
        csvwriter = csv.writer(csvfile)
        # Write colums
        csvwriter.writerow(fields)

    # Build empty AccountId array
    AccountId = []

    # Test on one account
    #AccountId = ['510468480186']

    # Get account id from organization
    AccountId = GetAccountIds()   

   # Loop through the account array
    for account in AccountId:
        # find account email
        account_email = GetAccountEmail(account)
        print(account_email)

        # Assume role into child account and execute governance items
        org_role_arn = 'arn:aws:iam::' + account + ':role/' + shared_role

        # Assume role into child account as Control Tower role
        try:
            child_credentials = assume_role(org_role_arn)

            # If statement to make sure we can assume a role into the account so that we don't stop the loop   
            if child_credentials != None:
                #print('This would get the IPs')

                list_used_ip(child_credentials,account_email,filename)

        except botocore.exceptions.ClientError as error:
            # Logging error but continue on with script
            pass
            print("Error occured in: " + account)

if __name__ == "__main__":
    main()