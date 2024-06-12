# AWS Account Decommissioning Tool, v1.3 AUTHOR: michael.quintero@rackspace.com
# PURPOSE: To provide the user insight into resources used for all regions within an account. Most importantly, also provides the ability to delete all resources within an account...very destructive!
# Usage: python3 aws_raze.py
# Note: User is expected to have already set credentials. Requirements are boto3 & colorama

import boto3
import time
from botocore.exceptions import ClientError
from colorama import Fore, Style, init

init(autoreset=True)

def get_account_info():
    sts_client = boto3.client('sts')
    try:
        account_id = sts_client.get_caller_identity()["Account"]
        return account_id
    except Exception as e:
        print(f"Error fetching AWS account information: {e}")
        return None

# Used the colorama library to improve readability, but may end up removing to keep the script tight
def print_disclaimer(account_id):
    print(Fore.RED +"#####################################################################")
    print(Fore.RED +"#                           DISCLAIMER                              #")
    print(Fore.RED +"#####################################################################")
    print(f"ATTENTION: You are currently logged into AWS Account ID: {account_id}")
    print("WARNING: This tool is designed for DESTRUCTIVE operations within an AWS account.")
    print("It is intended ONLY for use in decommissioning an AWS account or for specific")
    print("scenarios where all resources must be terminated or deleted.")
    print("")
    print("By using this tool, YOU ACKNOWLEDGE AND AGREE that:")
    print("")
    print("1. You have full knowledge of the actions this tool will perform.")
    print("2. You have verified that the resources managed by this tool can be safely deleted.")
    print("3. You accept all liability for the use of this tool.")
    print("4. This tool will TERMINATE ALL RESOURCES within the account")
    print("   across all regions configured in the script. This action CANNOT BE UNDONE.")
    print("")
    print("Please type 'I AGREE' to continue or 'EXIT' to terminate.")
    print(Fore.RED +"#####################################################################")
    print(Style.RESET_ALL)  

REGIONS = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']

# Functions for listing resources (printed when using the list option)
def list_ec2_instances(region):
    ec2 = boto3.client('ec2', region_name=region)
    instances = ec2.describe_instances()
    return instances['Reservations']

def list_ec2_volumes(region):
    ec2 = boto3.client('ec2', region_name=region)
    volumes = ec2.describe_volumes()
    return volumes['Volumes']

def list_s3_buckets():
    s3 = boto3.client('s3')
    response = s3.list_buckets()
    return response['Buckets']

def list_eks_clusters(region):
    eks = boto3.client('eks', region_name=region)
    clusters = eks.list_clusters()
    return clusters['clusters']

def list_rds_instances(region):
    rds = boto3.client('rds', region_name=region)
    instances = rds.describe_db_instances()
    return instances['DBInstances']

def list_guardduty_detectors(region):
    guardduty = boto3.client('guardduty', region_name=region)
    detectors = guardduty.list_detectors()
    return detectors['DetectorIds']

def list_cloudwatch_alarms(region):
    cloudwatch = boto3.client('cloudwatch', region_name=region)
    alarms = cloudwatch.describe_alarms()
    return alarms['MetricAlarms']

def list_sagemaker_notebooks(region):
    sagemaker = boto3.client('sagemaker', region_name=region)
    notebooks = sagemaker.list_notebook_instances()
    return notebooks['NotebookInstances']

def list_elb_load_balancers(region):
    elb = boto3.client('elb', region_name=region)
    response = elb.describe_load_balancers()
    return response['LoadBalancerDescriptions']

def list_alb_load_balancers(region):
    elbv2 = boto3.client('elbv2', region_name=region)
    try:
        response = elbv2.describe_load_balancers()
        return response['LoadBalancers']
    except Exception as e:
        print(f"Failed to list ALB load balancers in {region}: {e}")
        return []

def list_target_groups(region):
    elbv2 = boto3.client('elbv2', region_name=region)
    try:
        response = elbv2.describe_target_groups()
        target_groups = response['TargetGroups']
        return target_groups
    except Exception as e:
        print(f"Failed to list target groups in {region}: {e}")
        return []

def list_vpcs(region):
    ec2 = boto3.client('ec2', region_name=region)
    vpcs = ec2.describe_vpcs()
    return vpcs['Vpcs']

def list_security_hub_findings(region):
    securityhub = boto3.client('securityhub', region_name=region)
    try:
        findings = securityhub.get_findings()
        return findings['Findings']
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidAccessException':
            print(f"Security Hub is not enabled in region {region}")
            return []
        else:
            raise

def list_config_rules(region):
    config = boto3.client('config', region_name=region)
    rules = config.describe_config_rules()
    return rules['ConfigRules']

def list_kms_keys(region):
    kms = boto3.client('kms', region_name=region)
    keys = kms.list_keys()
    return keys['Keys']

def list_nat_gateways(region):
    ec2 = boto3.client('ec2', region_name=region)
    nat_gateways = ec2.describe_nat_gateways()
    return nat_gateways['NatGateways']

def list_elastic_ips(region):
    ec2 = boto3.client('ec2', region_name=region)
    addresses = ec2.describe_addresses()
    return addresses['Addresses']

def list_ebs_snapshots(region):
    ec2 = boto3.client('ec2', region_name=region)
    snapshots = ec2.describe_snapshots(OwnerIds=['self'])
    return snapshots['Snapshots']

# Functions for the delete actions, which are called under 'main'

def delete_ec2_instances(region):
    ec2 = boto3.client('ec2', region_name=region)
    reservations = list_ec2_instances(region)
    for reservation in reservations:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            instance_state = instance['State']['Name']

            if instance_state == 'terminated':
                continue

            if instance_state in ['running', 'stopped']:
                try:
                    describe_attribute = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute='disableApiTermination')
                    if describe_attribute['DisableApiTermination']['Value']:
                        ec2.modify_instance_attribute(InstanceId=instance_id, Attribute='disableApiTermination', Value='False')
                        print(f"Termination protection disabled for Instance: {instance_id}")

                    if instance_state == 'running':
                        ec2.stop_instances(InstanceIds=[instance_id])
                        print(f"Stopping EC2 Instance: {instance_id}")
                        waiter = ec2.get_waiter('instance_stopped')
                        waiter.wait(InstanceIds=[instance_id])
                        print(f"Instance {instance_id} stopped.")

                    ec2.terminate_instances(InstanceIds=[instance_id])
                    print(f"Terminated EC2 Instance: {instance_id}")
                except ClientError as e:
                    print(f"Error processing EC2 Instance {instance_id}: {e}")
            else:
                print(f"Instance {instance_id} is in '{instance_state}' state and cannot be processed for stop/terminate.")

def delete_ec2_volumes(region):
    ec2 = boto3.client('ec2', region_name=region)
    instances = list_ec2_instances(region)
    volumes = list_ec2_volumes(region)

    for volume in volumes:
        volume_id = volume['VolumeId']
        if volume['State'] == 'in-use' and volume.get('Attachments'):
            for attachment in volume['Attachments']:
                instance_id = attachment['InstanceId']
                instance_details = next((inst for res in instances for inst in res['Instances'] if inst['InstanceId'] == instance_id), None)

                if instance_details and volume_id == instance_details.get('RootDeviceName'):
                    print(f"Volume {volume_id} is the root device for instance {instance_id}. Attempting to stop the instance before detaching the volume.")
                    try:
                        ec2.stop_instances(InstanceIds=[instance_id])
                        print(f"Stopping instance {instance_id}.")
                        waiter = ec2.get_waiter('instance_stopped')
                        waiter.wait(InstanceIds=[instance_id])
                        print(f"Instance {instance_id} stopped.")
                        ec2.detach_volume(VolumeId=volume_id, InstanceId=instance_id)
                        print(f"Detaching root volume {volume_id} from {instance_id}.")
                    except ClientError as e:
                        print(f"Failed to stop instance or detach volume: {e}")
                        continue
        try:
            waiter = ec2.get_waiter('volume_available')
            waiter.wait(VolumeIds=[volume_id])
            ec2.delete_volume(VolumeId=volume_id)
            print(f"Deleted EC2 Volume: {volume_id}")
        except ClientError as e:
            print(f"Error deleting EC2 Volume {volume_id}: {e}")

def deregister_ami_for_snapshot(ec2_client, snapshot_id):
    amis = ec2_client.describe_images(Filters=[{'Name': 'block-device-mapping.snapshot-id', 'Values': [snapshot_id]}])
    for ami in amis['Images']:
        ami_id = ami['ImageId']
        print(f"Deregistering AMI {ami_id} that uses snapshot {snapshot_id}")
        ec2_client.deregister_image(ImageId=ami_id)
        print(f"AMI {ami_id} deregistered successfully.")

def delete_ebs_snapshots(region):
    ec2 = boto3.client('ec2', region_name=region)
    snapshots = list_ebs_snapshots(region)
    for snapshot in snapshots:
        snapshot_id = snapshot['SnapshotId']
        try:
            ec2.delete_snapshot(SnapshotId=snapshot_id)
            print(f"Deleted EBS Snapshot: {snapshot_id}")
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidSnapshot.InUse':
                print(f"Snapshot {snapshot_id} is in use and cannot be deleted. Attempting to deregister associated AMIs.")
                deregister_ami_for_snapshot(ec2, snapshot_id)
                try:
                    ec2.delete_snapshot(SnapshotId=snapshot_id)
                    print(f"Successfully deleted EBS Snapshot: {snapshot_id} after AMI deregistration.")
                except ClientError as e:
                    print(f"Final attempt failed to delete EBS Snapshot {snapshot_id}: {e}")
            else:
                print(f"Error deleting EBS Snapshot {snapshot_id}: {e}")

def delete_s3_buckets():
    s3 = boto3.client('s3')
    buckets = list_s3_buckets()
    for bucket in buckets:
        try:
            paginator = s3.get_paginator('list_objects_v2')
            page_iterator = paginator.paginate(Bucket=bucket['Name'])
            for page in page_iterator:
                if 'Contents' in page:
                    for obj in page['Contents']:
                        s3.delete_object(Bucket=bucket['Name'], Key=obj['Key'])
            s3.delete_bucket(Bucket=bucket['Name'])
            print(f"Deleted S3 Bucket: {bucket['Name']}")
        except ClientError as e:
            print(f"Error deleting S3 Bucket {bucket['Name']}: {e}")

def delete_elastic_ips(region):
    ec2 = boto3.client('ec2', region_name=region)
    try:
        eips = ec2.describe_addresses()
        for eip in eips['Addresses']:
            if 'AssociationId' not in eip:
                try:
                    ec2.release_address(AllocationId=eip['AllocationId'])
                    print(f"Released Elastic IP: {eip['PublicIp']} (Allocation ID: {eip['AllocationId']})")
                except ClientError as e:
                    print(f"Failed to release Elastic IP {eip['PublicIp']} (Allocation ID: {eip['AllocationId']}): {e}")
            else:
                print(f"Elastic IP {eip['PublicIp']} is currently associated, skipping release.")
    except ClientError as e:
        print(f"Error retrieving Elastic IPs: {e}")

def delete_eks_clusters(region):
    eks = boto3.client('eks', region_name=region)
    clusters = list_eks_clusters(region)

    for cluster_name in clusters:
        try:
            nodegroups = eks.list_nodegroups(clusterName=cluster_name)['nodegroups']
            for nodegroup in nodegroups:
                eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup)
                print(f"Deleting node group {nodegroup} in cluster {cluster_name}")

            fargate_profiles = eks.list_fargate_profiles(clusterName=cluster_name)['fargateProfileNames']
            for profile in fargate_profiles:
                eks.delete_fargate_profile(clusterName=cluster_name, fargateProfileName=profile)
                print(f"Deleting Fargate profile {profile} in cluster {cluster_name}")
        except ClientError as e:
            print(f"Failed to delete resources in {cluster_name}: {e}")
            continue

        try:
            eks.delete_cluster(name=cluster_name)
            print(f"Initiated deletion of EKS Cluster: {cluster_name}")
            
            while True:
                response = eks.describe_cluster(name=cluster_name)
                if response['cluster']['status'] == 'DELETING':
                    print(f"Waiting for deletion of cluster {cluster_name}")
                    time.sleep(30)
                else:
                    break
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                print(f"Cluster {cluster_name} successfully deleted.")
            else:
                print(f"Failed to delete EKS Cluster {cluster_name}: {e}")

def delete_rds_instances(region):
    rds = boto3.client('rds', region_name=region)
    instances = list_rds_instances(region)
    for instance in instances:
        instance_id = instance['DBInstanceIdentifier']
        instance_state = instance['DBInstanceStatus']

        if instance_state in ['available', 'failed', 'incompatible-network', 'incompatible-option-group', 'incompatible-parameters', 'incompatible-restore']:
            try:
                rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
                print(f"Deleted RDS Instance: {instance_id}")
            except ClientError as e:
                print(f"Error deleting RDS Instance {instance_id}: {e}")
        else:
            print(f"RDS Instance {instance_id} is in state '{instance_state}' and cannot be deleted at this time.")

def delete_guardduty_detectors(region):
    guardduty = boto3.client('guardduty', region_name=region)
    detectors = list_guardduty_detectors(region)
    
    for detector_id in detectors:
        try:
            guardduty.delete_detector(DetectorId=detector_id)
            print(f"Deleted GuardDuty Detector: {detector_id}")
        except ClientError as e:
            print(f"Failed to delete GuardDuty Detector {detector_id} in {region}: {e}")

def delete_cloudwatch_alarms(region):
    cloudwatch = boto3.client('cloudwatch', region_name=region)
    alarms = list_cloudwatch_alarms(region)
    for alarm in alarms:
        alarm_name = alarm['AlarmName']
        cloudwatch.delete_alarms(AlarmNames=[alarm_name])
        print(f"Deleted CloudWatch Alarm: {alarm_name}")

def delete_sagemaker_notebooks(region):
    sagemaker = boto3.client('sagemaker', region_name=region)
    notebooks = list_sagemaker_notebooks(region)
    for notebook in notebooks:
        notebook_name = notebook['NotebookInstanceName']
        sagemaker.delete_notebook_instance(NotebookInstanceName=notebook_name)
        print(f"Deleted SageMaker Notebook: {notebook_name}")

def delete_elb_load_balancers(region):
    elb = boto3.client('elb', region_name=region)
    load_balancers = list_elb_load_balancers(region)
    for lb in load_balancers:
        lb_name = lb['LoadBalancerName']
        
        instances = elb.describe_instance_health(LoadBalancerName=lb_name)['InstanceStates']
        instance_ids = [{'InstanceId': inst['InstanceId']} for inst in instances if inst['State'] == 'InService']
        if instance_ids:
            elb.deregister_instances_from_load_balancer(LoadBalancerName=lb_name, Instances=instance_ids)
            print(f"Deregistered instances from ELB: {lb_name}")

        elb.delete_load_balancer(LoadBalancerName=lb_name)
        print(f"Deleted ELB Load Balancer: {lb_name}")

def delete_alb_load_balancers(region):
    elbv2 = boto3.client('elbv2', region_name=region)
    load_balancers = list_alb_load_balancers(region)
    for lb in load_balancers:
        lb_arn = lb['LoadBalancerArn']

        try:
            target_groups = elbv2.describe_target_groups(LoadBalancerArn=lb_arn)['TargetGroups']
        except Exception as e:
            print(f"Failed to retrieve target groups for {lb['LoadBalancerName']}: {e}")
            continue 

        for tg in target_groups:
            try:
                targets = elbv2.describe_target_health(TargetGroupArn=tg['TargetGroupArn'])['TargetHealthDescriptions']
                target_ids = [{'Id': target['Target']['Id']} for target in targets if target['TargetHealth']['State'] == 'healthy']
                if target_ids:
                    elbv2.deregister_targets(TargetGroupArn=tg['TargetGroupArn'], Targets=target_ids)
                    print(f"Deregistered targets from target group {tg['TargetGroupName']}")
            except Exception as e:
                print(f"Error deregistering targets in {tg['TargetGroupName']}: {e}")

        try:
            elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
            print(f"Deleted ALB Load Balancer: {lb['LoadBalancerName']} (ARN: {lb_arn})")
        except boto3.exceptions.Boto3Error as e:
            print(f"Error deleting ALB Load Balancer {lb['LoadBalancerName']} (ARN: {lb_arn}): {e}")

def delete_vpcs(region):
    ec2 = boto3.client('ec2', region_name=region)
    vpcs = list_vpcs(region)
    for vpc in vpcs:
        vpc_id = vpc['VpcId']
        ec2.delete_vpc(VpcId=vpc_id)
        print(f"Deleted VPC: {vpc_id}")

def delete_config_rules(region):
    config = boto3.client('config', region_name=region)
    rules = list_config_rules(region)

    for rule in rules:
        rule_name = rule['ConfigRuleName']
        if rule.get('CreatedBy'):
            print(f"Skipping deletion of service-linked Config Rule: {rule_name}")
            continue

        try:
            config.delete_config_rule(ConfigRuleName=rule_name)
            print(f"Deleted Config Rule: {rule_name}")
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDeniedException':
                print(f"Access denied for deleting Config Rule {rule_name}. Rule may be service-linked or managed by AWS.")
            else:
                print(f"Failed to delete Config Rule {rule_name}: {e}")

def delete_kms_keys(region):
    kms = boto3.client('kms', region_name=region)
    keys = list_kms_keys(region)
    for key in keys:
        key_id = key['KeyId']
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
        print(f"Scheduled KMS Key for deletion: {key_id}")

def delete_target_groups(region):
    elbv2 = boto3.client('elbv2', region_name=region)
    target_groups = list_target_groups(region)

    load_balancers = elbv2.describe_load_balancers()['LoadBalancers']
    
    for tg in target_groups:
        tg_arn = tg['TargetGroupArn']

        for lb in load_balancers:
            lb_arn = lb['LoadBalancerArn']

            try:
                listeners = elbv2.describe_listeners(LoadBalancerArn=lb_arn)['Listeners']
                for listener in listeners:
                    for action in listener['DefaultActions']:
                        if action['Type'] == 'forward' and action['TargetGroupArn'] == tg_arn:
                            elbv2.delete_listener(ListenerArn=listener['ListenerArn'])
                            print(f"Deleted listener {listener['ListenerArn']} that was using target group {tg_arn}")

                elbv2.delete_target_group(TargetGroupArn=tg_arn)
                print(f"Deleted target group: {tg['TargetGroupName']} (ARN: {tg_arn})")
            except boto3.exceptions.Boto3Error as e:
                print(f"Failed to delete target group {tg['TargetGroupName']} (ARN: {tg_arn}): {e}")

def delete_load_balancers_and_target_groups(region):
    elbv2 = boto3.client('elbv2', region_name=region)
    elb = boto3.client('elb', region_name=region)

    elb_load_balancers = elb.describe_load_balancers()['LoadBalancerDescriptions']
    alb_load_balancers = elbv2.describe_load_balancers()['LoadBalancers']

    for lb in elb_load_balancers:
        lb_name = lb['LoadBalancerName']

        instances = elb.describe_instance_health(LoadBalancerName=lb_name)['InstanceStates']
        instance_ids = [{'InstanceId': inst['InstanceId']} for inst in instances if inst['State'] == 'InService']
        if instance_ids:
            elb.deregister_instances_from_load_balancer(LoadBalancerName=lb_name, Instances=instance_ids)
            print(f"Deregistered instances from ELB: {lb_name}")

        elb.delete_load_balancer(LoadBalancerName=lb_name)
        print(f"Deleted ELB Load Balancer: {lb_name}")

    for lb in alb_load_balancers:
        lb_arn = lb['LoadBalancerArn']

        listeners = elbv2.describe_listeners(LoadBalancerArn=lb_arn)['Listeners']
        for listener in listeners:
            elbv2.delete_listener(ListenerArn=listener['ListenerArn'])
            print(f"Deleted listener {listener['ListenerArn']}")

        target_groups = elbv2.describe_target_groups(LoadBalancerArn=lb_arn)['TargetGroups']
        for tg in target_groups:
            targets = elbv2.describe_target_health(TargetGroupArn=tg['TargetGroupArn'])['TargetHealthDescriptions']
            target_ids = [{'Id': target['Target']['Id']} for target in targets if target['TargetHealth']['State'] == 'healthy']
            if target_ids:
                elbv2.deregister_targets(TargetGroupArn=tg['TargetGroupArn'], Targets=target_ids)
                print(f"Deregistered targets from target group {tg['TargetGroupName']}")

        elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
        print(f"Deleted ALB Load Balancer: {lb['LoadBalancerName']} (ARN: {lb_arn})")

    all_target_groups = elbv2.describe_target_groups()['TargetGroups']
    for tg in all_target_groups:
        try:
            elbv2.delete_target_group(TargetGroupArn=tg['TargetGroupArn'])
            print(f"Deleted target group: {tg['TargetGroupName']} (ARN: {tg['TargetGroupArn']})")
        except boto3.exceptions.Boto3Error as e:
            print(f"Failed to delete target group {tg['TargetGroupName']} (ARN: {tg['TargetGroupArn']}): {e}")

def delete_nat_gateways(region):
    ec2 = boto3.client('ec2', region_name=region)
    nat_gateways = list_nat_gateways(region)

    for ng in nat_gateways:
        ng_id = ng['NatGatewayId']
        
        if ng['State'] in ['pending', 'deleting']:
            print(f"NAT Gateway {ng_id} is in {ng['State']} state, skipping deletion.")
            continue

        for address in ng.get('NatGatewayAddresses', []):
            if 'AllocationId' in address:
                allocation_id = address['AllocationId']
                try:
                    response = ec2.describe_addresses(AllocationIds=[allocation_id])
                    if response['Addresses']:
                        ec2.release_address(AllocationId=allocation_id)
                        print(f"Released EIP associated with NAT Gateway {ng_id}")
                    else:
                        print(f"No Elastic IP found for Allocation ID: {allocation_id}, skipping.")
                except ClientError as e:
                    if e.response['Error']['Code'] == 'InvalidAllocationID.NotFound':
                        print(f"The allocation ID '{allocation_id}' does not exist, it may have already been released.")
                    else:
                        print(f"Failed to release EIP for {allocation_id}: {e}")
                        if e.response['Error']['Code'] == 'AuthFailure':
                            print("Check IAM permissions: Ensure the IAM role has ec2:ReleaseAddress permission.")
        try:
            ec2.delete_nat_gateway(NatGatewayId=ng_id)
            print(f"Deleting NAT Gateway {ng_id}")
        except ClientError as e:
            print(f"Failed to delete NAT Gateway {ng_id}: {e}")


def print_resources(region, service_name, resources):
    if resources:
        print(f"\n--- {service_name} ---")
        for resource in resources:
            print(resource)

def print_target_groups(region):
    target_groups = list_target_groups(region)
    formatted_target_groups = [
        f"Target Group Name: {tg['TargetGroupName']}, ARN: {tg['TargetGroupArn']}, Protocol: {tg['Protocol']}"
        for tg in target_groups
    ]
    print_resources(region, "Target Groups", formatted_target_groups)

def main():
    account_id = get_account_info()
    if not account_id:
        print("Unable to verify AWS account. Exiting.")
        return

    print_disclaimer(account_id)
    agreement = input("Your choice (I AGREE/EXIT): ")
    if agreement.upper() != "I AGREE":
        print("Exiting tool. No actions have been performed.")
        return

    action = input("Do you want to list all account resources or delete all account resources? Choose carefully (list/delete): ")
    if action == "list":
        s3_buckets = list_s3_buckets()
        print_resources("global", "S3 Buckets", [f"Bucket Name: {bucket['Name']}" for bucket in s3_buckets])

    for region in REGIONS:
        print(f"\n {Fore.YELLOW} #################### REGION: {region}  #################### {Style.RESET_ALL}")
        
        if action == "list":
            ec2_instances = list_ec2_instances(region)
            filtered_instances = [f"Instance ID: {instance['InstanceId']}, State: {instance['State']['Name']}"
                                  for reservation in ec2_instances
                                  for instance in reservation['Instances']
                                  if instance['State']['Name'] != 'terminated']

            print_resources(region, "EC2 Instances", filtered_instances)

            ec2_volumes = list_ec2_volumes(region)
            print_resources(region, "EC2 Volumes", [f"Volume ID: {volume['VolumeId']}, State: {volume['State']}" for volume in ec2_volumes])

            eks_clusters = list_eks_clusters(region)
            print_resources(region, "EKS Clusters", [f"Cluster Name: {cluster}" for cluster in eks_clusters])

            rds_instances = list_rds_instances(region)
            print_resources(region, "RDS Instances", [f"DB Instance Identifier: {instance['DBInstanceIdentifier']}, Status: {instance['DBInstanceStatus']}" for instance in rds_instances])

            guardduty_detectors = list_guardduty_detectors(region)
            print_resources(region, "GuardDuty Detectors", [f"Detector ID: {detector}" for detector in guardduty_detectors])

            cloudwatch_alarms = list_cloudwatch_alarms(region)
            print_resources(region, "CloudWatch Alarms", [f"Alarm Name: {alarm['AlarmName']}, State: {alarm['StateValue']}" for alarm in cloudwatch_alarms])

            sagemaker_notebooks = list_sagemaker_notebooks(region)
            print_resources(region, "SageMaker Notebooks", [f"Notebook Name: {notebook['NotebookInstanceName']}, Status: {notebook['NotebookInstanceStatus']}" for notebook in sagemaker_notebooks])

            elb_load_balancers = list_elb_load_balancers(region)
            formatted_load_balancers = [
                f"Load Balancer Name: {lb['LoadBalancerName']}, DNS Name: {lb['DNSName']}" 
                for lb in elb_load_balancers
            ]
            print_resources(region, "Elastic Load Balancers", formatted_load_balancers)

            alb_load_balancers = list_alb_load_balancers(region)
            print_resources(region, "ALB Load Balancers", [f"Load Balancer Name: {lb}" for lb in alb_load_balancers])

            print_target_groups(region)

            vpcs = list_vpcs(region)
            print_resources(region, "VPCs", [f"VPC ID: {vpc['VpcId']}, State: {vpc['State']}" for vpc in vpcs])

            security_hub_findings = list_security_hub_findings(region)
            print_resources(region, "Security Hub Findings", [f"Finding ID: {finding['Id']}, Severity: {finding['Severity']['Label']}" for finding in security_hub_findings])

            config_rules = list_config_rules(region)
            print_resources(region, "Config Rules", [f"Config Rule Name: {rule['ConfigRuleName']}, Compliance: {rule['Compliance']['ComplianceType'] if 'Compliance' in rule else 'N/A'}" for rule in config_rules])

            kms_keys = list_kms_keys(region)
            print_resources(region, "KMS Keys", [f"Key ID: {key['KeyId']}" for key in kms_keys])

            nat_gateways = list_nat_gateways(region)
            print_resources(region, "NAT Gateways", [f"NAT Gateway ID: {nat_gateway['NatGatewayId']}, State: {nat_gateway['State']}" for nat_gateway in nat_gateways])

            elastic_ips = list_elastic_ips(region)
            print_resources(region, "Elastic IPs", [f"Elastic IP: {address['PublicIp']}, Allocation ID: {address['AllocationId']}" for address in elastic_ips])

            ebs_snapshots = list_ebs_snapshots(region)
            print_resources(region, "EBS Snapshots", [f"Snapshot ID: {snapshot['SnapshotId']}, State: {snapshot['State']}, Volume Size: {snapshot['VolumeSize']} GB" for snapshot in ebs_snapshots])

        elif action == "delete":
            confirm = input("Are you sure you want to delete all listed resources? There is no going back! (yes/no): ")
            if confirm.lower() == 'yes':
                delete_load_balancers_and_target_groups(region)
                delete_ec2_instances(region)
                delete_rds_instances(region)
                delete_ec2_volumes(region)
                delete_ebs_snapshots(region)
                delete_eks_clusters(region)
                delete_nat_gateways(region)
                delete_elastic_ips(region)
                delete_guardduty_detectors(region)
                delete_cloudwatch_alarms(region)
                delete_sagemaker_notebooks(region)
                delete_s3_buckets()
                delete_config_rules(region)
            else:
                print("Deletion cancelled.")

        else:
            print("Invalid selection. Please choose 'list' or 'delete'.")

if __name__ == "__main__":
    main()
