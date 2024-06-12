
# AWS Account Decommissioning Tool

## Author
Michael Quintero (michael.quintero@rackspace.com)

## Description
This tool is designed to provide insight into AWS resources across all regions within an account and to delete said resources. To be used in scenarios requiring the complete decommissioning of an AWS account. It's currently configured for many AWS resources, but new ones can be added at anytime.
Currently, will list/delete the following: ALB/ELB, Target Groups, EC2 Instances, EBS Volumes/Snapshots, RDS Instances, EKS Clusters, NAT Gateways, Elastic IPs, Cloudwatch Alarms, Sagemaker Notebooks, S3 Buckets and files, and GuardDuty Detectors.

## Version
1.3

## Warning
**This tool performs destructive operations within an AWS account and is only intended for decommissioning. Ensure that all resources managed by this tool are backed up or safely deletable before proceeding.**

## Requirements
- Python 3.x
- AWS CLI
- boto3
- colorama

## Setup
1. Ensure Python 3.x is installed on your system.
2. Install required Python libraries:
   ```
   pip install -r requirements.txt
   ```
3. If you're not copy/pasting Janus temp creds, then configure AWS CLI with credentials having administrative access to the AWS account:
   ```
   aws configure
   ```

## Usage
Run the script with:
```
python3 aws_raze.py
```

### Operations
- **List**: Enumerate all resources across all configured AWS regions.
- **Delete**: Irreversibly delete all listed resources.

### Disclaimer
Upon running, the tool will display a disclaimer requiring explicit agreement to proceed with the listing or deletion operations.

## License
This script is provided "as is", without warranty of any kind, express or implied. Use at your own risk.

## Support
For issues or support, contact michael.quintero@rackspace.com.
