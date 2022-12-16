# Use AWS-CLI to deploy VPC network and Ec2 Instance 
#### Summary
##### We all know AWS and related infrastructure is widley managed using tools like Terraform. I created this project to compare and see how aws-cli tool can be used to deploy a VPC network which will have two publicly accessible subnets and a private subnet whose accessibility will be limited within the VPC. Followed by deploying three Ec2 instances used for three specific purposes.

##### This project is built upon the following AWS resoruces.
- VPC
- Subnets
- Route Tables
- Internet Gateway
- NAT-Gateway
- Elastic IP address
- Security Groups
- Key-pair
- Ec2 Instances

#### Flow Chart Diagram of the architecture
[![Flow Chart](https://github.com/sreejithsnair1989/aws-cli-vpc-build/blob/main/VPC%20Project%20Flowchart.jpg)
## Prerequisite
##### Before we begin, this project require AWS-CLI to be installed locally on your system. This help [article](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html "AWS-CLI") demonstrates how to install AWS-CLI on all three major Operating Systems such as Windows, Linux & MacOS.

## Let's Begin...

### Create IAM user and configure AWS-CLI
```
$ aws iam create-user --user-name vpc-admin --tags '{"Key": "Name", "Value": "vpc-admin-iam"}'
{
    "User": {
        "Path": "/",
        "UserName": "vpc-admin",
        "UserId": "AIDAYSCSUUJBSP5YG34AJ",
        "Arn": "arn:aws:iam::588583838275:user/vpc-admin",
        "CreateDate": "2022-12-16T02:30:00+00:00",
        "Tags": [
            {
                "Key": "Name",
                "Value": "vpc-admin-iam"
            }
        ]
    }
}

$ aws iam create-access-key --user-name vpc-admin
{
    "AccessKey": {
        "UserName": "vpc-admin",
        "AccessKeyId": "#############",
        "Status": "Active",
        "SecretAccessKey": "##########################",
        "CreateDate": "2022-12-16T02:36:45+00:00"
    }
}
$ aws iam attach-user-policy --user-name vpc-admin --policy-arn arn:aws:iam::aws:policy/AmazonVPCFullAccess

$ aws iam attach-user-policy --user-name vpc-admin --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess

$ aws configure --profile=vpc-admin
AWS Access Key ID [None]: ###############
AWS Secret Access Key [None]: ###############
Default region name [None]: ap-south-1              ##This project uses ap-south-1 [ AWS Mumbai] Region
Default output format [None]: json
```
##### Now, our aws-cli tool is all ready to spin up the project that we are working on.
## VPC
##### This infrastructure is built on single VPC using IP address from 172.16.0.0/16 range. All three subnets and Ec2 Instances are deployed under this VPC. Using the aws-cli tool, we will create the VPC and add appropriate tags for better tracking.

### Create VPC
```
vpc_id=$(aws ec2 create-vpc --cidr-block 172.16.0.0/16 --query Vpc.VpcId --output text --profile=vpc-admin)

aws ec2 create-tags --resource $vpc_id --tags '{"Key": "Name", "Value": "vpc-demo"}' --profile=vpc-admin ##Add tags for better tracking
```
##### Now that the VPC is live, we need to enable the option to allocate DNS hostnames automatically for instances that will be created under this VPC.

## Enable DNS Hostname
```
$ aws ec2 modify-vpc-attribute --vpc-id $vpc_id --enable-dns-hostnames --profile=vpc-admin
```
## Subnets
##### Total three subnets are required to pull this project off. Two public subnets where the frontend webserver and the bastion server will be deployed. The database server will be deployed on a private subnet that is only accessible within the VPC network.

### Create Subnets

#### Public-1 Subnet
```
pub_1=$(aws ec2 create-subnet --vpc-id $vpc_id --cidr-block 172.16.0.0/18 --availability-zone ap-south-1a --tag-specifications 'ResourceType=subnet, Tags=[{Key=Name,Value=subnet-public-1}]' --query Subnet.SubnetId --output text --profile=vpc-admin)

aws ec2 modify-subnet-attribute --subnet-id $pub_1 --map-public-ip-on-launch --profile=vpc-admin ##Attach public IP to Ec2 instances created under this Subnet.
```
#### Public-2 Subnet
```
$ pub_2=$(aws ec2 create-subnet --vpc-id $vpc_id --cidr-block 172.16.64.0/18 --availability-zone ap-south-1b --tag-specifications 'ResourceType=subnet, Tags=[{Key=Name,Value=subnet-public-2}]' --query Subnet.SubnetId --output text --profile=vpc-admin)

$ aws ec2 modify-subnet-attribute --subnet-id $pub_2 --map-public-ip-on-launch --profile=vpc-admin ##Attach public IP to Ec2 instances created under this Subnet.
```

#### Private-1 Subnet
```
$ priv_1=$(aws ec2 create-subnet --vpc-id $vpc_id --cidr-block 172.16.128.0/18 --availability-zone ap-south-1b --tag-specifications 'ResourceType=subnet, Tags=[{Key=Name,Value=subnet-private-1}]' --query Subnet.SubnetId --output text --profile=vpc-admin)

##Since instance deployed in private subnet doesn't require a Public IP, we are omtting this operation.
```
## Internet Gateway
##### As you all are aware, without an Internet Gateway point, there is no way for the VPC to interract with the public Internet which makes Internet Gateway an integral part of this setup. For this project, we require one Internet gateway that will responsible for all outbound communication from both public subnets.

#### Create Internet Gateway
```
$ igw_id=$(aws ec2 create-internet-gateway --tag-specifications 'ResourceType=internet-gateway, Tags=[{Key=Name,Value=igw-1}]' --query InternetGateway.InternetGatewayId --output text --profile=vpc-admin)
```

#### Attach Intergateway to VPC
```
$ aws ec2 attach-internet-gateway --vpc-id $vpc_id --internet-gateway-id $igw_id
```
## Elastic IP address
##### As you may already aware, NAT-Gateway require an additional IP address to perform outbound communication to the public internet. This IP requirement is full-filled by pruchasing an Elastic-IP address and attaching it to the NAT-Gateway.

#### Purchse Elastic-IP address
```
$ alloc_id=$(aws ec2 allocate-address --query AllocationId --output text --profile=vpc-admin)
```
## NAT-Gateway
##### Although the backend server is designed and deployed as a parivate instance that won't be accessible to public traffic. A NAT-Gateway is added to this project to accomodate the requirement that at some point, the backend server might need an internet connectivity in order to perform maintenance in the form of application/programs updates or install new packages etc. 

#### Create NAT_Gateway
```
$ nat_id=$(aws ec2 create-nat-gateway --subnet-id $pub_2 --tag-specifications 'ResourceType=natgateway, Tags=[{Key=Name,Value=nat-gw1}]' --allocation-id $alloc_id --query NatGateway.NatGatewayId --output text --profile=vpc-admin)
```

## Route Table
##### This setup require two route tables to acheieve routing within the VPC and guide the outbound traffic towards the Internet Gateway. A public route-table will be deployed to manage the traffic in and out of the two public subnets whereas, the private subnet traffic will be handled using a private route-table.


#### Create Public Route table

```
$ pub_rtb=$(aws ec2 create-route-table --vpc-id $vpc_id --tag-specifications 'ResourceType=route-table, Tags=[{Key=Name,Value=public-rtb}]' --query RouteTable.RouteTableId --output text --profile=vpc-admin)
```
#### Insert Public Route data
```
$ aws ec2 create-route --route-table-id $pub_rtb --destination-cidr-block 0.0.0.0/0 --gateway-id $igw_id --profile=vpc-admin
{
    "Return": true
}
##Route outbound traffic to InternetGateway
```
#### Attach Public Route table to public-1 Subnet
```
$ aws ec2 associate-route-table --subnet-id $pub_1 --route-table-id $pub_rtb --profile=vpc-admin
{
    "AssociationId": "rtbassoc-08f8a4f71ecd2e4e6",
    "AssociationState": {
        "State": "associated"
    }
}
```
#### Attach Public Route table to public-2 Subnet
```
aws ec2 associate-route-table --subnet-id $pub_2 --route-table-id $pub_rtb --profile=vpc-admin
{
    "AssociationId": "rtbassoc-058f31c8b753aabb1",
    "AssociationState": {
        "State": "associated"
    }
}
```

#### Create Private Route table
```
$ priv_rtb=$(aws ec2 create-route-table --vpc-id $vpc_id --tag-specifications 'ResourceType=route-table, Tags=[{Key=Name,Value=zomato-private-rtb}]' --query RouteTable.RouteTableId --output text --profile=vpc-admin)
```
#### Insert Private Route data
```
$ aws ec2 create-route --route-table-id $priv_rtb --destination-cidr-block 0.0.0.0/0 --nat-gateway-id $nat_id --profile=vpc-admin
{
    "Return": true
}
```
#### Attach Private Route table to Private-1 Subnet
```
$ aws ec2 associate-route-table --subnet-id $priv_1 --route-table-id $priv_rtb --profile=vpc-admin
{
    "AssociationId": "rtbassoc-046f353bd6117224c",
    "AssociationState": {
        "State": "associated"
    }
}
```
## Secutiy Groups
##### This project deploy three different Security Groups that will be attached to the Ec2 instances to filter the incoming traffic to that particular instance. The bastion server's security group would allow all incoming traffic on port 22 on the other hand, the frontend server will allow all incoming traffic on port 80 & 443 while it only allows bastion server to connect to its port 22 for SSH access. When it comes to the backend server, it will allow traffic on port 3306 from the frotend server at the same time it will also open to incoming connection from bastion server on port 22 for SSH access.

### Create Security Group & Add Traffic Rule for Bastion-Server
```
$ bastion_sg=$(aws ec2 create-security-group --group-name bastion-server --description "Allow SSH from all IP" --vpc-id $vpc_id --tag-specifications 'ResourceType=security-group, Tags=[{Key=Name,Value=bastion-server}]' --query GroupId --output text --profile=vpc-admin)

$ aws ec2 authorize-security-group-ingress --group-id $bastion_sg --protocol tcp --port 22 --cidr 0.0.0.0/0 --profile=vpc-admin
{
    "Return": true,
    "SecurityGroupRules": [
        {
            "SecurityGroupRuleId": "sgr-0b3269ead51258755",
            "GroupId": "sg-0da4fb2de1f160fb3",
            "GroupOwnerId": "588583838275",
            "IsEgress": false,
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "CidrIpv4": "0.0.0.0/0"
        }
    ]
}
```

### Create Security Group & Add Traffic Rule for Frontend-Server
```
$ frontend_sg=$(aws ec2 create-security-group --group-name frontend-server --description "Allow SSH from bastion-server and HTTP/S from Public" --vpc-id $vpc_id --tag-specifications 'ResourceType=security-group, Tags=[{Key=Name,Value=frontend-server}]' --query GroupId --output text --profile=vpc-admin)

##Allow SSH traffic from Bastion-server
$ aws ec2 authorize-security-group-ingress --group-id $frontend_sg --protocol tcp --protocol tcp --port 22 --source-group $bastion_sg --profile=vpc-admin
{
    "Return": true,
    "SecurityGroupRules": [
        {
            "SecurityGroupRuleId": "sgr-0f925fc165cb26beb",
            "GroupId": "sg-006869555048b7183",
            "GroupOwnerId": "588583838275",
            "IsEgress": false,
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "ReferencedGroupInfo": {
                "GroupId": "sg-0da4fb2de1f160fb3",
                "UserId": "588583838275"
            }
        }
    ]
}

##Allow HTTP/S traffic from public
$ aws ec2 authorize-security-group-ingress --group-id $frontend_sg --protocol tcp --port 80 --port 443 --cidr 0.0.0.0/0 --profile=vpc-admin
{
    "Return": true,
    "SecurityGroupRules": [
        {
            "SecurityGroupRuleId": "sgr-0ee53bb4bc8b377e6",
            "GroupId": "sg-006869555048b7183",
            "GroupOwnerId": "588583838275",
            "IsEgress": false,
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "CidrIpv4": "0.0.0.0/0"
        }
    ]
}
```
### Create Security Group & Add Traffic Rule for Backend-Server
```
$ backend_sg=$(aws ec2 create-security-group --group-name backend-server --description "Allow SSH from bastion-server and MYSQL from frontend-server" --vpc-id $vpc_id --tag-specifications 'ResourceType=security-group, Tags=[{Key=Name,Value=backend-server}]' --query GroupId --output text --profile=vpc-admin)

##Allow SSH traffic from Bastion-server
$ aws ec2 authorize-security-group-ingress --group-id $backend_sg --protocol tcp --protocol tcp --port 22 --source-group $bastion_sg --profile=vpc-admin
{
    "Return": true,
    "SecurityGroupRules": [
        {
            "SecurityGroupRuleId": "sgr-056ad0fc480498326",
            "GroupId": "sg-0f7f8ee1e53a62ee5",
            "GroupOwnerId": "588583838275",
            "IsEgress": false,
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "ReferencedGroupInfo": {
                "GroupId": "sg-0da4fb2de1f160fb3",
                "UserId": "588583838275"
            }
        }
    ]
}

##Allow MariaDB/Aurora Traffic from Frontend-server
$ aws ec2 authorize-security-group-ingress --group-id $backend_sg --protocol tcp --port 3306 --source-group $frontend_sg --profile=vpc-admin
{
    "Return": true,
    "SecurityGroupRules": [
        {
            "SecurityGroupRuleId": "sgr-02a5dba8a9f2d2f47",
            "GroupId": "sg-0f7f8ee1e53a62ee5",
            "GroupOwnerId": "588583838275",
            "IsEgress": false,
            "IpProtocol": "tcp",
            "FromPort": 3306,
            "ToPort": 3306,
            "ReferencedGroupInfo": {
                "GroupId": "sg-006869555048b7183",
                "UserId": "588583838275"
            }
        }
    ]
}
```
## Key-Pairs
##### All Ec2 instances deployed as a part of this project use the same key-pair for SSH authentication.

### Create Key-piar
```
$ aws ec2 create-key-pair --key-name secret-key --query 'KeyMaterial' --output text > secret-key.pem --profile=vpc-admin

##Change permission of the key-pair file
$ chmod 400 secret-key.pem
```
## Ec2 Instance
##### Coming down to the important part of the project, this setup require three Ec2 instances to roll-out Frontend-server where services like Apache,  PHP and the site files will be deployed. The second Ec2 instance is dedicated for hosting a database server where we will be running MariaDB server. Third and final Ec2 instance is created for leveraging SSH access to both frontend-server and backend-server as well a point of contact for Public users.

##### Before we can launch instances, we need couple of information such as AMI-ID that needs to be used for these particular Ec2 Instances also, we need to create user-data that will be executed at the time of instance creation
#### Locate AMI-ID
```
$ ami_id=$(aws ssm get-parameters --names /aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2 --region ap-south-1 --query 'Parameters[0].[Value]' --output text)
```
#### Create User-data files
```
##User-data for Bastion-server
#!/bin/bash
echo "ClientAliveInterval 60" >> /etc/ssh/sshd_config
echo "LANG=en_US.utf-8" >> /etc/environment
echo "LC_ALL=en_US.utf-8" >> /etc/environment
service sshd restart 

##User-data for Frontend-Server
#!/bin/bash
echo "ClientAliveInterval 60" >> /etc/ssh/sshd_config
echo "LANG=en_US.utf-8" >> /etc/environment
echo "LC_ALL=en_US.utf-8" >> /etc/environment
service sshd restart 
yum install httpd php -y
systemctl restart httpd.service
systemctl enable httpd.service

##User-data for Backend-Server
#!/bin/bash
echo "ClientAliveInterval 60" >> /etc/ssh/sshd_config
echo "LANG=en_US.utf-8" >> /etc/environment
echo "LC_ALL=en_US.utf-8" >> /etc/environment
service sshd restart 
yum install mariadb-server -y
systemctl restart mariadb.service
systemctl enable mariadb.service
```

#### Launch Bastion Ec2 Instance
```
$ aws ec2 run-instances --image-id $ami_id --count 1 --instance-type t2.micro --key-name secret-key --security-group-ids $bastion_sg --subnet-id $pub_1 --user-data file://bastion.sh --profile=vpc-admin
{
    "Groups": [],
    "Instances": [
        {
            "AmiLaunchIndex": 0,
            "ImageId": "ami-0a02c812e7eeb846d",
            "InstanceId": "i-0b3c630e9d3dcee74",
            "InstanceType": "t2.micro",
            "KeyName": "secret-key",
            "LaunchTime": "2022-12-16T15:34:11+00:00",
            "Monitoring": {
                "State": "disabled"
            },
            "Placement": {
                "AvailabilityZone": "ap-south-1a",
                "GroupName": "",
                "Tenancy": "default"
            ##### Output Truncated ####
```

#### Launch Frontend Ec2 Instance
```
$ aws ec2 run-instances --image-id $ami_id --count 1 --instance-type t2.micro --key-name secret-key --security-group-ids $frontend_sg --subnet-id $pub_2 --user-data file://frontend.sh --profile=vpc-admin
{
    "Groups": [],
    "Instances": [
        {
            "AmiLaunchIndex": 0,
            "ImageId": "ami-0a02c812e7eeb846d",
            "InstanceId": "i-0531e167302066010",
            "InstanceType": "t2.micro",
            "KeyName": "secret-key",
            "LaunchTime": "2022-12-16T15:45:00+00:00",
            "Monitoring": {
                "State": "disabled"
            },
            "Placement": {
                "AvailabilityZone": "ap-south-1b",
                "GroupName": "",
                "Tenancy": "default"
            },
            "PrivateDnsName": "ip-172-16-71-109.ap-south-1.compute.internal",
            "PrivateIpAddress": "172.16.71.109",
            "ProductCodes": [],
            "PublicDnsName": "",
            "State": {
                "Code": 0,
                "Name": "pending"
            },
             ##### Output Truncated ####
```
#### Create Backend Ec2 Instance
```
$ aws ec2 run-instances --image-id $ami_id --count 1 --instance-type t2.micro --key-name secret-key --security-group-ids $backend_sg --subnet-id $priv_1 --user-data file://backend.sh --profile=vpc-admin
{
    "Groups": [],
    "Instances": [
        {
            "AmiLaunchIndex": 0,
            "ImageId": "ami-0a02c812e7eeb846d",
            "InstanceId": "i-08dcdc1d5f6e149ec",
            "InstanceType": "t2.micro",
            "KeyName": "secret-key",
            "LaunchTime": "2022-12-16T15:48:02+00:00",
            "Monitoring": {
                "State": "disabled"
            },
            "Placement": {
                "AvailabilityZone": "ap-south-1b",
                "GroupName": "",
                "Tenancy": "default"
            },
            "PrivateDnsName": "ip-172-16-168-26.ap-south-1.compute.internal",
            "PrivateIpAddress": "172.16.168.26",
            "ProductCodes": [],
            "PublicDnsName": "",
            "State": {
                "Code": 0,
                "Name": "pending"
            },
          ##### Output Truncated ####
```
