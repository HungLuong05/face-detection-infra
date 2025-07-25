from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
)
from constructs import Construct

class FaceDetectionInfraStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create VPC
        vpc = ec2.Vpc(
            self, "FaceDetectionVPC",
            max_azs=2,  # Use 2 availability zones
            nat_gateways=1,  # Cost-effective NAT gateway setup
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.PUBLIC,
                    name="PublicSubnet",
                    cidr_mask=24
                ),
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    name="PrivateSubnet", 
                    cidr_mask=24
                )
            ]
        )

        # Create Security Group
        security_group = ec2.SecurityGroup(
            self, "FaceDetectionSecurityGroup",
            vpc=vpc,
            description="Security group for face detection EC2 instance",
            allow_all_outbound=True
        )

        # Allow SSH access (port 22) - you may want to restrict this to your IP
        security_group.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(22),
            "Allow SSH access"
        )

        # Allow HTTP access (port 80) if needed for your application
        security_group.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(80),
            "Allow HTTP access"
        )

        # Allow HTTPS access (port 443) if needed
        security_group.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(443),
            "Allow HTTPS access"
        )

        # Create Key Pair (you'll need to create this in AWS Console first, or use an existing one)
        # For this example, we'll reference an existing key pair - comment out if you don't have one
        # key_name = "face-detection-key"  # Replace with your actual key pair name

        # Create EC2 Instance (t3.medium)
        instance = ec2.Instance(
            self, "FaceDetectionInstance",
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.T3,
                ec2.InstanceSize.MEDIUM
            ),
            machine_image=ec2.AmazonLinuxImage(
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2
            ),
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PUBLIC  # Place in public subnet for easy access
            ),
            security_group=security_group,
            # key_pair=ec2.KeyPair.from_key_pair_name(self, "KeyPair", key_name),  # Uncomment and set key_name if you have a key pair
            user_data=ec2.UserData.for_linux(),
        )

        # Add user data script to install basic tools (optional)
        instance.user_data.add_commands(
            "yum update -y",
            "yum install -y python3 python3-pip",
            "pip3 install --upgrade pip",
            # Add more commands as needed for your face detection application
        )

        # Output the instance's public IP address
        from aws_cdk import CfnOutput
        CfnOutput(
            self, "InstancePublicIP",
            value=instance.instance_public_ip,
            description="Public IP address of the EC2 instance"
        )

        CfnOutput(
            self, "InstanceId",
            value=instance.instance_id,
            description="EC2 Instance ID"
        )
