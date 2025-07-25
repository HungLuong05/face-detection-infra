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

        # Allow access to face detection app (port 7860)
        security_group.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(7860),
            "Allow access to face detection application"
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

        # Add user data script to install basic tools and set up face detection app
        instance.user_data.add_commands(
            "yum update -y",
            "yum install -y python3 python3-pip git",
            "pip3 install --upgrade pip",
            
            # Create a user for running the application (optional, for security)
            "useradd -m facedetection || true",
            "cd /home/facedetection",
            
            # Clone the face detection repository
            "git clone https://github.com/minhtuan-ne/CoderPush-Human-Detection.git",
            "cd CoderPush-Human-Detection",
            
            # Create virtual environment and install dependencies
            "python3 -m venv venv",
            "source venv/bin/activate",
            "pip install -r requirements/requirements.txt",
            
            # Change ownership to facedetection user
            "chown -R facedetection:facedetection /home/facedetection",
            
            # Create a systemd service file for auto-start
            "cat > /etc/systemd/system/facedetection.service << 'EOF'",
            "[Unit]",
            "Description=Face Detection API Service",
            "After=network.target",
            "",
            "[Service]",
            "Type=simple",
            "User=facedetection",
            "WorkingDirectory=/home/facedetection/CoderPush-Human-Detection",
            "Environment=PATH=/home/facedetection/CoderPush-Human-Detection/venv/bin",
            "ExecStart=/home/facedetection/CoderPush-Human-Detection/venv/bin/python src/api/app.py",
            "Restart=always",
            "RestartSec=10",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "EOF",
            
            # Enable and start the service
            "systemctl daemon-reload",
            "systemctl enable facedetection.service",
            "systemctl start facedetection.service",
            
            # Add firewall rule for port 7860 (if firewalld is running)
            "firewall-cmd --permanent --add-port=7860/tcp || true",
            "firewall-cmd --reload || true",
            "python src/api/app.py"
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

        CfnOutput(
            self, "FaceDetectionAppURL",
            value=f"http://{instance.instance_public_ip}:7860",
            description="URL to access the Face Detection application"
        )
