from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
    CfnOutput,
    RemovalPolicy
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
            ],
        )
        vpc.apply_removal_policy(RemovalPolicy.DESTROY)  # Remove VPC on stack deletion

        # Create Security Group
        security_group = ec2.SecurityGroup(
            self, "FaceDetectionSecurityGroup",
            vpc=vpc,
            description="Security group for face detection EC2 instance",
            allow_all_outbound=True,
        )
        security_group.apply_removal_policy(RemovalPolicy.DESTROY)  # Remove security group on stack deletion

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

        security_group.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(7860),
            "Allow access to face detection API"
        )

        # Create Key Pair (you'll need to create this in AWS Console first, or use an existing one)
        # For this example, we'll reference an existing key pair - comment out if you don't have one
        # key_name = "face-detection-key"  # Replace with your actual key pair name

        # Create EC2 Instance (t2.micro)
        instance = ec2.Instance(
            self, "FaceDetectionInstance",
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.T2,
                ec2.InstanceSize.LARGE
            ),
            machine_image=ec2.AmazonLinuxImage(
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2023
            ),
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PUBLIC  # Place in public subnet for easy access
            ),
            security_group=security_group,
            # key_pair=ec2.KeyPair.from_key_pair_name(self, "KeyPair", key_name),  # Uncomment and set key_name if you have a key pair
            user_data=ec2.UserData.for_linux(),
            block_devices=[
                ec2.BlockDevice(
                    device_name="/dev/xvda",
                    volume=ec2.BlockDeviceVolume.ebs(
                        volume_size=16,  # 16 GB root volume
                        volume_type=ec2.EbsDeviceVolumeType.GP3,  # General Purpose SSD
                        encrypted=True,  # Encrypt the volume
                        delete_on_termination=True  # Delete volume on instance termination
                    )
                )
            ]
        )
        instance.apply_removal_policy(RemovalPolicy.DESTROY)  # Remove instance on stack deletion

        # Add user data script to install basic tools (optional)
        instance.user_data.add_commands(
            "dnf update -y",
            "dnf install -y python3.11 python3-pip git",
            "pip3 install --upgrade pip",

            # Create a user for running the application (optional, for security)
            "useradd -m facedetection || true",
            "cd /home/facedetection",

            # Change ownership to facedetection user
            "chown -R facedetection:facedetection /home/facedetection",

            # Run git clone as the facedetection user
            "sudo -u facedetection bash -c 'cd /home/facedetection && git clone https://github.com/minhtuan-ne/CoderPush-Human-Detection.git'",
            
            # Create virtual environment and install dependencies
            "sudo -u facedetection bash -c 'cd /home/facedetection/CoderPush-Human-Detection && python3 -m venv venv'",
            "sudo -u facedetection bash -c 'cd /home/facedetection/CoderPush-Human-Detection && source venv/bin/activate && pip install -r requirements/requirements.txt'",

            # # Create virtual environment and install dependencies
            # "python3 -m venv venv",
            # "source venv/bin/activate",
            # "pip install -r requirements/requirements.txt",

            # # Change ownership to facedetection user
            # "chown -R facedetection:facedetection /home/facedetection",

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
            # "python src/api/app.py"
        )

        # Output the instance's public IP address
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
