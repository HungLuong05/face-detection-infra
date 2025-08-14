from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
    aws_s3 as s3,
    aws_iam as iam,
    CfnOutput,
    RemovalPolicy
)
from constructs import Construct

class FaceDetectionInfraStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create S3 bucket for face detection application
        face_detection_bucket = s3.Bucket(
            self, "FaceDetectionBucket",
            bucket_name=f"face-detection-bucket-{self.account}-{self.region}",  # Unique bucket name
            versioned=False,  # Disable versioning for cost savings
            removal_policy=RemovalPolicy.DESTROY,  # Delete bucket on stack deletion
            auto_delete_objects=True,  # Automatically delete objects when destroying bucket
            public_read_access=False,  # Keep bucket private
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,  # Block all public access
            encryption=s3.BucketEncryption.S3_MANAGED,  # Server-side encryption
            cors=[
                s3.CorsRule(
                    allowed_origins=["*"],
                    allowed_methods=[s3.HttpMethods.GET, s3.HttpMethods.POST, s3.HttpMethods.PUT],
                    allowed_headers=["*"],
                    max_age=3000
                )
            ]
        )

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

        # Create IAM role for EC2 instance to access S3
        ec2_role = iam.Role(
            self, "FaceDetectionEC2Role",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore")  # For Systems Manager
            ]
        )
        ec2_role.apply_removal_policy(RemovalPolicy.DESTROY)

        # Grant S3 bucket permissions to EC2 role
        face_detection_bucket.grant_read_write(ec2_role)

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

        # Create EC2 Instance (t2.large)
        instance = ec2.Instance(
            self, "FaceDetectionInstance",
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.T2,
                ec2.InstanceSize.LARGE
            ),
            machine_image=ec2.MachineImage.from_ssm_parameter(
                "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
            ),
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PUBLIC  # Place in public subnet for easy access
            ),
            security_group=security_group,
            role=ec2_role,
            user_data=ec2.UserData.for_linux(),
            block_devices=[
                ec2.BlockDevice(
                    device_name="/dev/sda1",
                    volume=ec2.BlockDeviceVolume.ebs(
                        volume_size=32,  # 20 GB root volume
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
            "apt update -y",
            "apt install -y python3.11 python3.11-dev python3.10-venv python3-pip git build-essential ffmpeg",
            "pip3 install --upgrade pip",

            # Create a user for running the application (optional, for security)
            "useradd -m facedetection || true",
            "cd /home/facedetection",

            # Change ownership to facedetection user
            "chown -R facedetection:facedetection /home/facedetection",

            # Set S3 environment variables for the facedetection user
            f"echo 'export S3_BUCKET_NAME={face_detection_bucket.bucket_name}' >> /home/facedetection/.bashrc",
            f"echo 'export S3_PREFIX=faces' >> /home/facedetection/.bashrc",  # Add custom prefix
            f"echo 'export AWS_DEFAULT_REGION={self.region}' >> /home/facedetection/.bashrc",
            f"echo 'export S3_BUCKET_NAME={face_detection_bucket.bucket_name}' >> /home/facedetection/.profile",
            f"echo 'export S3_PREFIX=faces' >> /home/facedetection/.profile",
            f"echo 'export AWS_DEFAULT_REGION={self.region}' >> /home/facedetection/.profile",

            # Run git clone as the facedetection user
            "sudo -u facedetection bash -c 'cd /home/facedetection && git clone https://github.com/minhtuan-ne/CoderPush-Human-Detection.git'",
            
            # Create virtual environment and install dependencies
            "sudo -u facedetection bash -c 'cd /home/facedetection/CoderPush-Human-Detection && python3 -m venv venv'",
            "sudo -u facedetection bash -c 'mkdir -p /home/facedetection/tmp'",
            "sudo -u facedetection bash -c 'cd /home/facedetection/CoderPush-Human-Detection && source venv/bin/activate && TMPDIR=/home/facedetection/tmp pip install -r requirements/requirements.txt'",

            # # Create virtual environment and install dependencies
            # "python3 -m venv venv",
            # "source venv/bin/activate",
            # "pip install -r requirements/requirements.txt",

            # # Change ownership to facedetection user
            # "chown -R facedetection:facedetection /home/facedetection",

            # Create a systemd service file for auto-start
            # "cat > /etc/systemd/system/facedetection.service << 'EOF'",
            # "[Unit]",
            # "Description=Face Detection API Service",
            # "After=network.target",
            # "",
            # "[Service]",
            # "Type=simple",
            # "User=facedetection",
            # "WorkingDirectory=/home/facedetection/CoderPush-Human-Detection",
            # "Environment=PATH=/home/facedetection/CoderPush-Human-Detection/venv/bin",
            # "ExecStart=/home/facedetection/CoderPush-Human-Detection/venv/bin/python src/api/app.py",
            # "Restart=always",
            # "RestartSec=10",
            # "",
            # "[Install]",
            # "WantedBy=multi-user.target",
            # "EOF",

            # # Enable and start the service
            # "systemctl daemon-reload",
            # "systemctl enable facedetection.service",
            # "systemctl start facedetection.service",

            # Add firewall rule for port 7860 (if firewalld is running)
            "ufw allow 22/tcp || true",
            "ufw allow 7860/tcp || true",
            "ufw --force enable || true",
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
