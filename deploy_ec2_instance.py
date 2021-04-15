import boto3
import configparser
import json
import os
import stat
import yaml

from botocore.config import Config
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend

config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), '.config'))

ec2 = boto3.resource(
    "ec2",
    region_name=config['AWS']['REGION'],
    aws_access_key_id=config['AWS']['ACCESS_KEY_ID'],
    aws_secret_access_key=config['AWS']['SECRET_ACCESS_KEY']
)

ec2_client = boto3.client(
    "ec2",
    region_name=config['AWS']['REGION'],
    aws_access_key_id=config['AWS']['ACCESS_KEY_ID'],
    aws_secret_access_key=config['AWS']['SECRET_ACCESS_KEY']
)

ssm_client = boto3.client(
    "ssm",
    region_name=config['AWS']['REGION'],
    aws_access_key_id=config['AWS']['ACCESS_KEY_ID'],
    aws_secret_access_key=config['AWS']['SECRET_ACCESS_KEY']
)

iam_client = boto3.client(
    "iam",
    region_name=config['AWS']['REGION'],
    aws_access_key_id=config['AWS']['ACCESS_KEY_ID'],
    aws_secret_access_key=config['AWS']['SECRET_ACCESS_KEY']
)

def execute_commands_on_linux_instances(client, commands, instance_ids):
    response = client.send_command(
        DocumentName="AWS-RunShellScript",
        Parameters={'commands': commands},
        InstanceIds=instance_ids,
    )
    return response

def load_yaml():
    with open(os.path.join(os.path.dirname(__file__)) + 'source.yaml') as f:
        data = yaml.safe_load(f)

    return data

settings = load_yaml()

def get_lastest_ami_id():
    try:
        ami_name = f"/aws/service/ami-amazon-linux-latest/{settings['server']['ami_type']}-ami-{settings['server']['virtualization_type']}-{settings['server']['architecture']}-{settings['server']['root_device_type']}"
        response = ssm_client.get_parameter(Name=ami_name, WithDecryption=True)
    except ClientError as e:
        if e.response['Error']['Code'] == 'ParameterNotFound':
            print('Parameter Not Found. Try a new one.')
            return
        else:
            raise e

    return response['Parameter']['Value']

def get_or_create_key_pair():
    key_name = settings['server']['name']

    # check if current key name exist
    key_pairs = ec2_client.describe_key_pairs()['KeyPairs']
    for kp in key_pairs:
        if key_name == kp['KeyName']:
            return key_name

    # create new key pair
    try:
        response = ec2_client.create_key_pair(KeyName=key_name)
        pem = response['KeyMaterial']
        kp_file_name = key_name + '.pem'
        with open(kp_file_name, 'w') as f:
            f.write(pem)

        # chmod 400 .pem
        os.chmod(os.path.join(os.path.dirname(__file__)) + kp_file_name, stat.S_IRUSR)

    except ClientError as e:
        raise e

    return response['KeyName']

def generate_public_key(private_key_pem_file_name):
    with open(os.path.join(os.path.dirname(__file__)) + private_key_pem_file_name + '.pem', "rb") as key_file:
        private_key = crypto_serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=crypto_serialization.Encoding.OpenSSH,
        format=crypto_serialization.PublicFormat.OpenSSH
    )

    return pem.decode('utf-8')

def get_or_create_security_group():
    sg_name = f"{settings['server']['name']}-EC2-SSH"

    for sg in ec2_client.describe_security_groups()['SecurityGroups']:
        if sg['GroupName'] == sg_name:
            return sg_name

    try:
        response = ec2_client.create_security_group(
            Description='For SSH Access',
            GroupName=sg_name
        )

        response = ec2_client.authorize_security_group_ingress(
            GroupName=sg_name,
            IpPermissions=[
                {
                    'FromPort': 22,
                    'IpProtocol': 'tcp',
                    'IpRanges': [
                        {
                            'CidrIp': '0.0.0.0/0',
                            'Description': 'Internet',
                        },
                    ],
                    'ToPort': 22,
                },
            ],
        )
    except ClientError as e:
        raise e

    return sg_name

def get_or_create_instance_profile():
    inst_profile_name = f"{settings['server']['name']}-EC2-Instance-Profile"
    role_name = f"{settings['server']['name']}-EC2-SSMAcess"

    try:
        response = iam_client.get_instance_profile(InstanceProfileName=inst_profile_name)
        return response['InstanceProfile']['Arn']
    except iam_client.exceptions.NoSuchEntityException:
        print(f"Instance profile({inst_profile_name}) does not exists. Creating new one...")
    except Exception as e:
        print("Unexpected error: %s" % e)
        raise e

    # create role
    arpd = {
        "Version":"2012-10-17",
        "Statement":[
            {
                "Effect":"Allow",
                "Principal": {
                    "Service":"ec2.amazonaws.com"
                },
                "Action":"sts:AssumeRole"
            }
        ]
    }

    try:
        response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(arpd),
            Description='Allows EC2 instances to call AWS services on your behalf.'
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'EntityAlreadyExists':
            print(f"Role({role_name}) already exists")
        else:
            print("Unexpected error: %s" % e)
            raise e

    # attach policy to role
    response = iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn='arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
    )

    # create instance profile
    response = iam_client.create_instance_profile(
        InstanceProfileName=inst_profile_name
    )
    arn = response['InstanceProfile']['Arn']

    # add role to instance profile
    response = iam_client.add_role_to_instance_profile(
        InstanceProfileName=inst_profile_name,
        RoleName=role_name
    )
    return arn

def get_block_device_mapping():
    blkdevmappings = []
    i = 0
    for volume in settings['server']['volumes']:
        d = {
            'DeviceName': volume['device'],
            'VirtualName': f'ephemeral{i}',
            'Ebs': {
                'VolumeSize': volume['size_gb'],
                'VolumeType': 'standard'
            },
        }
        blkdevmappings.append(d)
        i += 1

    return blkdevmappings

def create_instance():
    image_id = get_lastest_ami_id()
    key_name = get_or_create_key_pair()
    sg_name = get_or_create_security_group()
    ip_arn = get_or_create_instance_profile()
    blkdevmappings = get_block_device_mapping()

    try:
        response = ec2_client.run_instances(
            BlockDeviceMappings=blkdevmappings,
            SecurityGroups=[sg_name],
            IamInstanceProfile={'Arn': ip_arn},
            ImageId=image_id,
            KeyName=key_name,
            MinCount=settings['server']['min_count'],
            MaxCount=settings['server']['max_count'],
            InstanceType=f"{settings['server']['instance_type']}"
        )
    except ClientError as e:
        print("Unexpected error: %s" % e)
        raise e

    instance = ec2.Instance(response['Instances'][0]['InstanceId'])

    print(f'Waiting for instance {instance.id} to switch to running state.')
    waiter = ec2_client.get_waiter('instance_running')
    waiter.wait(InstanceIds=[instance.id])
    print(f'...Instance {instance.id} is running.')

    print(f'Waiting for instance {instance.id} to be status ok.')
    waiter = ec2_client.get_waiter('instance_status_ok')
    waiter.wait(InstanceIds=[instance.id])
    print(f'...Instance {instance.id} is status ok.')

    if len(settings['server']['volumes']) > 0:
        print(f'Make file system on volume')
        for volume in settings['server']['volumes'][1:]:
            commands = [
                f"sudo mkfs -t {volume['type']} {volume['device']}",
                f"sudo mkdir {volume['mount']}",
                f"sudo mount {volume['device']} {volume['mount']}",
                f"sudo chmod -R 777 {volume['mount']}"
            ]
            response = execute_commands_on_linux_instances(ssm_client, commands, [instance.id])
        print('...done')

    print('creating users and setting up public key...')
    public_key_str = generate_public_key(key_name)
    for user in settings['server']['users']:
        user_name = user['login']

        commands = [
            f"sudo adduser {user_name}",
            f"sudo su - {user_name} -c 'mkdir .ssh'",
            f"sudo su - {user_name} -c 'chmod 700 .ssh'",
            f"sudo su - {user_name} -c 'echo {public_key_str} >> .ssh/authorized_keys'",
            f"sudo su - {user_name} -c 'chmod 600 .ssh/authorized_keys'"
        ]

        response = execute_commands_on_linux_instances(ssm_client, commands, [instance.id])
        print(f'Connect with SSH:')
        print(f'$ ssh -i "{key_name}.pem" {user_name}@{instance.public_dns_name}')
    print(f'crete {user_name} ...done')

create_instance()
