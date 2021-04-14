import boto3
import configparser
import json
import logging
import os
import stat
import yaml

from botocore.config import Config
from botocore.exceptions import ClientError


logger = logging.getLogger(__name__)

config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), '.config'))

"""
load_yaml -> create_key_pair -> get_lastest_ami_id -> create_key_pair -> create_security_group

-> create policy -> create IAM role
-> create_instance -> ssh-keygen on instance

"""

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
            logger.warning('Parameter Not Found. Try a new one.')
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

def get_or_create_security_group():
    sg_name = 'ec2_SSH'

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

    try:
        response = iam_client.get_instance_profile(InstanceProfileName=inst_profile_name)
        return response['InstanceProfile']['Arn']
    except ClientError as e:
        pass

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

    response = iam_client.create_role(
        RoleName=f"{settings['server']['name']}_EC2SSMAcess",
        AssumeRolePolicyDocument=json.dumps(arpd),
        Description='Allows EC2 instances to call AWS services on your behalf.'
    )

    # attach policy to role
    response = iam_client.attach_role_policy(
        RoleName=f"{settings['server']['name']}_EC2SSMAcess",
        PolicyArn='arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
    )

    # create instance profile
    response = iam_client.create_instance_profile(
        InstanceProfileName=inst_profile_name
    )
    arn = response['InstanceProfile']['Arn']
    name = response['InstanceProfile']['InstanceProfileName']

    # add role to instance profile
    response = iam_client.add_role_to_instance_profile(
        InstanceProfileName=inst_profile_name,
        RoleName=f"{settings['server']['name']}_EC2SSMAcess"
    )
    return arn

def create_instance():
    image_id = get_lastest_ami_id()
    key_name = get_or_create_key_pair()
    sg_name = get_or_create_security_group()
    ip_arn = get_or_create_instance_profile()

    try:
        response = ec2_client.run_instances(
            BlockDeviceMappings=[
                {
                    'DeviceName': '/dev/xvda',
                    'VirtualName': 'ephemeral0',
                    'Ebs': {
                        'VolumeSize': 10,
                        'VolumeType': 'standard'
                    },
                },
                {
                    'DeviceName': '/dev/xvdf',
                    'VirtualName': 'ephemeral1',
                    'Ebs': {
                        'VolumeSize': 100,
                        'VolumeType': 'standard'
                    },
                },
            ],
            SecurityGroups=[sg_name],
            IamInstanceProfile={
                'Arn': ip_arn,
            },
            ImageId=image_id,
            KeyName=key_name,
            MinCount=settings['server']['min_count'],
            MaxCount=settings['server']['max_count'],
            InstanceType=f"{settings['server']['instance_type']}"
        )
    except ClientError as e:
        raise e

    instance_id = response['Instances'][0]['InstanceId']

    print(f'Waiting for instance {instance_id} to switch to running state.')
    waiter = ec2_client.get_waiter('instance_running')
    waiter.wait(InstanceIds=[instance_id])
    print(f'Instance {instance_id} is running.')

    # commands = ['echo "hello world"']
    # response = ssm_lient.send_command(
    #     DocumentName="AWS-RunShellScript",
    #     Parameters={'commands': commands},
    #     InstanceIds=[instance_id],
    # )

# create_instance()

def execute_commands_on_linux_instances(client, commands, instance_ids):
    """Runs commands on remote linux instances
    :param client: a boto/boto3 ssm client
    :param commands: a list of strings, each one a command to execute on the instances
    :param instance_ids: a list of instance_id strings, of the instances on which to execute the command
    :return: the response from the send_command function (check the boto3 docs for ssm client.send_command() )
    """

    resp = client.send_command(
        DocumentName="AWS-RunShellScript",
        Parameters={'commands': commands},
        InstanceIds=instance_ids,
    )
    return resp

def test():
    a = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCztHqaZydaetBJGowKhPDpc0ewmUHjiDlHYSwj7v2yFfad+SzvBU0bFAmfSjkVftT9rSPUyl5JMEVYGGXCadRRfH35Sy99pDYSOup6m1Y+y+SYLhuIN6SLbN//059gunE/p6hhWVsV785gwL69embmp5FDXvzUY2yB0c+08xPNLZ0kCFR4arte6s6m1ZukB2379yQHueCTQ8lt1WbuGxRjrpC0LvZBfl4OGcDVaMkjjQfAUidwMHn7X0CqdPOx7pjXOAKVWWr2dLzyqHd1sVtmjydYyw2tTr+9c7SycFZZYf1tn0VvQnHJhgrqnSSlDEwrfKRo9/NBFxbb8qMEgf6f'
    commands = [
        'sudo adduser -m user3',
        'sudo su - user3',
        'cd ~/',
        'mkdir .ssh',
        'chmod 700 .ssh',
        f"echo {a} >> .ssh/authorized_keys",
        'chmod 600 .ssh/authorized_keys',
     ]

    ssm_document = "AWS-RunShellScript"
    # params = {"commands": ["#!/bin/bash\necho 'hello world'"]}
    params = {"commands": commands}
    response = ssm_client.send_command(
        DocumentName=ssm_document,
        Parameters=params,
        InstanceIds=['i-08ad420951b416280'],
    )

test()
