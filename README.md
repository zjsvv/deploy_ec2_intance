## Create an IAM user on AWS with following existing policies
```
AmazonEC2FullAccess
AmazonEC2RoleforSSM
IAMFullAccess
AWSResourceGroupsReadOnlyAccess
AmazonSSMFullAccess
IAMUserSSHKeys
```

## How to setup local environment
1. Installing virtualenv
    ```
    $ python3 -m pip install --user virtualenv
    ```

2. Clone the repository
    ```
    $ git clone .git
    ```

3. Go inside the project directory
    ```
    $ cd deploy_ec2_intance
    ```

4. Setup virtual environment
  * Creating a virtual environment
    ```
    $ python3 -m venv env
    ```

  * Activating a virtual environment
    ```
    $ source env/bin/activate
    ```

5. Install required packages
    ```
    $ pip install -r requirements.txt
    ```
## Setup AWS config and credentials for boto3
1. modify `.config`
    ```
    ACCESS_KEY_ID=YOUR_KEY
    SECRET_ACCESS_KEY=YOUR_SECRET
    ```

## How to deploy

```
$ bash deploy.sh
```
