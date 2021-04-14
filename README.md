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

4. Install required packages
    ```
    $ pip install -r requirements.txt
    ```

## setup aws config and credentials for boto3
1. ~/.aws/credentials
    ```
    aws_access_key_id = YOUR_KEY
    aws_secret_access_key = YOUR_SECRET
    ```
