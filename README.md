# Simple Bastion Security

The files in this repository demonstrate a relatively lightweight method to improve the security of your bastion host(s) by removing the need to allow connections from the entire public internet (0.0.0.0/0).  The key to this is the use of a security group that, in its "base" state, disallows connections entirely.  When a user wishes to connect, they run a small utility to insert a rule into the security group that allows connection only from the public IP address that they're actually on.  To make sure that the security group doesn't end up littered with many obsolete rules, a Lambda function runs periodically that removes "expired" rules.


## User Roles in AWS

Users of the `bastion-util` must have a role attached with at least the permissions in the below policy:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "ec2:DescribeSecurityGroups",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupIngress"
            ],
            "Resource": "<dynamic security group arn>",
            "Effect": "Allow"
        }
    ]
}

```

Where `<dynamic security group arn>` is replaced with the full ARN of the security group to be managed (e.g. `arn:aws:ec2:ca-central-1:123456789012:security-group/sg-00112233445566778`).  The ARN may be obtained from the `sgDynamicBastion` output of the CloudFormation template.


## Using the files herein

Clean up everything local with `make distclean` or `make clean`, depending on how picky you are.

A "normal" build process would go along the lines of

```sh
# edit demo-bastion-security.yaml and change parameter values as necessary
make create-stack
make
# wait for the stack to complete creation; check the AWS console
make deploy
# note the filename of the LambdaHandler zipfile;
# edit demo-bastion-security.yaml to replace that parameter
# edit demo-bastion-security.yaml to uncomment the bottom half
make update-stack
# edit your SSH configuration file to include (corrected) contents of the ssh-config file here
# ssh to your bastion
```




