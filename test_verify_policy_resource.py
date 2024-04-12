import pytest
from main import verify_policy_resource


def test_verify_policy_resource_verified():
    policy = {
        "PolicyName": "root",
        "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "IamListAccess",
                    "Effect": "Allow",
                    "Action": [
                        "iam:ListRoles",
                        "iam:ListUsers"
                    ],
                    "Resource": "*"
                }
            ]
        }
    }

    assert verify_policy_resource(policy) == False
    
    
def test_verify_policy_resource_not_verified():
    policy = {
        "PolicyName": "root",
        "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "IamListAccess",
                    "Effect": "Allow",
                    "Action": [
                        "iam:ListRoles",
                        "iam:ListUsers"
                    ],
                    "Resource": "not *"
                }
            ]
        }
    }

    assert verify_policy_resource(policy) == True
    
    
def test_verify_policy_resource_none():
    with pytest.raises(ValueError, match='The policy is None'):
        verify_policy_resource(None)


def test_verify_policy_resource_not_dict():
    with pytest.raises(ValueError, match='The policy is not a dictionary'):
        verify_policy_resource("not a dictionary")
    

def test_verify_policy_resource_empty():
    policy = {}

    with pytest.raises(ValueError, match='The policy is empty') as e:
        verify_policy_resource(policy)
    

def test_verify_policy_resource_no_policy_document():
    policy = {
        "PolicyName": "root"
    }
    
    error_message = 'The policy dictionary does not have a PolicyDocument key'
    with pytest.raises(ValueError, match=error_message) as e:
        verify_policy_resource(policy)
    
    
def test_verify_policy_resource_no_statement():
    policy = {
        "PolicyName": "root",
        "PolicyDocument": {
            "Version": "2012-10-17"
        }
    }
    
    error_message = 'The policy dictionary does not have a Statement key'
    with pytest.raises(ValueError, match=error_message) as e:
        verify_policy_resource(policy)
    
    
def test_verify_policy_resource_empty_statement():
    policy = {
        "PolicyName": "root",
        "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": []
        }
    }
    
    error_message = 'The policy Statement key\'s value is an empty list'
    with pytest.raises(ValueError, match=error_message) as e:
        verify_policy_resource(policy)
    
    
def test_verify_policy_resource_no_resource():
    policy = {
        "PolicyName": "root",
        "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "IamListAccess",
                    "Effect": "Allow",
                    "Action": [
                        "iam:ListRoles",
                        "iam:ListUsers"
                    ]
                }
            ]
        }
    }
    
    error_message = 'The policy does not have a Resource key'
    with pytest.raises(ValueError, match=error_message) as e:
        verify_policy_resource(policy)