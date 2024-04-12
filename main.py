import json


def verify_policy_resource(policy: dict[str, str|dict]) -> bool:
    """
    Verifies if the 'Resource' filed in the policy is not equal to '*'.
    
    :param dict[str, str|dict] policy: The dictionary JSON policy in a AWS::IAM::Role Policy format to be verified.
    
    :raises ValueError:
        If the policy is empty, does not have a 'PolicyDocument' key, does not have a 'Statement' key,
        value of 'Statement' key is an empty list or does not have a 'Resource' key.
        
    :return: bool
        Returns True if the 'Resource' field in the first 'Statement' of the 'PolicyDocument' 
        is not equal to '*', otherwise False.
    """
    
    if policy is None:
        raise ValueError('The policy is None')
    if not isinstance(policy, dict):
        raise ValueError('The policy is not a dictionary')
    if policy == {}:
        raise ValueError('The policy is empty')
    if 'PolicyDocument' not in policy:
        raise ValueError('The policy dictionary does not have a PolicyDocument key')
    if 'Statement' not in policy['PolicyDocument']:
        raise ValueError('The policy dictionary does not have a Statement key')
    if policy['PolicyDocument']['Statement'] == []:
        raise ValueError('The policy Statement value is an empty list')
    if len(policy['PolicyDocument']['Statement']) > 1:
        raise ValueError('The policy has more than one Statement')
    if 'Resource' not in policy['PolicyDocument']['Statement'][0]:
        raise ValueError('The policy does not have a Resource key')
    
    resource = policy['PolicyDocument']['Statement'][0]['Resource']

    is_verified = (resource != '*')
    
    return is_verified