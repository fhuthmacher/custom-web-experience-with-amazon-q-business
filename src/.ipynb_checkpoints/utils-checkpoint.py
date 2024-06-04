import datetime
import logging
import os
import boto3
import jwt
import urllib3
from streamlit_oauth import OAuth2Component
logger = logging.getLogger()

# Read the configuration file
from dotenv import load_dotenv, find_dotenv

# loading environment variables that are stored in local file dev.env
local_env_filename = 'okta.env'
load_dotenv(find_dotenv(local_env_filename),override=True)

os.environ['DOMAIN'] = os.getenv('DOMAIN')
os.environ['AUTH_CLIENT_ID'] = os.getenv('AUTH_CLIENT_ID')
os.environ['API_IDENTIFIER'] = os.getenv('API_IDENTIFIER')
os.environ['REGION'] = os.getenv('REGION')
os.environ['IDC_APPLICATION_ID'] = os.getenv('IDC_APPLICATION_ID')
os.environ['IAM_ROLE'] = os.getenv('IAM_ROLE')
os.environ['AMAZON_Q_APP_ID'] = os.getenv('AMAZON_Q_APP_ID')
os.environ['CALLBACKURL'] = os.getenv('CALLBACKURL')
os.environ['AUTHORIZE_URL'] = os.getenv('AUTHORIZE_URL')
os.environ['TOKEN_URL'] = os.getenv('TOKEN_URL')
os.environ['REFRESH_TOKEN_URL'] = os.getenv('REFRESH_TOKEN_URL')
os.environ['REVOKE_TOKEN_URL'] = os.getenv('REVOKE_TOKEN_URL')


DOMAIN = os.environ["DOMAIN"]
AUTH_CLIENT_ID = os.environ['AUTH_CLIENT_ID']
CLIENT_SECRET = os.environ.get('AUTH_CLIENT_SECRET')
API_IDENTIFIER = os.environ["API_IDENTIFIER"]
REGION = os.environ['REGION']
IDC_APPLICATION_ID = os.environ['IDC_APPLICATION_ID']
IAM_ROLE = os.environ['IAM_ROLE']
AMAZON_Q_APP_ID = os.environ['AMAZON_Q_APP_ID']
CALLBACKURL = os.environ['CALLBACKURL']
AUTHORIZE_URL = os.environ['AUTHORIZE_URL']
TOKEN_URL = os.environ['TOKEN_URL']
REFRESH_TOKEN_URL = os.environ['REFRESH_TOKEN_URL']
REVOKE_TOKEN_URL = os.environ['REVOKE_TOKEN_URL']


AWS_CREDENTIALS = {}

def configure_oauth_component():
    """
    Configure the OAuth2 component
    """

    print(f'oauth component details: {DOMAIN} - {AUTHORIZE_URL}  - {TOKEN_URL} - {AUTH_CLIENT_ID} - {CLIENT_SECRET} ')
    return OAuth2Component(
        client_id=AUTH_CLIENT_ID, 
        client_secret=CLIENT_SECRET,
        authorize_endpoint=AUTHORIZE_URL, 
        token_endpoint=TOKEN_URL, 
        refresh_token_endpoint=REFRESH_TOKEN_URL, 
        revoke_token_endpoint=REVOKE_TOKEN_URL
    )

def refresh_iam_oidc_token(refresh_token):
    """
    Refresh the IAM OIDC token using the refresh token retrieved from Cognito
    """
    client = boto3.client("sso-oidc", region_name=REGION)
    response = client.create_token_with_iam(
        clientId=IDC_APPLICATION_ID,
        grantType="refresh_token",
        refreshToken=refresh_token,
    )
    return response


def get_iam_oidc_token(id_token):
    """
    Get the IAM OIDC token using the ID token retrieved from Cognito
    """
    print (f'region: {REGION}')
    client = boto3.client("sso-oidc", region_name=REGION)
    print (f'sso-oidc client: {client}')
    response = {}
    # try:
    response = client.create_token_with_iam(
        clientId=IDC_APPLICATION_ID,
        grantType="urn:ietf:params:oauth:grant-type:jwt-bearer",

# "grant_types_supported":["authorization_code","implicit","refresh_token","password","client_credentials","urn:ietf:params:oauth:grant-type:device_code","urn:openid:params:grant-type:ciba"]
        assertion=id_token,
    )
    print (f'create_token_with_iam response: {response}')
        
    # except Exception as e:
    #     print(f"An error occurred: {e}")
    
    return response
        


def assume_role_with_token(iam_token):
    """
    Assume IAM role with the IAM OIDC idToken
    """
    global AWS_CREDENTIALS
    decoded_token = jwt.decode(iam_token, options={"verify_signature": False})
    sts_client = boto3.client("sts", region_name=REGION)
    response = sts_client.assume_role(
        RoleArn=IAM_ROLE,
        RoleSessionName="qapp",
        ProvidedContexts=[
            {
                "ProviderArn": "arn:aws:iam::aws:contextProvider/IdentityCenter",
                "ContextAssertion": decoded_token["sts:identity_context"],
            }
        ],
    )
    AWS_CREDENTIALS = response["Credentials"]
    return response


# This method create the Q client
def get_qclient(idc_id_token: str):
    """
    Create the Q client using the identity-aware AWS Session.
    """
    if not AWS_CREDENTIALS or AWS_CREDENTIALS["Expiration"] < datetime.datetime.now(
        datetime.UTC
    ):
        assume_role_with_token(idc_id_token)
    session = boto3.Session(
        aws_access_key_id=AWS_CREDENTIALS["AccessKeyId"],
        aws_secret_access_key=AWS_CREDENTIALS["SecretAccessKey"],
        aws_session_token=AWS_CREDENTIALS["SessionToken"],
    )
    amazon_q = session.client("qbusiness", REGION)
    return amazon_q


# This code invoke chat_sync api and format the response for UI
def get_queue_chain(
    prompt_input, conversation_id, parent_message_id, token
):
    """"
    This method is used to get the answer from the queue chain.
    """
    amazon_q = get_qclient(token)
    print(f'amazon_q: {amazon_q}')
    if conversation_id != "":
        answer = amazon_q.chat_sync(
            applicationId=AMAZON_Q_APP_ID,
            userMessage=prompt_input,
            conversationId=conversation_id,
            parentMessageId=parent_message_id,
        )
    else:
        answer = amazon_q.chat_sync(
            applicationId=AMAZON_Q_APP_ID, userMessage=prompt_input
        )

    system_message = answer.get("systemMessage", "")
    conversation_id = answer.get("conversationId", "")
    parent_message_id = answer.get("systemMessageId", "")
    result = {
        "answer": system_message,
        "conversationId": conversation_id,
        "parentMessageId": parent_message_id,
    }

    if answer.get("sourceAttributions"):
        attributions = answer["sourceAttributions"]
        valid_attributions = []

        # Generate the answer references extracting citation number,
        # the document title, and if present, the document url
        for attr in attributions:
            title = attr.get("title", "")
            url = attr.get("url", "")
            citation_number = attr.get("citationNumber", "")
            attribution_text = []
            if citation_number:
                attribution_text.append(f"[{citation_number}]")
            if title:
                attribution_text.append(f"Title: {title}")
            if url:
                attribution_text.append(f", URL: {url}")

            valid_attributions.append("".join(attribution_text))

        concatenated_attributions = "\n\n".join(valid_attributions)
        result["references"] = concatenated_attributions

        # Process the citation numbers and insert them into the system message
        citations = {}
        for attr in answer["sourceAttributions"]:
            for segment in attr["textMessageSegments"]:
                citations[segment["endOffset"]] = attr["citationNumber"]
        offset_citations = sorted(citations.items(), key=lambda x: x[0])
        modified_message = ""
        prev_offset = 0

        for offset, citation_number in offset_citations:
            modified_message += (
                system_message[prev_offset:offset] + f"[{citation_number}]"
            )
            prev_offset = offset

        modified_message += system_message[prev_offset:]
        result["answer"] = modified_message

    return result