from datetime import datetime, timedelta, timezone

import jwt
import jwt.algorithms
import streamlit as st  #all streamlit commands will be available through the "st" alias
import utils
from streamlit_feedback import streamlit_feedback
import os

UTC=timezone.utc

# Read the configuration file
from dotenv import load_dotenv, find_dotenv

# loading environment variables that are stored in local file dev.env
local_env_filename = 'dev.env'
load_dotenv(find_dotenv(local_env_filename),override=True)

os.environ['AUTH0_DOMAIN'] = os.getenv('AUTH0_DOMAIN')
os.environ['AUTH_CLIENT_ID'] = os.getenv('AUTH_CLIENT_ID')
os.environ['API_IDENTIFIER'] = os.getenv('API_IDENTIFIER')
os.environ['REGION'] = os.getenv('REGION')
os.environ['IDC_APPLICATION_ID'] = os.getenv('IDC_APPLICATION_ID')
os.environ['IAM_ROLE'] = os.getenv('IAM_ROLE')
os.environ['AMAZON_Q_APP_ID'] = os.getenv('AMAZON_Q_APP_ID')
os.environ['CALLBACKURL'] = os.getenv('CALLBACKURL')

AUTH0_DOMAIN = os.environ["AUTH0_DOMAIN"]
AUTH_CLIENT_ID = os.environ['AUTH_CLIENT_ID']
API_IDENTIFIER = os.environ["API_IDENTIFIER"]
REGION = os.environ['REGION']
IDC_APPLICATION_ID = os.environ['IDC_APPLICATION_ID']
IAM_ROLE = os.environ['IAM_ROLE']
AMAZON_Q_APP_ID = os.environ['AMAZON_Q_APP_ID']
CALLBACKURL = os.environ['CALLBACKURL']
st.set_page_config(page_title="Amazon Q Business Custom UI") #HTML title
st.title("Amazon Q Business Custom UI") #page title

# Define a function to clear the chat history
def clear_chat_history():
    st.session_state.messages = [{"role": "assistant", "content": "How may I assist you today?"}]
    st.session_state.questions = []
    st.session_state.answers = []
    st.session_state.input = ""
    st.session_state["chat_history"] = []
    st.session_state["conversationId"] = ""
    st.session_state["parentMessageId"] = ""


oauth2 = utils.configure_oauth_component()
print(f'oauth2: {oauth2}')
if "token" not in st.session_state:
    # If not, show authorize button
    redirect_uri = f"https://{CALLBACKURL}/component/streamlit_oauth.authorize_button/index.html"
    # result = oauth2.authorize_button("Login with oauth2",scope="openid", pkce="S256", redirect_uri=redirect_uri)
    result = oauth2.authorize_button("Login with auth0", redirect_uri, "openid")
    print(f'result: {result}')
    if result and "token" in result:
        # If authorization successful, save token in session state
        st.session_state.token = result.get("token")
        # Retrieve the Identity Center token
        st.session_state["idc_jwt_token"] = utils.get_iam_oidc_token(st.session_state.token["id_token"])
        st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(tz=UTC) + \
            timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
        st.rerun()
else:
    token = st.session_state["token"]
    print(f'token: {token}')
    refresh_token = token["refresh_token"] # saving the long lived refresh_token
    print(f'refresh_token: {refresh_token}')
    user_email = jwt.decode(token["id_token"], options={"verify_signature": False})["email"]
    print(f'user_email: {user_email}')
    if st.button("Refresh Auth Token") :
        # If refresh token button is clicked or the token is expired, refresh the token
        token = oauth2.refresh_token(token, force=True)
        # Put the refresh token in the session state as it is not returned by Cognito
        token["refresh_token"] = refresh_token
        # Retrieve the Identity Center token

        st.session_state.token = token
        st.rerun()

    if "idc_jwt_token" not in st.session_state:
        st.session_state["idc_jwt_token"] = utils.get_iam_oidc_token(token["id_token"])
        st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(UTC) + \
            timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
    elif st.session_state["idc_jwt_token"]["expires_at"] < datetime.now(UTC):
        # If the Identity Center token is expired, refresh the Identity Center token
        try:
            st.session_state["idc_jwt_token"] = utils.refresh_iam_oidc_token(
                st.session_state["idc_jwt_token"]["refreshToken"]
                )
            st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(UTC) + \
                timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
        except Exception as e:
            st.error(f"Error refreshing Identity Center token: {e}. Please reload the page.")

    col1, col2 = st.columns([1,1])

    with col1:
        st.write("Welcome: ", user_email)
    with col2:
        st.button("Clear Chat History", on_click=clear_chat_history)

    # Initialize the chat messages in the session state if it doesn't exist
    if "messages" not in st.session_state:
        st.session_state["messages"] = [{"role": "assistant", "content": "How can I help you?"}]

    if "conversationId" not in st.session_state:
        st.session_state["conversationId"] = ""

    if "parentMessageId" not in st.session_state:
        st.session_state["parentMessageId"] = ""

    if "chat_history" not in st.session_state:
        st.session_state["chat_history"] = []

    if "questions" not in st.session_state:
        st.session_state.questions = []

    if "answers" not in st.session_state:
        st.session_state.answers = []

    if "input" not in st.session_state:
        st.session_state.input = ""


    # Display the chat messages
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.write(message["content"])


    # User-provided prompt
    if prompt := st.chat_input():
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.write(prompt)


    # If the last message is from the user, generate a response from the Q_backend
    if st.session_state.messages[-1]["role"] != "assistant":
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                placeholder = st.empty()
                response = utils.get_queue_chain(prompt,st.session_state["conversationId"],
                                                 st.session_state["parentMessageId"],
                                                 st.session_state["idc_jwt_token"]["idToken"])
                if "references" in response:
                    full_response = f"""{response["answer"]}\n\n---\n{response["references"]}"""
                else:
                    full_response = f"""{response["answer"]}\n\n---\nNo sources"""
                placeholder.markdown(full_response)
                st.session_state["conversationId"] = response["conversationId"]
                st.session_state["parentMessageId"] = response["parentMessageId"]


        st.session_state.messages.append({"role": "assistant", "content": full_response})
        feedback = streamlit_feedback(
            feedback_type="thumbs",
            optional_text_label="[Optional] Please provide an explanation",
        )
