# Backend/auth_graphql/main.py (Conceptual Rewrite - NOT fully tested code)
import os
import json # You'll need this for parsing Cognito JWTs or other configs
from typing import Optional
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from dotenv import load_dotenv
import strawberry
from strawberry.fastapi import GraphQLRouter

# AWS SDK
import boto3

# For JWT validation from Cognito
import jwt
from jwt.algorithms import RSAAlgorithm
from urllib.request import urlopen

load_dotenv()

# --- Configuration ---
AWS_REGION = os.getenv("AWS_REGION", "us-east-1") # Example region
COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID", "your-cognito-user-pool-id")
COGNITO_CLIENT_ID = os.getenv("COGNITO_CLIENT_ID", "your-cognito-client-id") # For User Pool client without a secret

# For validating Cognito JWTs
# This URL provides the public keys for your Cognito User Pool
COGNITO_JWKS_URL = f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"

# --- AWS Clients ---
cognito_client = boto3.client('cognito-idp', region_name=AWS_REGION)
# dynamodb_client = boto3.client('dynamodb', region_name=AWS_REGION) # If storing user profiles separately

# --- User Model and Authentication Logic (Conceptual) ---

# In Cognito, users are managed by Cognito itself.
# You might still have a local User class to represent the authenticated user's data for your app.
class User:
    def __init__(self, id: str, username: str, email: Optional[str] = None):
        self.id = id
        self.username = username
        self.email = email

# --- GraphQL Types ---

@strawberry.type
class UserType:
    id: str
    username: str
    email: Optional[str]

@strawberry.type
class AuthResponse:
    user: Optional[UserType]
    access_token: Optional[str] # This will be the Cognito ID or Access token
    id_token: Optional[str]     # Cognito ID token
    refresh_token: Optional[str] # Cognito Refresh token
    message: str
    success: bool

# --- GraphQL Mutations ---

@strawberry.type
class Mutation:
    @strawberry.mutation
    async def register_user(self, username: str, password: str, email: Optional[str] = None) -> AuthResponse:
        try:
            # Cognito Sign Up API call
            response = cognito_client.sign_up(
                ClientId=COGNITO_CLIENT_ID,
                Username=username,
                Password=password,
                UserAttributes=[
                    {'Name': 'email', 'Value': email}
                ] if email else []
            )
            
            # Note: Cognito often requires email verification (confirmation code) after sign_up
            # For simplicity, this example assumes no confirmation, or that you'll handle it elsewhere.
            # In a real app, you'd call 'confirm_sign_up' after user provides code.
            
            return AuthResponse(
                user=None, # User details might not be immediately available before confirmation
                access_token=None,
                id_token=None,
                refresh_token=None,
                message="User registered. Confirmation may be required.",
                success=True
            )
        except cognito_client.exceptions.UsernameExistsException:
            return AuthResponse(message="User already exists.", success=False)
        except Exception as e:
            print(f"Error registering user: {e}")
            return AuthResponse(message=f"Registration failed: {e}", success=False)

    @strawberry.mutation
    async def login_user(self, username: str, password: str) -> AuthResponse:
        try:
            # Initiate Auth API call for login
            response = cognito_client.initiate_auth(
                ClientId=COGNITO_CLIENT_ID,
                AuthFlow='USER_PASSWORD_AUTH', # Or 'ADMIN_NO_SRP_AUTH' if using admin credentials
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password
                }
            )
            
            auth_result = response['AuthenticationResult']
            id_token = auth_result['IdToken']
            access_token = auth_result['AccessToken']
            refresh_token = auth_result.get('RefreshToken')

            # Decode ID token to get user details
            decoded_id_token = jwt.decode(id_token, options={"verify_signature": False}) # Just to get username/email for response
            user_id = decoded_id_token.get('sub')
            user_username = decoded_id_token.get('cognito:username', username) # Use cognito username if available
            user_email = decoded_id_token.get('email')

            logged_in_user = UserType(id=user_id, username=user_username, email=user_email)

            return AuthResponse(
                user=logged_in_user,
                access_token=access_token,
                id_token=id_token,
                refresh_token=refresh_token,
                message="Login successful!",
                success=True
            )
        except cognito_client.exceptions.NotAuthorizedException:
            return AuthResponse(message="Invalid username or password.", success=False)
        except cognito_client.exceptions.UserNotConfirmedException:
             return AuthResponse(message="User not confirmed.", success=False)
        except Exception as e:
            print(f"Error logging in user: {e}")
            return AuthResponse(message=f"Login failed: {e}", success=False)

# --- GraphQL Queries ---

@strawberry.type
class Query:
    @strawberry.field
    async def hello(self) -> str:
        return "Hello from AWS Cognito GraphQL Auth Service!"

    @strawberry.field
    async def me(self, info: strawberry.Info) -> Optional[UserType]:
        current_user = info.context["current_user"]
        if not current_user:
            raise HTTPException(status_code=401, detail="Not authenticated")
        return UserType(id=current_user.id, username=current_user.username, email=current_user.email)

# --- GraphQL Schema ---
schema = strawberry.Schema(query=Query, mutation=Mutation)

# --- FastAPI App Setup ---
app = FastAPI()
graphql_app = GraphQLRouter(schema)

# --- JWT Validation (for protected queries like 'me') ---
# Cache JWKS public keys for faster validation
cached_jwks = None

async def get_jwks():
    global cached_jwks
    if cached_jwks is None:
        try:
            with urlopen(COGNITO_JWKS_URL) as response:
                jwks = json.loads(response.read().decode('utf-8'))
                cached_jwks = {jwk['kid']: jwk for jwk in jwks['keys']}
        except Exception as e:
            print(f"Error fetching JWKS: {e}")
            raise HTTPException(status_code=500, detail="Failed to load public keys for token validation.")
    return cached_jwks

async def verify_cognito_jwt(token: str) -> Optional[dict]:
    jwks = await get_jwks()
    
    # Get kid from token header to find the correct public key
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header['kid']
    
    if kid not in jwks:
        raise HTTPException(status_code=401, detail="Invalid token: KID not found.")

    public_key = RSAAlgorithm.from_jwk(json.dumps(jwks[kid]))

    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=['RS256'], # Cognito JWTs use RS256, not HS256
            audience=COGNITO_CLIENT_ID # Audience is your Cognito Client ID
            # issuer=f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}" # Optional, but good for stricter validation
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired.")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")
    except Exception as e:
        print(f"Error during JWT validation: {e}")
        raise HTTPException(status_code=401, detail="Authentication failed.")


# Middleware to add current_user to GraphQL context
@app.middleware("http")
async def add_user_to_context(request: Request, call_next):
    current_user = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        try:
            payload = await verify_cognito_jwt(token)
            # Fetch user details from Cognito or DynamoDB if needed.
            # For simplicity, extract from JWT payload:
            user_id = payload.get('sub')
            username = payload.get('cognito:username') # Often 'cognito:username' or 'username'
            email = payload.get('email')
            current_user = User(id=user_id, username=username, email=email)
        except HTTPException as e:
            print(f"Authentication failed in middleware: {e.detail}")
        except Exception as e:
            print(f"Unexpected error in middleware auth: {e}")

    request.state.current_user = current_user
    response = await call_next(request)
    return response

# Custom context getter for Strawberry
async def get_context(request: Request):
    return {
        "request": request,
        "current_user": request.state.current_user
    }

graphql_app.context_getter = get_context
app.include_router(graphql_app, prefix="/graphql")

@app.get("/")
async def root():
    return {"message": "AWS Cognito GraphQL Authentication Service is running!"}