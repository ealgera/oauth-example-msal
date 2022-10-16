# oauth-example-msal
A test application to test the OAuth2/OIDC flow with Azure AD.
Conform the Microsoft MSAL libraries and Python (3.x).

### Setup (Linux)
#### Python setup
- create a virtual Python environment with: python3 -m venv venv
- activate the virtual Python environment with: source venv/bin/activate
- install the needed Python libraries: pip install -r requirements.txt

#### App setup
- create in Azure AD an web-app registration.
- copy the client secret and client id.
- create an .env file like the example file .env_example
- add the client secret to the .env file. Use the CLIENT_SECRET variable.

#### Start the app: python auth-code-msal.py
