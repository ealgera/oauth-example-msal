# oauth-example-msal
A test application to test the OAuth2/OIDC flow with Azure AD.
Conform the Microsoft MSAL libraries and Python (3.x).

### Setup (Linux)
#### Python setup
- create a virtual Python environment with: python3 -m venv venv
- activate the virtual Python environment with: source venv/bin/activate
- install the needed Python libraries: pip install -r requirements.txt

#### App setup
- create in Azure AD a web-app registration.
- create an API person (scope).
- copy the client secret and client id.
- 
- create an .env file like the example file .env_example
- add the client secret to the .env file. Use the CLIENT_SECRET variable.
- change / set needed variables in app_config.py (in any case: CLIENT_ID and maybe SCOPE)

#### Start the app
- start: python auth-code-msal.py
- goto http://localhost:5000 in a browser

