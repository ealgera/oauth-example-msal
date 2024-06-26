import os
from dotenv import load_dotenv

### Azure App reg voor: python-auth-code
load_dotenv(".env")

# App Secrets
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
if not CLIENT_SECRET:
    raise ValueError("CLIENT_SECRET is niet gedefinieerd!")

CLIENT_ID = "73de801a-937d-4ee3-ba3e-dec460e1428b"     # Application (client) ID of app registration
TENANT_ID = "121d18b6-96bd-4da0-9bb8-845d80a1ec21"

# AUTHORITY = "https://login.microsoftonline.com/common"  # For multi-tenant app
# AUTHORITY = "https://login.microsoftonline.com/Enter_the_Tenant_Name_Here"
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"

REDIRECT_PATH = "/getAToken"  # Used for forming an absolute URL to your redirect URI.
                              # The absolute URL must match the redirect URI you set
                              # in the app's registration in the Azure portal.

# You can find more Microsoft Graph API endpoints from Graph Explorer
# https://developer.microsoft.com/en-us/graph/graph-explorer
ENDPOINT = 'https://graph.microsoft.com/v1.0/users'  # This resource requires no admin consent

# You can find the proper permission names from this document
# https://docs.microsoft.com/en-us/graph/permissions-reference
SCOPE = ["User.ReadBasic.All"]

SESSION_TYPE = "filesystem"  # Specifies the token cache should be stored in server-side session
