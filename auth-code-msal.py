'''
OAuth 2 Autorization code grant flow
Volgens Microsoft, middels de MSAL library
'''

import json
from flask         import Flask, render_template, redirect, url_for, session, request
from flask_session import Session # Voor server-side Session. Session wordt niet direct gebruikt maar via flask.session
import msal
import requests
# from requests import request

import app_config

app = Flask(__name__)
app.config.from_object(app_config)
Session(app)

@app.route("/")
def index():
    if not session.get("user"):            # Geen 'user' in de sessie, dan eerst aanmelden via de /login route en sessie dict opbouwen
        return redirect(url_for("login"))

    return render_template(
        "index.html",
        user=session["user"],
        my_session=session,
        app_id=app_config.CLIENT_ID,
        app_secret=app_config.CLIENT_SECRET,
        version=msal.__version__)

@app.route("/login")
def login():
    '''
    Wordt aangeroepen vanuit de "/" route (index) wanneer er GEEN session["user"] waarde bestaat.
    Bouwt een flow-dictionary op met gegevens voor de authorization code grant. De flow-dictionary wordt aangemaakt via: _build_auth_code_flow()
    De flow dictionary wordt opgeslagen in session["flow"]
    Daarna wordt het login-scherm getoond met applicatie- en flow-gegevens en een 'Sign In' button.
    De 'Sign In' button verwijst naar de URL in session["flow"]["auth_uri"]
    '''
    session["flow"] = _build_auth_code_flow(scopes=app_config.SCOPE)  # Alle benodigde 'flow' elementen in de session["flow"]

    return render_template(
        "login.html", 
        auth_url=session["flow"]["auth_uri"],
        app_id=app_config.CLIENT_ID,
        app_secret=app_config.CLIENT_SECRET, 
        version=msal.__version__, session_info=session
    )

@app.route(app_config.REDIRECT_PATH)  # Leidt naar: /getAToken
def authorized():
    '''
    Wordt aangeroepen ná een authenticatie. De IDP (Azure AD) doet een callback naar de redirect uri.
    Deze route/view is opgenomen in app_config én in Azure app registratie 'redirect uri'
    Variabele 'result' is een Dict met o.a. access token en eventueel id token (afhankelijk van scope)

    Normaal krijg je na authenticatie alleen een authorization code. In een volgende stap wissel je 
    deze code + client-id, -secret in voor een acces-code en id-token (laatste afhankelijk van de scope openid).
        Blijkbaar wordt het inwisselen + verificatie van gegevens al in de achtergrond gedaan want in
        'result' zitten deze tokens al.
        Dit blijft mij onduidelijk: waarom deze tokens al hier?
        Feitelijk wordt in de functie graphcall het authorization token omgezet naar een acces-, refresh en id-token.
    '''
    print(f"[info] <Authorized> ...")

    try:
        cache  = _load_cache()
        result = _build_msal_app(cache=cache).acquire_token_by_auth_code_flow(
        # result = _build_msal_app().acquire_token_by_auth_code_flow(
            session.get("flow", {}),
            request.args
        ) 

        if "error" in result:
            return render_template("auth_error.html", result=result)
        
        session["user"]   = result.get("id_token_claims")
        session["tokens"] = result
        _save_cache(cache)
    except Exception as e:
        print(f"\n *** FOUT ***")
        print(e)
        print()

    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        app_config.AUTHORITY + "/oauth2/v2.0/logout" +
        "?post_logout_redirect_uri=" + url_for("index", _external=True)
    )

@app.route("/graphcall")
def graphcall():
    print(f"[info] <graphcall> ...")
    token = _get_token_from_cache(scope=app_config.SCOPE)
    # token = session.get("token", None)
    if not token:
        print(f"[info] <graphcall> GEEN token (uit cache) gevonden ...")
        return redirect(url_for("login"))
    else:
        print(f"[info] <graphcall> WEL token (uit cache) gevonden ...\n")
        for k, v in token.items():
            print(f"[info] <graphcall> {k}:")
            print(f"\t {v} ...\n")

    # headers = {"Authorization": "Bearer " + token["access_token"]}
    headers = {"Authorization": "Bearer " + session["tokens"]["access_token"]}
    print(f"[info] <graphcall> headers: {headers} ...\n")
    graph_data = requests.get(
        app_config.ENDPOINT,
        headers=headers,
    ).json()
    return render_template("display.html", result=graph_data)

@app.route("/show_tokens")
def show_tokens():
    ct = json.loads(session["token_cache"])
    return render_template("show_tokens.html", result=session["tokens"], cache=ct)

def _load_cache() -> msal.SerializableTokenCache:
    '''
    Plaatst een Dict met token gegevens in cache-object als het session["token_cache"] bestaat...
    Geeft een cache-object terug. Leeg of met token gegevens.
    '''
    print(f"[info] <_load_cache> ...")
    cache = msal.SerializableTokenCache()
    if session.get("token_cache"):
        print(f"[info] <_load_cache> -> token cache WEL in sessie gevonden: cache-object (dict) terug vanuit session ...")
        cache.deserialize(session["token_cache"])
    else:
        print(f"[info] <_load_cache> -> token cache NIET in sessie gevonden: leeg cache-object terug ...")
    return cache

def _save_cache(cache: msal.SerializableTokenCache):
    '''
    Maakt het session["token_cache"] in JSON formaat aan, ALLEEN als de cache is gewijzigd
    '''
    print(f"[info] <_save_cache> ...")
    if cache.has_state_changed:
        print(f"[info] <_save_cache> -> cache gewijzigd: token_chache wordt in JSON formaat bewaard in sessie ...")
        session["token_cache"] = cache.serialize()
        if session["token_cache"]:
            print(f"[info] <_save_cache> token cache in sessie aangemaakt ..., type: {type(session['token_cache'])}")

def _build_msal_app(cache=None, authority=None) -> msal.ConfidentialClientApplication:
    print(f"[info] <_build_msal_app>")
    if cache:
        print(f"[info] <_build_msal_app> -> MET cache ({type(cache)})")
    else:
        print(f"[info] <_build_msal_app> -> ZONDER cache")

    return msal.ConfidentialClientApplication(
        client_id=app_config.CLIENT_ID, 
        authority=authority or app_config.AUTHORITY,
        client_credential=app_config.CLIENT_SECRET,
        token_cache=cache)

def _build_auth_code_flow(authority=None, scopes=None) -> dict:
    red_uri = "http://localhost:5000" + app_config.REDIRECT_PATH
    return _build_msal_app(authority=authority).initiate_auth_code_flow(scopes or []) #, redirect_uri=red_uri)
    # return _build_msal_app(authority=authority).initiate_auth_code_flow(scopes or [], redirect_uri=url_for("authorized", _external="True"))

def _get_token_from_cache(scope=None):
    print(f"[info] <_get_token_from_cache> ...")
    cache    = _load_cache()
    cca      = _build_msal_app(cache=cache)
    accounts = cca.get_accounts()
    print(f"[info] <_get_token_from_cache> ... accounts:")
    print(f"{accounts}\n")
    if accounts:
        result = cca.acquire_token_silent(scopes=scope, authority=app_config.AUTHORITY, account=accounts[0])
        print(f"[info] <_get_token_from_cache> Result is:")
        print(f"{result}, {type(result)}\n")
        _save_cache(cache)
        return result

# app.jinja_env.globals.update(_build)

if __name__ == "__main__":
    app.run()
