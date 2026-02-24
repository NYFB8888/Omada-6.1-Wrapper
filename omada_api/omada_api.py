from urllib import response
import requests
import urllib3
import http.client
import logging
import json
import time
import traceback
from enum import Enum
from requests.cookies import RequestsCookieJar
import sys

class Omada:
#================== Omada Init ==========================
    class mod(Enum):
            GET = "GET"
            POST = "POST"
            UPDATE = "PUT"
            DELETE = "DELETE"
            PATCH = "PATCH"

    def __init__(self, baseurl, username, password,
                 client_id, client_secret, omada_id,*,
                 site='Default', verify=False, 
                 warnings=False, debug=False):
        
        self.baseurl:str        = baseurl
        self.username:str       = username
        self.password:str       = password
        self.client_id:str      = client_id
        self.client_secret:str  = client_secret
        self.omada_id:str       = omada_id

        self.site:str           = site
        self.verify:bool        = verify
        self.debug:bool         = debug
        self.warnings:bool      = warnings

        self.loginResult = False
        self.omadac_id =  None
        self.token = None
        self.oauth_token = None
        self.site_id = None

        self._logger = self._omadaError.setup_logger()
        self.session = requests.Session()
        self.session.cookies = RequestsCookieJar()

        if not debug:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        if debug:
            self._setup_verbose_mode()
            self._log_config()

        try:         
           self.Login()
        except Exception as e:
            self._logger.error(f"Login failed: {e}")

#####################################################################################
    def Login(self):

        if self.loginResult == False:
            url= f"{self.baseurl}/api/v2/login"
            json_auth={"username": self.username, "password": self.password}
            result=self._http(self.mod.POST,url,verify=self.verify,json=json_auth)
            self.token=result['token']
            self.omadac_id=result['omadacId']
            self.session.headers.update({"Csrf-Token": self.token})    

            url = f"{self.baseurl}/openapi/authorize/token?grant_type=client_credentials"
            payload = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "omadacId": self.omada_id
            }

            result = self._http(self.mod.POST,url,verify=self.verify,json=payload)
            self.oauth_token = result['accessToken']
            self.site_id = self.get_site_id(self.site)

            if self.token  == None or self.oauth_token == None:
                self.loginResult = False
                raise self._omadaError("no authentication tokens")
            else:
                self.loginResult = True
        else:
            pass
#=====================================================
    def Logout(self):
        if not self.loginResult:
            return

        try:
            url = f"{self.baseurl}/api/v2/logout?token={self.token}"
            self._http(self.mod.POST, url, verify=self.verify, json={})
        except Exception as e:
            self._logger.error(f"Web UI Logout failed: {e}")

        self.oauth_token = None
        
        # 3. Session Cleanup
        self.token = None
        self.session.headers.pop("Csrf-Token", None)
        self.session.cookies.clear()
        self.loginResult = False
        
        if self.debug:
            self._logger.debug("Logged out from Web UI and cleared OpenAPI tokens.")

#===============================Error hendler==============================================

    class _omadaError(Exception):

        def __init__(self, response_data):
            if response_data is None:
                raise TypeError("response_data cannot be None")

            if isinstance(response_data, dict):
                self.errorCode = int(response_data.get("errorCode", 0))
                self.msg = response_data.get("msg", "")
            elif isinstance(response_data, str):
                self.errorCode = 0
                self.msg = response_data
            else:
                raise TypeError(
                    f"response_data must be dict or str, not {type(response_data).__name__}"
                )

        def __str__(self):
            if self.errorCode == 0:
                return self.msg
            return f"[{self.errorCode}] {self.msg}"

        @staticmethod
        def setup_logger(name="omada", level=logging.INFO):
            logger = logging.getLogger(name)
            logger.setLevel(level)

            if not logger.handlers:
                handler = logging.StreamHandler()
                formatter = logging.Formatter(
                    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                )
                handler.setFormatter(formatter)
                logger.addHandler(handler)

            return logger

        @staticmethod
        def log_exception(logger, exc: Exception):
            """Logs only module, function, and line number."""
            exc_type, exc_value, tb = sys.exc_info()
            last = traceback.extract_tb(tb)[-1]

            module = last.filename
            line = last.lineno
            func = last.name

            logger.error(
                f"Exception in {module}:{func} at line {line} → {exc}"
            )

#-------------------------------------------------------------------

    def _http(self, mode, api, verify: bool = False, **arg):
            
            # --- 1. Handle OAuth and Headers ---
            if "openapi" in api.lower():
                headers = arg.get('headers', {}).copy()
                if hasattr(self, 'oauth_token') and self.oauth_token:
                    headers['Authorization'] = f"AccessToken={self.oauth_token}"
                    
                    # Apply JSON header to ALL write operations
                    if mode in [self.mod.POST, self.mod.UPDATE, self.mod.PATCH, self.mod.DELETE]:
                        headers['Content-Type'] = 'application/json'
                    
                    arg['headers'] = headers

            # --- 2. Smart Injection of Pagination ---
            # We only want to inject page/pageSize if we are fetching a list (a "Grid").
            # If the URL ends with these terms, it's likely a list.
            listing_keywords = ['/clients', '/devices', '/sites', '/gateways', '/aps', '/logs']
            is_listing_query = any(keyword in api.lower() for keyword in listing_keywords)
            
            # Don't inject if this is an "Action" (e.g., .../clients/authorize)
            if "/authorize" in api.lower() or "/unauthorize" in api.lower():
                is_listing_query = False

            if is_listing_query:
                defaults = {'page': 1, 'pageSize': 100}
                
                if mode == self.mod.POST:
                    # Northbound API v6+ wants list params in the JSON body
                    json_payload = arg.get('json', {}).copy()
                    for key, value in defaults.items():
                        json_payload.setdefault(key, value)
                    arg['json'] = json_payload
                    
                    # Clean up params to prevent duplication in URL
                    if 'params' in arg:
                        for key in defaults:
                            arg['params'].pop(key, None)
                
                elif mode == self.mod.GET:
                    # Standard GET requests want them in the URL
                    params = arg.get('params', {}).copy()
                    for key, value in defaults.items():
                        params.setdefault(key, value)
                    arg['params'] = params

            # --- 3. Logging and Execution ---
            if self.debug:
                self._logger.debug(f"Mode: {mode} | API: {api}")
                if arg.get('params'): self._logger.debug(f"Params: {arg['params']}")
                if arg.get('json'): self._logger.debug(f"JSON Body: {arg['json']}")

            match mode: 
                case self.mod.GET: 
                    response = self.session.get(api, verify=verify, **arg)
                case self.mod.POST: 
                    response = self.session.post(api, verify=verify, **arg) 
                case self.mod.UPDATE: 
                    response = self.session.put(api, verify=verify, **arg) 
                case self.mod.DELETE:
                    response = self.session.delete(api, verify=verify, **arg) 
                case self.mod.PATCH:
                    response = self.session.patch(api, verify=verify, **arg)
                case _: 
                    raise ValueError(f"Unsupported HTTP mode: {mode}")

            # --- 4. Response Handling ---
            if not response.ok:
                # This is critical for debugging 400/405 errors
                self._logger.error(f"HTTP {response.status_code}: {response.text}")
                
            response.raise_for_status()
            json_data = response.json()
            
            if json_data.get('errorCode') == 0:
                return json_data.get('result')
            
            raise self._omadaError(json_data)    
    
#-----------------------------------------------------------------
    def Commad(self,mod,api,verify=False, **arg):
        return self._http(mod,self.baseurl+api,verify=verify, **arg)
#-----------------------------------------------------------------

    def _setup_verbose_mode(self):
        http.client.HTTPConnection.debuglevel = 1
        self._logger.handlers.clear()
        logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        logging.getLogger().setLevel(logging.DEBUG)
        self._logger.setLevel(logging.DEBUG)
    
    def _log_config(self):
        config = {
            'URL': self.baseurl,
            'Site': self.site,
            'Username': self.username,
            'Client ID': self.client_id,
            'Client Secret': self.client_secret,
            'Omada ID': self.omada_id,
            'Verify SSL': self.verify,
            'Debug': self.debug
        }
        self._logger.debug("="*50)
        for key, value in config.items():
            self._logger.debug(f"{key:15} {value}")
        self._logger.debug("="*50)

##############################################################################

    def get_api_info(self):
        response = self._http(self.mod.GET,f"{self.baseurl}/api/info", verify=self.verify)
        return response
    
    def get_site_id(self, site):

        if not self.oauth_token:
             raise self._logger.error("OpenAPI not authenticated - cannot get site_id")
        
        url = f"{self.baseurl}/openapi/v1/{self.omada_id}/sites"
        result = self._http(self.mod.GET,url,params={'page': 1, 'pageSize': 100})
        
        if not result:
            raise self._logger.error("No sites found")
        
        for _site in result['data']:
            if _site['name'] == site:
                return _site['siteId'] 
        raise self._omadaError(f"Failed to get site_id")    
    
##################################################################################

def main():

    def PrintRes(res):
        print("="*70)
        print(json.dumps(res, indent=4))
        print("="*70)
    
    omada = Omada(
                baseurl      ="https://x.x.x.x",
                username     ="admin",
                password     ="password",
                site         ='LMySite',
                client_id    = "xxxxxxxxx",
                client_secret= "xxxxxxxxx",
                omada_id     = "xxxxxxxxx",
                debug =False,
                verify=False
            )
    
    omada._logger.info("[ MG Omada Module Test ]")
    '''
    result = omada.get_api_info()
    PrintRes(result)

    result = omada.get_site_id(omada.site)
    PrintRes(result)
    
    #GET /openapi/v1/{omada.omadac_id}/sites/{omada.site_id}/setting/lan/dns
    api=f"/openapi/v1/{omada.omadac_id}/sites/{omada.site_id}/setting/lan/dns"
    result = omada.Commad(omada.mod.GET,api)
    PrintRes(result)
 
    # GET /openapi/v1/{omadacId}/sites/{siteId}/setting/service/dhcp
    api=f"/openapi/v1/{omada.omadac_id}/sites/{omada.site_id}/setting/service/dhcp"
    result = omada.Commad(omada.mod.GET,api)
    PrintRes(result)
    '''  
  
    #POST /openapi/v2/{omadacId}/sites/{siteId}/clients
    api=f"/openapi/v2/{omada.omadac_id}/sites/{omada.site_id}/clients"
    result = omada.Commad(omada.mod.POST,api)
    PrintRes(result)

    omada.Logout()

if __name__ == "__main__":
    main()


