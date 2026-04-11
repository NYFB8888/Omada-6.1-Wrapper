from omada.omada_api import Omada
import json

def main():

    def PrintRes(res):
        print("="*70)
        print(json.dumps(res, indent=4))
        print("="*70)
    
    omada = Omada(
                baseurl="",
                username="",
                password="!",
                site='LMG',
                client_id="",
                client_secret="",
                debug =False,
                verify=False
            )
    
    omada._logger.info("[ MG Omada Module Test ]")
    
    result = omada.get_api_info()
    result = omada.get_siteId(omada.site)
    
    #GET /openapi/v1/{omada.omadacId}/sites/{omada.siteId}/setting/lan/dns
    api=f"/openapi/v1/{omada.omadacId}/sites/{omada.siteId}/setting/lan/dns"
    result = omada.Commad(omada.mod.GET,api)
    PrintRes(result)

    ''' 
    # GET /openapi/v1/{omadacId}/sites/{siteId}/setting/service/dhcp
    api=f"/openapi/v1/{omada.omadacId}/sites/{omada.siteId}/setting/service/dhcp"
    result = omada.Commad(omada.mod.GET,api)
    PrintRes(result)
    
    #GET /openapi/v1/{omadacId}/sites/{siteId}/setting/service/ddns
    api=f"/openapi/v1/{omada.omadacId}/sites/{omada.siteId}/setting/service/ddns"
    result = omada.Commad(omada.mod.GET,api)
    PrintRes(result)
    
    #GET /openapi/v1/{omadacId}/sites/{siteId}/rrm/config
    api=f"/openapi/v1/{omada.omadacId}/sites/{omada.siteId}/rrm/config"
    result = omada.Commad(omada.mod.GET,api)
    PrintRes(result)
    
    #GET/openapi/v1/{omadacId}/sites/{siteId}/dashboard/overview-diagram
    api=f"/openapi/v1/{omada.omadacId}/sites/{omada.siteId}/dashboard/overview-diagram"
    result = omada.Commad(omada.mod.GET,api)
    PrintRes(result)

    #GET /openapi/v1/{omadacId}/sites/{siteId}/dashboard/channels
    api=f"/openapi/v1/{omada.omadacId}/sites/{omada.siteId}/dashboard/channels"
    result = omada.Commad(omada.mod.GET,api)
    PrintRes(result) 

    #POST /openapi/v2/{omadacId}/sites/{siteId}/clients
    api=f"/openapi/v2/{omada.omadacId}/sites/{omada.siteId}/clients"
    result = omada.Commad(omada.mod.POST,api)
    PrintRes(result)
    '''
    omada._logger.info("[ MG Omada Module Test End]")
    omada.Logout()

if __name__ == "__main__":
    main()

