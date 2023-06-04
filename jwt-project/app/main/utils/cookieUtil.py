from datetime import timedelta
# from django.http import HttpResponse, HttpRequest

class CookieUtil:
    def __init__(self):
        self.response = HttpResponse()
        self.request = HttpRequest()

    def getCookieValue(request, name):
        cookieAccess = None
        try:
            cookieAccess = request.COOKIES.get(name)
            if (cookieAccess == None):
                return None
            return cookieAccess
        except:
            return None
	
    def create(response, name, value, secure, domain):

        config = { 
            "expires": timedelta(days=365), 
            "httponly": True,
            "secure": secure,
            "domain": domain,
            "path": "/"
        }

        #CookieName, TokenValue, Config
        response.set_cookie(name, value, **config)
        
    def clear(response, name):
        response.delete_cookie(name)