from rest_framework.exceptions import APIException
from rest_framework.views import exception_handler

class ErrorExceptionResult(APIException):
    def __init__(self, status_code=None, detail=None, code=None, customType=None):
        if status_code is not None:
            self.status_code = status_code
        if detail is not None:
            self.detail = detail
        if code is not None:
            self.code = code
        self.customType = customType
    
def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)
    if isinstance(exc, ErrorExceptionResult):
        if response is not None:
            response.data = {
                "error": exc.detail,
                "type": exc.customType,
                "status": exc.status_code
            }
        return response

    return response
