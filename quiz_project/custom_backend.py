from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
import logging

class CaseSensitiveBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        logger = logging.getLogger(__name__)
        logger.debug("Authenticating: request=%s, username=%s, kwargs=%s", request, username, kwargs)
        
        if username is None or password is None:
            return None
        
        UserModel = get_user_model()
        
        try:
            # Use additional kwargs (if provided) for filtering.
            user = UserModel.objects.get(username=username, **kwargs)
        except UserModel.DoesNotExist:
            return None
        else:
            # Enforce case-sensitive username comparison.
            if user.username != username:
                return None
            if user.check_password(password):
                return user
        return None