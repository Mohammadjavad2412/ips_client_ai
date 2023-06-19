from rest_framework.permissions import BasePermission, SAFE_METHODS

class IsSuperUser(BasePermission):
    def has_permission(self, request, view):
        if request.user.is_authenticated and request.user.is_superuser:
            return True
        return False

class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        if request.user.is_authenticated and request.user.is_admin:
            return True
        return False
    
class IsOwner(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.is_authenticated and request.user.id == obj.id:
            return True
        return False
    
class UserPermission(BasePermission):
    def has_permission(self, request, view):
        if request.method not in SAFE_METHODS and request.user.is_authenticated and request.user.is_superuser:
            return True
        return False
    
    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS and (request.user.is_authenticated|request.user.is_admin|request.user.is_superuser):
            return True
        if request.method not in SAFE_METHODS and request.user.is_authenticated and request.user.is_superuser:
            return True
        if request.user.is_authenticated and request.user.id == obj.id:
            return True
        else:
            return False 
        