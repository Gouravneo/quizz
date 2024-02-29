from django.urls import path
from .views import CreateUserAPIView, UserRetrieveUpdateAPIView,login_user
# from .views import CreateUserAPIView, UserRetrieveUpdateAPIView,your_view_function,signup,login_user,update_password,update_name


urlpatterns = [
    path('create/', CreateUserAPIView.as_view(), name='createuser'),
    path('updateretrieve/', UserRetrieveUpdateAPIView.as_view(), name='updateretrieveuser'),
    path('login/', login_user, name='login'),
    # path('endpoint/', your_view_function, name='your_endpoint'),
    # path('signup/', signup, name='signup'),    
    # path('update_password/', update_password, name='update_password'),
    # path('update_name/', update_name, name='update_name'),
]
