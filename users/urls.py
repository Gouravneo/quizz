from django.urls import path
from .views import CreateUserAPIView, UserRetrieveUpdateAPIView


urlpatterns = [
    path('create/', CreateUserAPIView.as_view(), name='createuser'),
    path('updateretrieve/', UserRetrieveUpdateAPIView.as_view(), name='updateretrieveuser'),
]
