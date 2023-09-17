from Ai import views
from django.urls import path


app_name = "Ai"
urlpatterns = [
    path("start_listening", views.StartListening.as_view(), name="start_listening"),
    path("stop_listening/<int:pk>/", views.StopListening().as_view(), name="stop_listening"),
    path("start_learning/<int:pk>", views.StartLearning.as_view(), name="start_learning"),
    path("learning_data_period/<int:pk>/", views.LearningDataPeriod.as_view(), name="learning_data_period"),
    path("start_testing/<int:pk>/", views.StartTesting.as_view(), name="start_testing"),
    path("stop_testing/<int:pk>/", views.StopTesting.as_view(), name="stop_testing"),
    path("model_learning_diagram/<int:pk>/", views.ModelLearningDiagram.as_view(), name="model_learning_diagram")
]