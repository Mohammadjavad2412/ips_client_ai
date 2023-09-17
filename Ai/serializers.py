from rest_framework.serializers import ModelSerializer
from .models import TrainData, Listener, Learner


class TrainDataSerializer(ModelSerializer):

    class Meta:
        model = TrainData
        fields = "__all__"
        