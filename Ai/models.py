from django.db import models
from user_manager.models import Users
# Create your models here.


class Listener(models.Model):
    protocol = models.CharField(max_length=100, null=True, blank=True)
    interface = models.CharField(max_length=100, null=True, blank=True)
    port = models.IntegerField(null=True, blank=True)
    is_active = models.BooleanField(null=True, blank=True, default=False)
    # creator = models.ForeignKey(Users, on_delete=models.DO_NOTHING, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    sniffer_thread_id = models.PositiveBigIntegerField(null=True, blank=True, unique=True)
    consumer_thread_id = models.PositiveBigIntegerField(null=True, blank=True, unique=True)

class TrainData(models.Model):
    listener = models.ForeignKey(Listener, on_delete=models.CASCADE)
    time = models.DateTimeField(auto_now_add=True)
    src_ip = models.CharField(max_length=100,blank=True, null=True)
    dst_ip = models.CharField(max_length=100,blank=True, null=True)
    src_port = models.IntegerField(blank=True, null=True)
    dst_port = models.IntegerField(blank=True, null=True)
    src_mac = models.CharField(max_length=100, blank=True, null=True)
    dst_mac = models.CharField(max_length=100, blank=True, null=True)
    fc_request = models.IntegerField(blank=True, null=True)


class Learner(models.Model):
    listener = models.ForeignKey(Listener, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    time_from = models.DateTimeField(blank=True, null=True)
    time_to = models.DateTimeField(blank=True, null=True)
    is_learning = models.CharField(max_length=20, null=True, blank=True)
    is_finished = models.CharField(max_length=20, null=True, blank=True)
    weights_model_path = models.CharField(max_length=200, null=True, blank=True)
    json_model_path = models.JSONField(null=True, blank=True)
    scaler = models.BinaryField(null=True,   blank=True)
    history = models.BinaryField(null=True, blank=True)
    threshold_error = models.FloatField(null=True, blank=True)
    learner_thread_id = models.PositiveBigIntegerField(null=True, blank=True, unique=True)

class TestData(models.Model):
    listener = models.ForeignKey(Listener, on_delete=models.CASCADE)
    learner = models.ForeignKey(Learner, on_delete=models.CASCADE, null=True, blank=True)
    time = models.DateTimeField(auto_now_add=True)
    src_ip = models.CharField(max_length=100,blank=True, null=True)
    dst_ip = models.CharField(max_length=100,blank=True, null=True)
    src_port = models.IntegerField(blank=True, null=True)
    dst_port = models.IntegerField(blank=True, null=True)
    src_mac = models.CharField(max_length=100,blank=True, null=True)
    dst_mac = models.CharField(max_length=100,blank=True, null=True)
    fc_request = models.IntegerField(blank=True, null=True)
    is_attack = models.IntegerField(blank=True, null=True)
    predict_thread_id = models.PositiveBigIntegerField(null=True, blank=True)
    sniffing_thread_id = models.PositiveBigIntegerField(null=True, blank=True)
    is_running = models.BooleanField(null=True, blank=True, default=False)