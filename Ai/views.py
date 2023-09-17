from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from utils.functions import protocol_mapper
from concurrent.futures import ThreadPoolExecutor
from .serializers import TrainDataSerializer
from .models import Listener, Learner, TrainData, TestData
from multiprocessing import Process
import multiprocessing
from django.db import connections
from datetime import datetime, timezone, timedelta
from tensorflow.keras.models import load_model
import matplotlib.pyplot as plt
import pickle
import pytz
import threading
import requests
import logging
import traceback
import json
import signal
import os
import psutil

# Create your views here.

class StartListening(APIView):

    def get(self, request):
        try:
            connection = connections['default']
            connection.connect()
            protocol = request.GET.get("protocol")
            port = request.GET.get("port")
            interface = request.GET.get("interface")
            client = protocol_mapper(protocol)
            thread_raw = Process(target=client.start_sniffing, args=(interface, port))
            thread_raw.start()
            sniffer_thread_id = thread_raw.pid
            obj = Listener(
                protocol = protocol,
                port= port,
                interface= interface,
                is_active= True,
                sniffer_thread_id=sniffer_thread_id,
            ) 
            obj.save(force_insert=True)
            thread_processed = Process(target=client.write_consumed_train_data_to_db, args=(obj,))
            thread_processed.start()
            consumer_thread_id = thread_processed.pid
            obj.consumer_thread_id = consumer_thread_id
            obj.save()
            connection.close()
            return Response({"info": "listening started"}, status.HTTP_200_OK)
        except:
            logging.error(traceback.format_exc())
            return Response({"error": "something's wrong"}, status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
class StopListening(APIView):

    def get(self, request, pk):
        try:            
            instance = Listener.objects.get(id=pk)
            instance.is_active = False
            thread_id = instance.sniffer_thread_id
            os.kill(thread_id, signal.SIGKILL)
            instance.save()
            return Response({"info": "stopping listener"}, status.HTTP_200_OK)
        except:
            logging.error(traceback.format_exc())
            return Response({"error": "something's wrong"}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class StartLearning(APIView):

    def get(self, request, pk):
        try:
            if request.GET.get("start_time", None):
                if request.GET.get("end_time", None):
                    start_time = request.GET.get("start_time")
                    end_time = request.GET.get("end_time")
                    start_time_datetime = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
                    start_time_datetime -= timedelta(hours=3, minutes=30)
                    end_time_datetime = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
                    end_time_datetime -= timedelta(hours=3, minutes=30)
                    listener = Listener.objects.get(id=pk)
                    training_data = TrainData.objects.filter(listener_id=listener.id,time__gte=start_time_datetime, time__lte=end_time_datetime)
                    serializer = TrainDataSerializer(training_data, many=True)
                    data = serializer.data
                    protocol = listener.protocol
                    client = protocol_mapper(protocol)
                    obj = Learner(
                        listener = listener,
                        time_from = start_time,
                        time_to = end_time,
                        is_learning = True,
                        is_finished = False,
                    )
                    obj.save()
                    thread_learn = Process(target=client.create_dataframe, args=(data,obj,))
                    thread_learn.start()
                    learner_thread_id = thread_learn.pid
                    obj.learner_thread_id = learner_thread_id
                    obj.save()
                    return Response({"info": "learning started"}, status.HTTP_200_OK)
                else:
                    return Response({"error": "end time should not be empty"}, status.HTTP_500_INTERNAL_SERVER_ERROR)
                
            else:
                listener = Listener.objects.get(id=pk)
                protocol = listener.protocol
                training_data = TrainData.objects.filter(listener_id = listener.id)
                serializer = TrainDataSerializer(training_data, many=True)
                data = serializer.data
                client = protocol_mapper(protocol)
                first_record = TrainData.objects.filter(listener_id=listener.id).first()
                first_record_datetime = first_record.time
                desired_tz = timezone(timedelta(hours=3, minutes=30))
                dt_desired_tz = first_record_datetime.astimezone(desired_tz)
                formatted_first_record = dt_desired_tz.strftime("%Y-%m-%d %H:%M:%S")
                last_record = TrainData.objects.filter(listener_id=listener.id).last()
                last_record_datetime = last_record.time
                desired_tz = timezone(timedelta(hours=3, minutes=30))
                dt_desired_tz = last_record_datetime.astimezone(desired_tz)
                formatted_last_record = dt_desired_tz.strftime("%Y-%m-%d %H:%M:%S") 
                obj = Learner(
                    listener = listener,
                    time_from = formatted_first_record,
                    time_to = formatted_last_record,
                    is_learning = True,
                    is_finished = False
                )
                obj.save()
                thread_learn = Process(target=client.create_dataframe, args=(data,obj))
                thread_learn.start()
                learner_thread_id = thread_learn.pid
                obj.learner_thread_id = learner_thread_id
                obj.save()
                return Response({"info": "learning started"}, status.HTTP_200_OK)
        except:
            logging.error(traceback.format_exc())
            return Response({"error":"something's wrong"}, status.HTTP_500_INTERNAL_SERVER_ERROR)

class LearningDataPeriod(APIView):

    def get(self, request, pk):
        try:
            listener = Listener.objects.get(id=pk)
            first_record = TrainData.objects.filter(listener_id=listener.id).first()
            first_record_datetime = first_record.time
            desired_tz = timezone(timedelta(hours=3, minutes=30))
            dt_desired_tz = first_record_datetime.astimezone(desired_tz)
            formatted_first_record = dt_desired_tz.strftime("%Y-%m-%d %H:%M:%S")
            last_record = TrainData.objects.filter(listener_id=listener.id).last()
            last_record_datetime = last_record.time
            desired_tz = timezone(timedelta(hours=3, minutes=30))
            dt_desired_tz = last_record_datetime.astimezone(desired_tz)
            formatted_last_record = dt_desired_tz.strftime("%Y-%m-%d %H:%M:%S")
            return Response({"first_record": formatted_first_record, "last_record": formatted_last_record}, status.HTTP_200_OK)
        except:
            logging.error(traceback.format_exc())
            return Response({"error": "something's wrong"}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class StartTesting(APIView):

    def get(self, request, pk):
        try:
            learner = Learner.objects.get(id=pk)
            listener_id = learner.listener_id
            listener = Listener.objects.get(id=listener_id)
            interface = listener.interface
            port = listener.port
            protocol = listener.protocol
            client = protocol_mapper(protocol)
            thread_sniff_for_test = Process(target=client.start_sniffing, args=(interface, port))
            thread_sniff_for_test.start()
            sniffing_thread_id = thread_sniff_for_test.pid
            threshold = learner.threshold_error
            scaler = learner.scaler
            scaler = pickle.loads(scaler)
            thread_predict = Process(target=client.predict_test, args=(threshold, scaler, learner, sniffing_thread_id))
            thread_predict.start()
            return Response({"info": "testing started"}, status.HTTP_200_OK)
        except:
            logging.error(traceback.format_exc())
            return Response({"error": "something's wrong"}, status.HTTP_500_INTERNAL_SERVER_ERROR)

class StopTesting(APIView):

    def get(self, request, pk):
        try:            
            instance = TestData.objects.filter(learner_id=pk)
            for inst in instance:
                inst.is_running = False
                inst.save()
            thread_id = instance[0].predict_thread_id
            os.kill(thread_id, signal.SIGKILL)
            sniffing_thread_id = instance[0].sniffing_thread_id
            os.kill(sniffing_thread_id, signal.SIGKILL)
            return Response({"info": "stopping listener"}, status.HTTP_200_OK)
        except:
            logging.error(traceback.format_exc())
            return Response({"error": "something's wrong"}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class ModelLearningDiagram(APIView):
    
    def get(self, request, pk):
        try:
            learner = Learner.objects.get(id=pk)
            history_pkl = learner.history
            history = pickle.loads(history_pkl)
            plt.plot(history.history['loss'])
            plt.xlabel('Epochs')
            plt.ylabel('MSLE Loss')
            plt.legend(['loss'])
            plt.show()
            return Response({"info": "history retrieved"}, status.HTTP_200_OK)
        except:
            logging.error(traceback.format_exc())
            return Response({"error": "something's wrong"}, status.HTTP_500_INTERNAL_SERVER_ERROR)

