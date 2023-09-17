from scapy.all import *
from kafka import KafkaProducer, KafkaConsumer
from .network_manager import NetworkManager
from ips_client.settings import IPS_CLIENT_BOOTSTRAP_SERVER, IPS_CLIENT_BOOTSTRAP_PORT
from scapy.all import *
from tensorflow.keras.models import load_model
from datetime import datetime
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
from sklearn.preprocessing import MinMaxScaler
from Ai.models import Listener, TrainData
from django.db import connections
from ips_client.settings import BASE_DIR
from Ai.models import TestData, Listener, Learner
from keras.models import model_from_json

import pickle
import pandas as pd
import numpy as np
import tensorflow
import json
import matplotlib.pyplot as plt
import ast

class Dnp3Client(NetworkManager):

    def __init__(self):
        self.bootstrap_servers = f"{IPS_CLIENT_BOOTSTRAP_SERVER}:{IPS_CLIENT_BOOTSTRAP_PORT}"

    def write_consumed_train_data_to_db(self, obj):
        try:
            connection = connections['default']
            connection.connect()
            topic = 'processed_packets'
            bootstrap_servers = self.bootstrap_servers
            consumer = KafkaConsumer(topic, bootstrap_servers=bootstrap_servers)
            for message in consumer:
                message = ast.literal_eval(message.value.decode('utf-8'))
                src_ip = message['src_ip']
                dst_ip = message['dst_ip']
                src_port = message['src_port']
                dst_port = message['dst_port']
                src_mac = message['src_mac']
                dst_mac = message['dst_mac']
                fc_request = int(message['fc_request'])
                listener = obj
                train_obj = TrainData(
                    listener = listener,
                    src_ip = src_ip,
                    dst_ip = dst_ip,
                    src_port = src_port,
                    dst_port = dst_port,
                    src_mac = src_mac,
                    dst_mac = dst_mac,
                    fc_request = fc_request
                )
                train_obj.save(force_insert=True)
            connection.close()
        except:
            logging.error(traceback.format_exc())
    
    def start_sniffing(self, interface, port):
        try:
            sniff(iface=interface, filter=f"port {port}", prn=self.packet_callback)
        except:
            logging.error(traceback.format_exc())
    
    def packet_callback(self, raw_packets):
        self.produce_raw_packets(raw_packets)

    def produce_raw_packets(self, raw_packets):
        try:
            topic = 'processed_packets'
            bootstrap_servers = self.bootstrap_servers
            producer = KafkaProducer(bootstrap_servers = bootstrap_servers)
            src_ip = raw_packets['IP'].src
            dst_ip = raw_packets['IP'].dst
            src_port = raw_packets['TCP'].sport
            dst_port = raw_packets['TCP'].dport
            src_mac = raw_packets['Ether'].src
            dst_mac = raw_packets['Ether'].dst
            if 'Raw' in raw_packets:
                payload = raw_packets['Raw'].load
                dec_payload = payload.hex()
                fc_request = dec_payload[24:26]
                processed_packet = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "src_mac": src_mac,
                    "dst_mac": dst_mac,
                    "fc_request": fc_request
                }
            else:
                processed_packet = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "src_mac": src_mac,
                    "dst_mac": dst_mac,
                    "fc_request": 34 #response function code for now, until we have the response of master
                }
            producer.send(topic, value=(str(processed_packet).encode('utf-8')))
        except:
            logging.error(traceback.format_exc())
   
    def create_dataframe(self, training_data, obj):
        try:
            data = training_data
            df = pd.DataFrame(data, columns=['src_ip', 'dst_ip', 'src_port', 'dst_port', 'src_mac', 'dst_mac', 'fc_request'])
            df['src_mac_decimal'] = df['src_mac'].apply(self.convert_mac_to_decimal)
            df['dst_mac_decimal'] = df['dst_mac'].apply(self.convert_mac_to_decimal)

            command_mapping = self.function_code_mapper()
            df['fc_request'] = df['fc_request'].map(command_mapping)

            df.loc[:, 'orig_oct1'] = df['src_ip'].apply(lambda x: int(x.split(".")[0]))
            df.loc[:, 'orig_oct2'] = df['src_ip'].apply(lambda x: int(x.split(".")[1]))
            df.loc[:, 'orig_oct3'] = df['src_ip'].apply(lambda x: int(x.split(".")[2]))
            df.loc[:, 'orig_oct4'] = df['src_ip'].apply(lambda x: int(x.split(".")[3]))

            df.loc[:, 'resp_oct1'] = df['dst_ip'].apply(lambda x: int(x.split(".")[0]))
            df.loc[:, 'resp_oct2'] = df['dst_ip'].apply(lambda x: int(x.split(".")[1]))
            df.loc[:, 'resp_oct3'] = df['dst_ip'].apply(lambda x: int(x.split(".")[2]))
            df.loc[:, 'resp_oct4'] = df['dst_ip'].apply(lambda x: int(x.split(".")[3]))

            df.loc[:, 'orig_mac_oct1'] = df['src_mac_decimal'].apply(lambda x: int(x.split(":")[0]))
            df.loc[:, 'orig_mac_oct2'] = df['src_mac_decimal'].apply(lambda x: int(x.split(":")[1]))
            df.loc[:, 'orig_mac_oct3'] = df['src_mac_decimal'].apply(lambda x: int(x.split(":")[2]))
            df.loc[:, 'orig_mac_oct4'] = df['src_mac_decimal'].apply(lambda x: int(x.split(":")[3]))
            df.loc[:, 'orig_mac_oct5'] = df['src_mac_decimal'].apply(lambda x: int(x.split(":")[4]))
            df.loc[:, 'orig_mac_oct6'] = df['src_mac_decimal'].apply(lambda x: int(x.split(":")[5]))

            df.loc[:, 'resp_mac_oct1'] = df['dst_mac_decimal'].apply(lambda x: int(x.split(":")[0]))
            df.loc[:, 'resp_mac_oct2'] = df['dst_mac_decimal'].apply(lambda x: int(x.split(":")[1]))
            df.loc[:, 'resp_mac_oct3'] = df['dst_mac_decimal'].apply(lambda x: int(x.split(":")[2]))
            df.loc[:, 'resp_mac_oct4'] = df['dst_mac_decimal'].apply(lambda x: int(x.split(":")[3]))
            df.loc[:, 'resp_mac_oct5'] = df['dst_mac_decimal'].apply(lambda x: int(x.split(":")[4]))
            df.loc[:, 'resp_mac_oct6'] = df['dst_mac_decimal'].apply(lambda x: int(x.split(":")[5]))

            one_hot_encoded_fc_request = pd.get_dummies(df['fc_request'])
            df = pd.concat([df, one_hot_encoded_fc_request], axis=1)
            fc_request_columns = one_hot_encoded_fc_request.columns
            for column in fc_request_columns:
                df[column] = df[column].astype(int)

            df_to_create_model = df.copy()
            df_to_create_model = df_to_create_model.drop(columns=['src_ip','dst_ip', 'src_mac', 'dst_mac', 'src_mac_decimal', 'dst_mac_decimal', 'fc_request'])
            print(df_to_create_model.iloc[0])
            print(df_to_create_model.iloc[1])
            self.create_train_data(df, df_to_create_model, obj)
            return df, df_to_create_model
        except:
            logging.error(traceback.format_exc())
        

    def convert_mac_to_decimal(self, mac_address):
        mac_address = mac_address.replace(':', '')
        decimal_address = ':'.join(str(int(mac_address[i:i+2], 16)) for i in range(0, len(mac_address), 2))
        return decimal_address        

    def function_code_mapper(self):
        commands = [
        "confirm",
        "read",
        "write",
        "select",
        "operate",
        "direct_operate",
        "direct_operate_nr",
        "immed_freeze",
        "immed_freeze_nr",
        "freeze_clear",
        "freeze_clear_nr",
        "freeze_at_time",
        "freeze_at_time_nr",
        "cold_restart",
        "warm_restart",
        "initialize_data",
        "initialize_appl",
        "start_appl",
        "stop_appl",
        "save_config",
        "enable_unsolicited",
        "disable_unsolicited",
        "assign_class",
        "delay_measure",
        "record_current_time",
        "open_file",
        "close_file",
        "delete_file",
        "get_file_info",
        "authenticate_file",
        "abort_file",
        "activate_config",
        "authenticate_req",
        "authenticate_err",
        "response",
        "unsolicited_response",
        "authenticate_resp"]

        command_mapping = {}
        for index, command in enumerate(commands):
            command_mapping[index] = command
        return command_mapping

    def create_train_data(self, df, df_to_create_model, obj):
        x_train = df_to_create_model.values
        print(x_train)
        self.scale_train_data(x_train, df, df_to_create_model, obj)

    def scale_train_data(self, x_train, df, df_to_create_model, obj):
        connection = connections['default']
        connection.connect()
        scaler = MinMaxScaler()
        scaled_train = scaler.fit_transform(x_train)
        scaler_train_pkl = pickle.dumps(scaler)
        obj.scaler = scaler_train_pkl
        obj.save()
        self.autoencoder_model(scaled_train, df, df_to_create_model, obj)

    def autoencoder_model(self, scaled_train, df, df_to_create_model, obj):

        input_dim = scaled_train.shape[1]
        input_layer = Input(shape=(input_dim,))
        hidden_1 = Dense(128, activation= 'relu')(input_layer)
        hidden_2 = Dense(64, activation= 'relu')(hidden_1)
        code = Dense(32, activation = 'relu')(hidden_2)
        hidden_3 = Dense(64, activation = 'relu')(code)
        hidden_4 = Dense(128, activation = 'relu')(hidden_3)
        output_layer = Dense(input_dim, activation = 'sigmoid')(hidden_4)

        autoencoder = Model(input_layer, output_layer)
        autoencoder.compile(optimizer = 'adam', loss = 'mse')
        history = autoencoder.fit(scaled_train, scaled_train, epochs=10, batch_size=32, verbose=1)
        listener_id = obj.listener_id
        history_pkl = pickle.dumps(history)
        obj.history = history_pkl
        dnp3_models = os.path.join(BASE_DIR, 'dnp3_models')
        if not os.path.exists(dnp3_models):
            os.makedirs(dnp3_models)
        weights_model_path = f'{dnp3_models}/dnp3_autoencoder_listener{listener_id}.h5'
        obj.weights_model_path = weights_model_path
        obj.save()
        autoencoder.save_weights(weights_model_path)
        json_model = autoencoder.to_json()
        json_model_path = f'dnp3_models/dnp3_autoencoder_json_listener{listener_id}.json'
        json_file = open(json_model_path, 'w')
        json_file.write(json_model)
        obj.json_model_path = json_model_path
        self.find_threshold(autoencoder, scaled_train, df, df_to_create_model, obj)

    def find_threshold(self, autoencoder, scaled_train, df, df_to_create_model, obj):
        reconstructions = autoencoder.predict(scaled_train)
        reconstruction_errors = tensorflow.keras.losses.msle(reconstructions, scaled_train)
        print(reconstruction_errors)
        threshold = np.max(reconstruction_errors.numpy())
        print(threshold)
        obj.threshold_error = threshold
        obj.save()

    def get_predictions(self, learner, scaled_test, threshold):
        try:
            json_model_path = learner.json_model_path
            weights_model_path = learner.weights_model_path
            json_file = open(json_model_path, 'r')
            json_model = model_from_json(json_file.read())
            json_model.load_weights(weights_model_path)
            predictions = json_model.predict(scaled_test)
            errors = tensorflow.keras.losses.msle(predictions, scaled_test)
            # 0 = normal, 1 = anomaly
            anomaly_mask = pd.Series(errors) > threshold
            preds = anomaly_mask.map(lambda x: 1.0 if x == True else 0.0)
            return preds
        except:
            logging.error(traceback.format_exc())

    def predict_test(self, threshold, scaler, learner, sniffing_thread_id):
        self.consume_data_for_test(threshold, scaler, learner, sniffing_thread_id)

    def consume_data_for_test(self,threshold, scaler, learner, sniffing_thread_id):
        connection = connections['default']
        connection.connect()
        topic = 'processed_packets'
        bootstrap_servers = self.bootstrap_servers
        consumer = KafkaConsumer(topic, bootstrap_servers=bootstrap_servers)
        for message in consumer:
            data ={}    
            message = ast.literal_eval(message.value.decode('utf-8'))
            data["src_ip"] = message['src_ip']
            data["dst_ip"] = message['dst_ip']
            data["src_port"] = message['src_port']
            data["dst_port"] = message['dst_port']
            data["src_mac"] = message['src_mac']
            data["dst_mac"] = message['dst_mac']
            data["fc_request"] = int(message['fc_request'])
            df, df_to_create_test = self.create_test_dataframe(data)
            x_test = df_to_create_test.values
            scaled_test = scaler.transform(x_test)
            preds = self.get_predictions(learner, scaled_test, threshold)
            listener_id = learner.listener_id
            listener = Listener.objects.get(id=listener_id)
            thread_predict_id = os.getpid()
            test_data_obj = TestData(
            learner=learner, 
            listener=listener,
            src_ip = data['src_ip'],
            dst_ip = data['dst_ip'],
            src_port = data['src_port'],
            dst_port = data['dst_port'],
            src_mac = data['src_mac'],
            dst_mac = data['dst_mac'],
            fc_request = data['fc_request'],
            is_attack = preds,
            is_running=True,
            predict_thread_id = thread_predict_id,
            sniffing_thread_id = sniffing_thread_id
            )
            test_data_obj.save()
        
    def create_test_dataframe(self, data):
        try:
            df = pd.DataFrame(data, index=[0])
            df['src_mac_decimal'] = df['src_mac'].apply(self.convert_mac_to_decimal)
            df['dst_mac_decimal'] = df['dst_mac'].apply(self.convert_mac_to_decimal)

            command_mapping = self.function_code_mapper()
            df['fc_request'] = df['fc_request'].map(command_mapping)

            df.loc[:, 'orig_oct1'] = df['src_ip'].apply(lambda x: int(x.split(".")[0]))
            df.loc[:, 'orig_oct2'] = df['src_ip'].apply(lambda x: int(x.split(".")[1]))
            df.loc[:, 'orig_oct3'] = df['src_ip'].apply(lambda x: int(x.split(".")[2]))
            df.loc[:, 'orig_oct4'] = df['src_ip'].apply(lambda x: int(x.split(".")[3]))

            df.loc[:, 'resp_oct1'] = df['dst_ip'].apply(lambda x: int(x.split(".")[0]))
            df.loc[:, 'resp_oct2'] = df['dst_ip'].apply(lambda x: int(x.split(".")[1]))
            df.loc[:, 'resp_oct3'] = df['dst_ip'].apply(lambda x: int(x.split(".")[2]))
            df.loc[:, 'resp_oct4'] = df['dst_ip'].apply(lambda x: int(x.split(".")[3]))

            df.loc[:, 'orig_mac_oct1'] = df['src_mac_decimal'].apply(lambda x: int(x.split(":")[0]))
            df.loc[:, 'orig_mac_oct2'] = df['src_mac_decimal'].apply(lambda x: int(x.split(":")[1]))
            df.loc[:, 'orig_mac_oct3'] = df['src_mac_decimal'].apply(lambda x: int(x.split(":")[2]))
            df.loc[:, 'orig_mac_oct4'] = df['src_mac_decimal'].apply(lambda x: int(x.split(":")[3]))
            df.loc[:, 'orig_mac_oct5'] = df['src_mac_decimal'].apply(lambda x: int(x.split(":")[4]))
            df.loc[:, 'orig_mac_oct6'] = df['src_mac_decimal'].apply(lambda x: int(x.split(":")[5]))

            df.loc[:, 'resp_mac_oct1'] = df['dst_mac_decimal'].apply(lambda x: int(x.split(":")[0]))
            df.loc[:, 'resp_mac_oct2'] = df['dst_mac_decimal'].apply(lambda x: int(x.split(":")[1]))
            df.loc[:, 'resp_mac_oct3'] = df['dst_mac_decimal'].apply(lambda x: int(x.split(":")[2]))
            df.loc[:, 'resp_mac_oct4'] = df['dst_mac_decimal'].apply(lambda x: int(x.split(":")[3]))
            df.loc[:, 'resp_mac_oct5'] = df['dst_mac_decimal'].apply(lambda x: int(x.split(":")[4]))
            df.loc[:, 'resp_mac_oct6'] = df['dst_mac_decimal'].apply(lambda x: int(x.split(":")[5]))

            one_hot_encoded_fc_request = pd.get_dummies(df['fc_request'])
            df = pd.concat([df, one_hot_encoded_fc_request], axis=1)
            fc_request_columns = one_hot_encoded_fc_request.columns
            for column in fc_request_columns:
                df[column] = df[column].astype(int)

            df_to_create_test = df.copy()
            df_to_create_test = df_to_create_test.drop(columns=['src_ip','dst_ip', 'src_mac', 'dst_mac', 'src_mac_decimal', 'dst_mac_decimal', 'fc_request'])
            if 'response' in df_to_create_test.columns:
                df_to_create_test['initialize_data'] = 0
            else:
                df_to_create_test['response'] = 0
            new_order = ['src_port', 'dst_port', 'orig_oct1', 'orig_oct2', 'orig_oct3', 'orig_oct4', 'resp_oct1', 'resp_oct2', 'resp_oct3', 'resp_oct4', 'orig_mac_oct1', 'orig_mac_oct2', 'orig_mac_oct3', 'orig_mac_oct4', 'orig_mac_oct5', 'orig_mac_oct6', 'resp_mac_oct1', 'resp_mac_oct2', 'resp_mac_oct3', 'resp_mac_oct4', 'resp_mac_oct5', 'resp_mac_oct6', 'initialize_data', 'response']
            df_to_create_test = df_to_create_test.reindex(columns=new_order)
            print(df_to_create_test.iloc[0])
            
            return df, df_to_create_test
        except:
            logging.error(traceback.format_exc())

    def plot_(self, history):
        plt.plot(history.history['loss'])
        # plt.plot(history.history['val_loss'])
        plt.xlabel('Epochs')
        plt.ylabel('MSLE Loss')
        plt.legend(['loss'])
        plt.show()