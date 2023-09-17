import pandas as pd
import numpy as np
import tensorflow
import json
from network_manager import NetworkManager
from scapy.all import *
from tensorflow.keras.models import load_model
from datetime import datetime
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
from sklearn.preprocessing import MinMaxScaler
import matplotlib.pyplot as plt


class ModBusClient(NetworkManager):


    def read_csv_(self, file_name):
        df = pd.read_csv(file_name)
        df = df[:1500000]

        df.loc[:, 'orig_oct1'] = df['sip'].apply(lambda x: int(x.split(".")[0]))
        df.loc[:, 'orig_oct2'] = df['sip'].apply(lambda x: int(x.split(".")[1]))
        df.loc[:, 'orig_oct3'] = df['sip'].apply(lambda x: int(x.split(".")[2]))
        df.loc[:, 'orig_oct4'] = df['sip'].apply(lambda x: int(x.split(".")[3]))

        df.loc[:, 'resp_oct1'] = df['dip'].apply(lambda x: int(x.split(".")[0]))
        df.loc[:, 'resp_oct2'] = df['dip'].apply(lambda x: int(x.split(".")[1]))
        df.loc[:, 'resp_oct3'] = df['dip'].apply(lambda x: int(x.split(".")[2]))
        df.loc[:, 'resp_oct4'] = df['dip'].apply(lambda x: int(x.split(".")[3]))
        df = df.reset_index()
        df = df.drop(columns=['index'], axis=1)
        return df

    def train_test_data_(self, df):

        train_test_ratio = int(np.round(df.shape[0]*0.8))
        df_train = df[:train_test_ratio]
        print(df_train.shape)
        attack_rows = df_train[df_train['label'] != 'NORMAL']
        print(attack_rows)
        df_train = df_train.drop(attack_rows.index)
        print(df_train.shape)
        df_test = df[train_test_ratio:]
        print(df_test.shape)
        df_test = pd.concat([df_test, attack_rows], ignore_index=True)
        print(df_test.shape)
        df_test = df_test.reset_index()
        df_test = df_test.drop(['index'], axis=1)
        print(df_train['label'].unique)
        print(df_test['label'].unique())
        print(df_train.shape)
        print(df_test.shape)

        x_train = np.array(df_train[['request', 'fc', 'error', 'address', 'data', 'orig_oct1',
        'orig_oct2', 'orig_oct3', 'orig_oct4', 'resp_oct1',
        'resp_oct2', 'resp_oct3', 'resp_oct4']])
        x_test = np.array(df_test[['request', 'fc', 'error', 'address', 'data', 'orig_oct1',
        'orig_oct2', 'orig_oct3', 'orig_oct4', 'resp_oct1',
        'resp_oct2', 'resp_oct3', 'resp_oct4']])
        return x_train, x_test, df_train, df_test

    def scale_data_(self, x_train, x_test):
        scaler = MinMaxScaler()
        scaled_train = scaler.fit_transform(x_train)
        scaled_test = scaler.transform(x_test)
        return scaled_train, scaled_test

    def autoencoder_model_(self, scaled_train, scaled_test):

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
        history = autoencoder.fit(scaled_train, scaled_train, epochs=10, batch_size=32, verbose=1, validation_data = (scaled_test, scaled_test))

        autoencoder.save('modbus_models/modbus_autoencoder.h5')
        with open('modbus_history/modbus_history.json', 'w') as hist_file:
            json.dump(history.history, hist_file)
        
        return autoencoder, history

    def find_threshold_(self, autoencoder, scaled_train):
        reconstructions = autoencoder.predict(scaled_train)
        reconstruction_errors = tensorflow.keras.losses.msle(reconstructions, scaled_train)
        threshold = np.mean(reconstruction_errors.numpy()) + np.std(reconstruction_errors.numpy())
        print(threshold)
        return threshold

    def get_predictions_(self, autoencoder, scaled_test, threshold):
        predictions = autoencoder.predict(scaled_test)
        errors = tensorflow.keras.losses.msle(predictions, scaled_test)
        print(errors)
        # 0 = anomaly, 1 = normal
        anomaly_mask = pd.Series(errors) > threshold
        preds = anomaly_mask.map(lambda x: 0.0 if x == True else 1.0)
        print(preds)
        return preds

    def plot_(self, history):
        plt.plot(history.history['loss'])
        plt.plot(history.history['val_loss'])
        plt.xlabel('Epochs')
        plt.ylabel('MSLE Loss')
        plt.legend(['loss', 'val_loss'])
        plt.show()
