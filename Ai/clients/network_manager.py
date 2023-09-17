from abc import ABC, abstractmethod


class NetworkManager(ABC):

##### Kafka Methods
    # @abstractmethod
    def produce_raw_packets():
        pass

#### Listener Methods

    # @abstractmethod
    def start_sniffing():
        pass

    # @abstractmethod
    def listen_and_produce():
        pass

#### AI Methods
    # @abstractmethod
    def read_csv_(self, file_name):
        pass
        
    # @abstractmethod
    def train_test_data_(self, df):
        pass

    # @abstractmethod
    def scale_data_(self, x_train, x_test):
        pass

    # @abstractmethod
    def autoencoder_model_(self, scaled_train, scaled_test):
        pass
    
    # @abstractmethod
    def find_threshold_(self, autoencoder, scaled_train):
        pass

    # @abstractmethod
    def get_predictions_(autoencoder, scaled_test, threshold):
        pass

    # @abstractmethod
    def plot_(self, history):
        pass
